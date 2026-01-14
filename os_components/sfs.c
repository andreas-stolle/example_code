#define FUSE_USE_VERSION 26

#include <errno.h>
#include <fuse.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "../../os/3-fs/sfs.h"
#include "../../os/3-fs/diskio.h"


static const char default_img[] = "test.img";

/* Options passed from commandline arguments */
struct options {
    const char *img;
    int background;
    int verbose;
    int show_help;
    int show_fuse_help;
} options;


#define log(fmt, ...) \
    do { \
        if (options.verbose) \
            printf(" # " fmt, ##__VA_ARGS__); \
    } while (0)


/* libfuse2 leaks, so let's shush LeakSanitizer if we are using Asan. */
const char* __asan_default_options() { return "detect_leaks=0"; }


/*
 * This is a helper function that is optional, but highly recomended you
 * implement and use. Given a path, it looks it up on disk. It will return 0 on
 * success, and a non-zero value on error (e.g., the file did not exist).
 * The resulting directory entry is placed in the memory pointed to by
 * ret_entry. Additionally it can return the offset of that direntry on disk in
 * ret_entry_off, which you can use to update the entry and write it back to
 * disk (e.g., rmdir, unlink, truncate, write).
 *
 * You can start with implementing this function to work just for paths in the
 * root entry, and later modify it to also work for paths with subdirectories.
 * This way, all of your other functions can use this helper and will
 * automatically support subdirectories. To make this function support
 * subdirectories, we recommend you refactor this function to be recursive, and
 * take the current directory as argument as well. For example:
 *
 *  static int get_entry_rec(const char *path, const struct sfs_entry *parent,
 *                           size_t nentries, blockidx_t blockidx,
 *                           struct sfs_entry *ret_entry,
 *                           unsigned *ret_entry_off)
 *
 * Here parent is the directory it is currently searching (at first the rootdir,
 * later the subdir). The nentries tells the function how many entries
 * there are in the directory (SFS_ROOTDIR_NENTRIES or SFS_DIR_NENTRIES).
 * Finally, the blockidx contains the blockidx of the given directory on
 * the disk, which will help in calculating ret_entry_off.
 */
static int get_entry_helper (char *path, struct sfs_entry *parent_entries, struct sfs_entry *ret_entry, unsigned *ret_entry_off,
                             size_t nentries, blockidx_t blockidx)
{
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");

    struct sfs_entry entries[nentries];
    for (unsigned i = 0; i < nentries; i++) {
        if (strncmp(parent_entries[i].filename, token, SFS_FILENAME_MAX) == 0) {
            char *next_part = strtok(NULL, "/");

            if (next_part == NULL) {
                *ret_entry = parent_entries[i];
                *ret_entry_off = parent_entries[i].first_block;
                log("getentry name %s\n", parent_entries[i].filename);
                log("getentrysize %i\n", parent_entries[i].size);
                return 0;
            }
            blockidx = parent_entries[i].first_block;
            disk_read(entries, SFS_DIR_SIZE, SFS_DATA_OFF + blockidx * SFS_BLOCK_SIZE);
            return get_entry_helper(path + strlen(token) + 1, entries, ret_entry, ret_entry_off,
                                    SFS_DIR_NENTRIES, blockidx);
        }
    }

    return -ENOENT;
}

static int get_entry(const char *path, struct sfs_entry *ret_entry, unsigned *ret_entry_off)
{
    log("get_entry %s\n", path);

    struct sfs_entry root_entries[SFS_ROOTDIR_NENTRIES];
    disk_read(root_entries, SFS_ROOTDIR_SIZE, SFS_ROOTDIR_OFF);

    if (strcmp(path, "/") == 0) {
        *ret_entry_off = SFS_ROOTDIR_OFF;
        *ret_entry = root_entries[0];
        return 0;
    }

    char *path_dup = strdup(path);

    return get_entry_helper(path_dup, root_entries, ret_entry, ret_entry_off, SFS_ROOTDIR_NENTRIES, SFS_BLOCKIDX_EMPTY);
}

/*
 * Retrieve information about a file or directory.
 * You should populate fields of `st` with appropriate information if the
 * file exists and is accessible, or return an error otherwise.
 *
 * For directories, you should at least set st_mode (with S_IFDIR) and st_nlink.
 * For files, you should at least set st_mode (with S_IFREG), st_nlink and
 * st_size.
 *
 * Return 0 on success, < 0 on error.
 */
static int sfs_getattr(const char *path, struct stat *st)
{
    log("getattr %s\n", path);

    memset(st, 0, sizeof(struct stat));
    st->st_uid = getuid();
    st->st_gid = getgid();
    st->st_atime = time(NULL);
    st->st_mtime = time(NULL);

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
        return 0;
    }

    struct sfs_entry entry;
    unsigned entry_offset = 0;
    int res = get_entry(path, &entry, &entry_offset);
    if (res < 0)
        return res;
    if (entry.size & SFS_DIRECTORY) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2;
    }
    else {
        st->st_mode = S_IFREG | 0644;
        st->st_size = entry.size & SFS_SIZEMASK;
        st->st_nlink = 1;
    }

    return 0;
}

/*
 * Return directory contents for `path`. This function should simply fill the
 * filenames - any additional information (e.g., whether something is a file or
 * directory) is later retrieved through getattr calls.
 * Use the function `filler` to add an entry to the directory. Use it like:
 *  filler(buf, <dirname>, NULL, 0);
 * Return 0 on success, < 0 on error.
 */
static int sfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    log("readdir %s\n", path);

    (void)offset, (void)fi;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    size_t nentries = SFS_ROOTDIR_NENTRIES;
    size_t size = SFS_ROOTDIR_SIZE;
    offset = SFS_ROOTDIR_OFF;

    if (strcmp(path, "/") != 0) {
        struct sfs_entry dir_entry;
        unsigned dir_entry_offset = 0;
        int res = get_entry(path, &dir_entry, &dir_entry_offset);
        if (res < 0)
            return res;
        if (!(dir_entry.size &  SFS_DIRECTORY))
            return ENOTDIR;

        nentries = SFS_DIR_NENTRIES;
        size = 2 * SFS_BLOCK_SIZE;
        offset = SFS_DATA_OFF + dir_entry.first_block * SFS_BLOCK_SIZE;
    }

    struct sfs_entry entries[nentries];
    disk_read(entries, size, offset);
    for (unsigned i = 0; i < nentries; i++) {
        if (entries[i].filename[0] != '\0')
            filler(buf, entries[i].filename, NULL, 0);
    }

    return 0;
}

/*
 * Read contents of `path` into `buf` for  up to `size` bytes.
 * Note that `size` may be bigger than the file actually is.
 * Reading should start at offset `offset`; the OS will generally read your file
 * in chunks of 4K byte.
 * Returns the number of bytes read (writting into `buf`), or < 0 on error.
 */
static int sfs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    log("read %s size=%zu offset=%ld\n", path, size, offset);

    (void)buf, (void)fi;
    struct sfs_entry entry;
    unsigned entry_offset = 0;
    int res = get_entry(path, &entry, &entry_offset);
    if (res < 0)
        return res;
    if (entry.size & SFS_DIRECTORY)
        return -EISDIR;

    size_t bytes_read = 0;
    size_t bytes_left = size;
    blockidx_t current_block = entry.first_block;
    size_t block_start_index = offset / SFS_BLOCK_SIZE;
    size_t block_offset = offset % SFS_BLOCK_SIZE;

    for (size_t i = 0; i < block_start_index && current_block != SFS_BLOCKIDX_END; i++) {
        disk_read(&current_block, sizeof(blockidx_t), SFS_BLOCKTBL_OFF + current_block * sizeof(blockidx_t));
        if (current_block == SFS_BLOCKIDX_EMPTY) {
            return -EIO;
        }
    }

    while (bytes_left > 0 && current_block != SFS_BLOCKIDX_END) {
        off_t disk_offset = SFS_DATA_OFF + current_block * SFS_BLOCK_SIZE;
        size_t block_start = block_offset;
        size_t block_size = SFS_BLOCK_SIZE - block_start;
        size_t to_read = (bytes_left < block_size) ? bytes_left : block_size;

        disk_read(buf + bytes_read, to_read, disk_offset + block_start);

        bytes_read += to_read;
        bytes_left -= to_read;
        block_offset = 0;
        disk_read(&current_block, sizeof(blockidx_t), SFS_BLOCKTBL_OFF + current_block * sizeof(blockidx_t));
    }

    return bytes_read;
}

/*
 * Create directory at `path`.
 * The `mode` argument describes the permissions, which you may ignore for this
 * assignment.
 * Returns 0 on success, < 0 on error.
 */
static char *get_filename(const char *path) {
    char *path_copy = strdup(path);
    char *file_name = strrchr(path_copy, '/');
    if (file_name) {
        file_name++;
    } else {
        file_name = path_copy;
    }
    char *result = strdup(file_name);
    free(path_copy);
    return result;
}

static char *get_parent_path(const char *path) {
    char *path_copy = strdup(path);
    size_t len = strlen(path_copy);
    while (len > 1 && path_copy[len - 1] == '/') {
        path_copy[len - 1] = '\0';
        len--;
    }
    char *last_slash = strrchr(path_copy, '/');
    if (!last_slash) {
        free(path_copy);
        return strdup("/");
    }
    if (last_slash == path_copy) {
        *(last_slash + 1) = '\0';
    } else {
        *last_slash = '\0';
    }
    char *result = strdup(path_copy);
    free(path_copy);
    return result;
}

static int sfs_mkdir(const char *path, mode_t mode)
{
    log("mkdir %s mode=%o\n", path, mode);

    char *parent_path = get_parent_path(path);
    char *new_dir_name = get_filename(path);

    if (strlen(new_dir_name) >= SFS_FILENAME_MAX)
        return -ENAMETOOLONG;

    struct sfs_entry parent_entry;
    unsigned parent_entry_offset;
    if (strcmp(parent_path, "/") == 0) {
        strncpy(parent_entry.filename, "/", SFS_FILENAME_MAX);
        parent_entry.size = SFS_ROOTDIR_SIZE;
        parent_entry.first_block = 0;
        parent_entry_offset = SFS_ROOTDIR_OFF;
    }
    else {
        int res = get_entry(parent_path, &parent_entry, &parent_entry_offset);
        if (res < 0)
            return res;
    }

    size_t nentries = SFS_DIR_NENTRIES;
    off_t parent_dir_offset = SFS_DATA_OFF + parent_entry.first_block * SFS_BLOCK_SIZE;
    size_t size = SFS_DIR_SIZE;
    if (strcmp(parent_path, "/") == 0) {
        nentries = SFS_ROOTDIR_NENTRIES;
        parent_dir_offset = SFS_ROOTDIR_OFF;
        size = SFS_ROOTDIR_SIZE;
    }
    struct sfs_entry parent_entries[nentries];
    disk_read(parent_entries, size, parent_dir_offset);

    int empty_slot = -1;
    for (unsigned i = 0; i < nentries; i++) {
        if (parent_entries[i].filename[0] == '\0') {
            empty_slot = i;
            break;
        }
    }
    if (empty_slot == -1)
        return -ENOSPC;

    blockidx_t blocktable[SFS_BLOCKTBL_NENTRIES];
    int first_empty_block = -1;
    disk_read(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);
    for (int i = 0; i < SFS_BLOCKTBL_NENTRIES - 1; i++) {
        if (blocktable[i] == SFS_BLOCKIDX_EMPTY && blocktable[i+1] == SFS_BLOCKIDX_EMPTY) {
            first_empty_block = i;
            blocktable[i] = i + 1;
            blocktable[i + 1] = SFS_BLOCKIDX_END;
            break;
        }
    }
    if (first_empty_block == -1)
        return ENOSPC;
    disk_write(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);

    memset(&parent_entries[empty_slot], 0, sizeof(struct sfs_entry));
    strncpy(parent_entries[empty_slot].filename, new_dir_name, SFS_FILENAME_MAX);
    parent_entries[empty_slot].first_block = first_empty_block;
    parent_entries[empty_slot].size = SFS_DIRECTORY;

    struct sfs_entry new_dir_entry[SFS_DIR_NENTRIES];
    for (unsigned i = 0; i < SFS_DIR_NENTRIES ; i++) {
        memset(new_dir_entry[i].filename, '\0', SFS_FILENAME_MAX);
        new_dir_entry[i].size = 0;
        new_dir_entry[i].first_block = SFS_BLOCKIDX_EMPTY;
    }
    disk_write(new_dir_entry, SFS_DIR_SIZE, SFS_DATA_OFF + first_empty_block * SFS_BLOCK_SIZE);
    disk_write(parent_entries, size, parent_dir_offset);

    return 0;
}


static int sfs_rmdir(const char *path)
{
    log("rmdir %s\n", path);

    struct sfs_entry entry;
    unsigned entry_offset;
    int res = get_entry(path, &entry, &entry_offset);
    if (res != 0) {
        log("Error: entry not found for path %s\n", path);
        return -ENOENT;
    }
    if (!(entry.size & SFS_DIRECTORY)) {
        log("Error: path %s is not a directory\n", path);
        return -ENOTDIR;
    }

    struct sfs_entry dir_entries[SFS_DIR_NENTRIES];
    disk_read(dir_entries, SFS_DIR_SIZE, SFS_DATA_OFF + entry.first_block * SFS_BLOCK_SIZE);
    log("Read directory entries for path %s\n", path);

    for (unsigned i = 0; i < SFS_DIR_NENTRIES; i++) {
        if (dir_entries[i].filename[0] != '\0') {
            log("Error: directory is not empty, entry: %s\n", dir_entries[i].filename);
            return -ENOTEMPTY;
        }
    }

    char *parent_path = get_parent_path(path);
    char *new_dir_name = get_filename(path);
    log("Parent path: %s, Directory name: %s\n", parent_path, new_dir_name);

    struct sfs_entry parent_entry;
    unsigned parent_entry_offset;
    res = get_entry(parent_path, &parent_entry, &parent_entry_offset);
    if (res != 0) {
        log("Error: parent entry not found for path %s\n", parent_path);
        free(parent_path);
        free(new_dir_name);
        return res;
    }
    log("Parent entry found: %s\n", parent_entry.filename);

    size_t nentries = SFS_DIR_NENTRIES;
    size_t dir_size = SFS_DIR_SIZE;
    off_t parent_dir_offset = SFS_DATA_OFF + parent_entry_offset * SFS_BLOCK_SIZE;
    if (strcmp(parent_path, "/") == 0) {
        nentries = SFS_ROOTDIR_NENTRIES;
        dir_size = SFS_ROOTDIR_SIZE;
        parent_dir_offset = SFS_ROOTDIR_OFF;
    }
    struct sfs_entry parent_entries[nentries];
    disk_read(parent_entries, dir_size, parent_dir_offset);
    log("Read parent directory entries\n");

    for (unsigned int i = 0; i < nentries - 1; i++) {
        if (strcmp(parent_entries[i].filename, new_dir_name) == 0) {
            memset(parent_entries[i].filename, '\0', SFS_FILENAME_MAX);
            parent_entries[i].size = 0;

            blockidx_t blocktable[SFS_BLOCKTBL_NENTRIES];
            disk_read(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);
            log("Read block table\n");

            blocktable[parent_entries[i].first_block] = SFS_BLOCKIDX_EMPTY;
            blocktable[parent_entries[i].first_block + 1] = SFS_BLOCKIDX_EMPTY;
            disk_write(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);
            log("Updated block table\n");

            parent_entries[i].first_block = SFS_BLOCKIDX_EMPTY;
            break;
        }
    }

    disk_write(parent_entries, dir_size, parent_dir_offset);
    log("Updated parent directory entries\n");
    return 0;
}

/*
 * Remove file at `path`.
 * Cannot be used to remove directories.
 * Returns 0 on success, < 0 on error.
 */
static int sfs_unlink(const char *path)
{
    log("unlink %s\n", path);

    struct sfs_entry entry;
    unsigned entry_offset;
    int res = get_entry(path, &entry, &entry_offset);
    if (res != 0)
        return -ENOENT;
    if (entry.size & SFS_DIRECTORY)
        return -EISDIR;

    char *parent_path = get_parent_path(path);
    char *file_name = get_filename(path);

    if (strlen(file_name) >= SFS_FILENAME_MAX)
        return -ENAMETOOLONG;

    struct sfs_entry parent_entry;
    unsigned parent_entry_offset;
    res = get_entry(parent_path, &parent_entry, &parent_entry_offset);
    if (res < 0)
        return res;

    size_t nentries = SFS_DIR_NENTRIES;
    off_t parent_dir_offset = SFS_DATA_OFF + parent_entry.first_block * SFS_BLOCK_SIZE;
    size_t parent_dir_size = SFS_DIR_SIZE;
    if (strcmp(parent_path, "/") == 0) {
        nentries = SFS_ROOTDIR_NENTRIES;
        parent_dir_offset = SFS_ROOTDIR_OFF;
        parent_dir_size = SFS_ROOTDIR_SIZE;
    }

    struct sfs_entry parent_entries[nentries];
    disk_read(parent_entries, parent_dir_size, parent_dir_offset);

    int file_slot = -1;
    for (unsigned i = 0; i < nentries; i++) {
        if (strcmp(parent_entries[i].filename, file_name) == 0) {
            if (parent_entries[i].size & SFS_DIRECTORY) {
                return -EISDIR;
            }
            file_slot = i;
            break;
        }
    }

    if (file_slot == -1)
        return -ENOENT;

    blockidx_t block_table[SFS_BLOCKTBL_NENTRIES];
    disk_read(block_table, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);

    blockidx_t block_idx = parent_entries[file_slot].first_block;
    while (block_idx != SFS_BLOCKIDX_END) {
        blockidx_t next_block_idx = block_table[block_idx];
        block_table[block_idx] = SFS_BLOCKIDX_EMPTY;
        block_idx = next_block_idx;
    }

    disk_write(block_table, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);

    memset(parent_entries[file_slot].filename, '\0', SFS_FILENAME_MAX);
    parent_entries[file_slot].first_block = SFS_BLOCKIDX_EMPTY;
    parent_entries[file_slot].size = 0;

    disk_write(parent_entries, parent_dir_size, parent_dir_offset);

    return 0;
}



/*
 * Create an empty file at `path`.
 * The `mode` argument describes the permissions, which you may ignore for this
 * assignment.
 * Returns 0 on success, < 0 on error.
 */
static int sfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)fi;
    log("create %s mode=%o\n", path, mode);

    char *parent_path = get_parent_path(path);
    char *new_file_name = get_filename(path);
    if (strlen(new_file_name) >= SFS_FILENAME_MAX) {
        return -ENAMETOOLONG;
    }

    struct sfs_entry parent_entry;
    unsigned parent_entry_offset;

    if (strcmp(parent_path, "/") == 0) {
        strncpy(parent_entry.filename, "/", SFS_FILENAME_MAX);
        parent_entry.size = SFS_ROOTDIR_SIZE;
        parent_entry.first_block = 0;
        parent_entry_offset = SFS_ROOTDIR_OFF;
    } else {
        int res = get_entry(parent_path, &parent_entry, &parent_entry_offset);
        if (res < 0) {
            return res;
        }
    }

    size_t nentries = SFS_DIR_NENTRIES;
    off_t parent_dir_offset = SFS_DATA_OFF + parent_entry.first_block * SFS_BLOCK_SIZE;
    size_t size = SFS_DIR_SIZE;
    if (strcmp(parent_entry.filename, "/") == 0) {
        nentries = SFS_ROOTDIR_NENTRIES;
        parent_dir_offset = SFS_ROOTDIR_OFF;
        size = SFS_ROOTDIR_SIZE;
    }
    struct sfs_entry parent_entries[nentries];
    disk_read(parent_entries, size, parent_dir_offset);

    int empty_slot = -1;
    for (unsigned i = 0; i < nentries; i++) {
        if (parent_entries[i].filename[0] == '\0') {
            empty_slot = i;
            break;
        }
    }
    if (empty_slot == -1) {
        free(new_file_name);
        return -ENOSPC;
    }

    struct sfs_entry new_file_entry;
    memset(&new_file_entry, 0, sizeof(new_file_entry));
    strncpy(new_file_entry.filename, new_file_name, SFS_FILENAME_MAX);
    new_file_entry.size = 0;
    new_file_entry.first_block = SFS_BLOCKIDX_END;
    free(new_file_name);

    parent_entries[empty_slot] = new_file_entry;
    disk_write(parent_entries, size, parent_dir_offset);

    return 0;
}

/*
 * Shrink or grow the file at `path` to `size` bytes.
 * Excess bytes are thrown away, whereas any bytes added in the process should
 * be nil (\0).
 * Returns 0 on success, < 0 on error.
 */
static int get_free_block(blockidx_t *block_table)
{
    for (blockidx_t i = 0; i < SFS_BLOCKTBL_NENTRIES; i++) {
        if (block_table[i] == SFS_BLOCKIDX_EMPTY)
            return i;
    }
    return -1;
}

static int sfs_truncate(const char *path, off_t size)
{
    log("truncate called on %s with size=%ld\n", path, size);

    struct sfs_entry entry;
    unsigned offset;
    int result = get_entry(path, &entry, &offset);
    if (result < 0)
        return result;
    if (result != 0)
        return -ENOENT;
    if (entry.size & SFS_DIRECTORY)
        return -EISDIR;

    blockidx_t blocktable[SFS_BLOCKTBL_NENTRIES];
    disk_read(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);

    blockidx_t new_start_block = entry.first_block;
    blockidx_t current_block = entry.first_block;

    unsigned int current_block_count = (entry.size + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;
    unsigned int required_block_count = (size + SFS_BLOCK_SIZE - 1) / SFS_BLOCK_SIZE;

    if (size < entry.size) {
        blockidx_t next_block;
        unsigned int block_index = 0;

        while (current_block != SFS_BLOCKIDX_END && block_index < current_block_count) {
            next_block = blocktable[current_block];

            if (block_index >= required_block_count)
                blocktable[current_block] = SFS_BLOCKIDX_EMPTY;
            else if (block_index == required_block_count - 1)
                blocktable[current_block] = SFS_BLOCKIDX_END;
            current_block = next_block;
            block_index++;
        }
        if (required_block_count == 0)
            new_start_block = SFS_BLOCKIDX_END;
        disk_write(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);
    }
    else if (size > entry.size) {
        required_block_count++;

        if (current_block != SFS_BLOCKIDX_END) {
            while (blocktable[current_block] != SFS_BLOCKIDX_END) {
                current_block = blocktable[current_block];
            }
        }
        else {
            current_block = get_free_block(blocktable);
            new_start_block = current_block;
            if (current_block == SFS_BLOCKIDX_END)
                return -ENOSPC;
            entry.first_block = current_block;
        }
        for (unsigned int block_index = current_block_count; block_index < required_block_count; block_index++) {
            int new_block = get_free_block(blocktable);
            if (new_block == -1)
                return -ENOSPC;
            blocktable[current_block] = new_block;
            current_block = new_block;
        }
        blocktable[current_block] = SFS_BLOCKIDX_END;
        disk_write(blocktable, SFS_BLOCKTBL_SIZE, SFS_BLOCKTBL_OFF);
    }

    struct sfs_entry parent_entry;
    unsigned parent_offset;
    char *parent_directory = get_parent_path(path);
    char *file_name = get_filename(path);
    result = get_entry(parent_directory, &parent_entry, &parent_offset);
    if (result < 0) return result;

    size_t nentries = SFS_DIR_NENTRIES;
    off_t parent_dir_offset = SFS_DATA_OFF + parent_entry.first_block * SFS_BLOCK_SIZE;
    size_t read_size = SFS_DIR_SIZE;
    if (strcmp(parent_directory, "/") == 0) {
        parent_dir_offset = SFS_ROOTDIR_OFF;
        read_size = SFS_ROOTDIR_SIZE;
        nentries = SFS_ROOTDIR_NENTRIES;
    }
    struct sfs_entry directory_entries[nentries];
    disk_read(directory_entries, read_size, parent_dir_offset);

    for (unsigned int i = 0; i < nentries; i++) {
        if (strcmp(directory_entries[i].filename, file_name) == 0) {
            directory_entries[i].size = size;
            directory_entries[i].first_block = new_start_block;
            break;
        }
    }

    disk_write(directory_entries, read_size, parent_dir_offset);
    return 0;
}



/*
 * Write contents of `buf` (of `size` bytes) to the file at `path`.
 * The file is grown if nessecary, and any bytes already present are overwritten
 * (whereas any other data is left intact). The `offset` argument specifies how
 * many bytes should be skipped in the file, after which `size` bytes from
 * buffer are written.
 * This means that the new file size will be max(old_size, offset + size).
 * Returns the number of bytes written, or < 0 on error.
 */
static int sfs_write(const char *path,
                     const char *buf,
                     size_t size,
                     off_t offset,
                     struct fuse_file_info *fi)
{
    (void)fi;
    log("write %s data='%.*s' size=%zu offset=%ld\n", path, (int)size, buf,
        size, offset);

    return -ENOSYS;
}


/*
 * Move/rename the file at `path` to `newpath`.
 * Returns 0 on succes, < 0 on error.
 */
static int sfs_rename(const char *path,
                      const char *newpath)
{
    /* Implementing this function is optional, and not worth any points. */
    log("rename %s %s\n", path, newpath);

    return -ENOSYS;
}


static const struct fuse_operations sfs_oper = {
        .getattr    = sfs_getattr,
        .readdir    = sfs_readdir,
        .read       = sfs_read,
        .mkdir      = sfs_mkdir,
        .rmdir      = sfs_rmdir,
        .unlink     = sfs_unlink,
        .create     = sfs_create,
        .truncate   = sfs_truncate,
        .write      = sfs_write,
        .rename     = sfs_rename,
};


#define OPTION(t, p)                            \
    { t, offsetof(struct options, p), 1 }
#define LOPTION(s, l, p)                        \
    OPTION(s, p),                               \
    OPTION(l, p)
static const struct fuse_opt option_spec[] = {
        LOPTION("-i %s",    "--img=%s",     img),
        LOPTION("-b",       "--background", background),
        LOPTION("-v",       "--verbose",    verbose),
        LOPTION("-h",       "--help",       show_help),
        OPTION(             "--fuse-help",  show_fuse_help),
        FUSE_OPT_END
};

static void show_help(const char *progname)
{
    printf("usage: %s mountpoint [options]\n\n", progname);
    printf("By default this FUSE runs in the foreground, and will unmount on\n"
           "exit. If something goes wrong and FUSE does not exit cleanly, use\n"
           "the following command to unmount your mountpoint:\n"
           "  $ fusermount -u <mountpoint>\n\n");
    printf("common options (use --fuse-help for all options):\n"
           "    -i, --img=FILE      filename of SFS image to mount\n"
           "                        (default: \"%s\")\n"
           "    -b, --background    run fuse in background\n"
           "    -v, --verbose       print debug information\n"
           "    -h, --help          show this summarized help\n"
           "        --fuse-help     show full FUSE help\n"
           "\n", default_img);
}

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    options.img = strdup(default_img);

    fuse_opt_parse(&args, &options, option_spec, NULL);

    if (options.show_help) {
        show_help(argv[0]);
        return 0;
    }

    if (options.show_fuse_help) {
        assert(fuse_opt_add_arg(&args, "--help") == 0);
        args.argv[0][0] = '\0';
    }

    if (!options.background)
        assert(fuse_opt_add_arg(&args, "-f") == 0);

    disk_open_image(options.img);

    return fuse_main(args.argc, args.argv, &sfs_oper, NULL);
}
