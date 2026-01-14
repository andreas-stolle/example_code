# Operating System Components (C)

## Components

### Unix Shell
Implements a custom Unix shell supporting command execution via `fork`/`exec`, job control, signal handling, pipes, and I/O redirection. The design closely follows traditional Unix process semantics.

### Memory Allocator
A custom dynamic memory allocator implementing `malloc`, `free`, and `realloc` without relying on the standard library. The allocator manages a heap using explicit metadata, free lists, and block splitting/coalescing.

### Simple File System (FUSE-based)
A user-space file system implementing a simple on-disk layout with directory entries, block allocation tables, and file metadata. Supports hierarchical directories and basic file operations with explicit disk I/O.

### Key-Value Store
A persistent key-value store providing basic insert, lookup, and delete operations. Designed to explore data layout, consistency, and error handling at a low level.
