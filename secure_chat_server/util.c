#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/decoder.h>

#include "util.h"
#include "api.h"

int lookup_host_ipv4(const char *hostname, struct in_addr *addr) {
    struct hostent *host;

    assert(hostname);
    assert(addr);

    /* look up hostname, find first IPv4 entry */
    host = gethostbyname(hostname);
    while (host) {
        if (host->h_addrtype == AF_INET &&
            host->h_addr_list &&
            host->h_addr_list[0]) {
            assert(host->h_length == sizeof(*addr));
            memcpy(addr, host->h_addr_list[0], sizeof(*addr));
            return 0;
        }
        host = gethostent();
    }

    fprintf(stderr, "error: unknown host: %s\n", hostname);
    return -1;
}

int max(int x, int y) {
    return (x > y) ? x : y;
}

int parse_port(const char *str, uint16_t *port_p) {
    char *endptr;
    long value;

    assert(str);
    assert(port_p);

    /* convert string to number */
    errno = 0;
    value = strtol(str, &endptr, 0);
    if (!value && errno) return -1;
    if (*endptr) return -1;

    /* is it a valid port number */
    if (value < 0 || value > 65535) return -1;

    *port_p = value;
    return 0;
}

bool is_whitespace(const char *c) {
    return (*c == ' ' || *c == '\t');
}

const char *skip_whitespace(const char *str) {
    while (is_whitespace(str)) str++;
    return str;
}

char *trim_whitespace(char *str) {
    if (!str || !*str) return str; // Handle NULL/empty strings
    char *start = str;
    while (isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    if (start != str) {
        memmove(str, start, end - start + 2); // +2 for null terminator
    }
    return str;
}

// extract a "token" - read value from string until tabs or spaces or end of string
// returned token must be freed
const char *extract_token(const char *p) {
    assert(p);

    // init
    const char *start = p;
    size_t len = 0;

    // skip leading whitespace
    start = skip_whitespace(start);

    // read till whitespace or end of string
    const char *end = start;
    while (*end && !is_whitespace(end)) {
        len++;
        end++;

        // check if token is too long
        if (len >= MAX_TOKEN_LENGTH) { return NULL; }
    }
    if (len == 0) return NULL;

    // allocate memory for token
    char *token = malloc(len + 1);
    assert(token);

    // write token value
    memcpy(token, start, len);
    token[len] = '\0';

    return token;
}

static void format_timestamp(long ts, char *out) {
    struct tm *tm_info = localtime(&ts);
    strftime(out, 64, "%Y-%m-%d %H:%M:%S", tm_info);
}

bool is_command(const char *p, const char *command) {
    size_t cmd_len = strlen(command);

    if (strncmp(p, command, cmd_len) != 0) return false;

    // idk why it didn't work before but had to check if followed by whitespace or end of string
    char next_char = p[cmd_len];
    return (next_char == ' ' || next_char == '\t' || next_char == '\0' || next_char == '\n');
}

bool format_message(const char *line, const char *current_user, char *output, size_t output_size, int allowedSize) {
    char line_copy[allowedSize];
    strncpy(line_copy, line, sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = '\0';

    char *curr_ptr = NULL;
    char *type = strtok_r(line_copy, "|", &curr_ptr);
    char *timestamp = strtok_r(NULL, "|", &curr_ptr);
    char *sender = strtok_r(NULL, "|", &curr_ptr);
    char *content = strtok_r(NULL, "|", &curr_ptr);
    char formatted_time[64];

    if (!type || !timestamp || !sender || !content) {
        fprintf(stderr, "error: malformed message\n");
        fprintf(stderr, "Debug Info - type: %s, timestamp: %s, sender: %s, content: %s\n",
                type ? type : "NULL",
                timestamp ? timestamp : "NULL",
                sender ? sender : "NULL",
                content ? content : "NULL");
        return false;
    }

    long ts = strtol(timestamp, NULL, 10);
    if (ts == 0 && strncmp(timestamp, "0", 1) != 0) {
        fprintf(stderr, "error: invalid timestamp '%s'\n", timestamp);
        return false;
    }

    format_timestamp(ts, formatted_time);

    if (strncmp(type, "PUBLIC", 6) == 0) {
        snprintf(output, output_size, "%s %s: %s", formatted_time, sender, content);
    } else if (strncmp(type, "PRIVATE", 7) == 0) {
        char *content = strtok_r(NULL, "|", &curr_ptr);
        if (!content) {
            fprintf(stderr, "error: malformed private message\n");
            return false;
        }
        snprintf(output, output_size, "%s %s: %s", formatted_time, sender, content);
    } else if (strncmp(type, "SYSTEM", 6) == 0) {
        // Special handling for /users command response
        if (strncmp(content, "online users: ", 14) == 0) {
            // Extract the user list part (skip "online users: ")
            const char *user_list = content + 14;

            // Start with the header
            int pos = snprintf(output, output_size, "online users:\n");

            // Parse comma-separated users and add each on new line
            char *list_copy = strdup(user_list);
            if (list_copy) {
                char *saveptr;
                char *username = strtok_r(list_copy, ",", &saveptr);

                while (username != NULL && pos < output_size - 50) {
                    // Trim whitespace from username
                    while (*username == ' ') username++;
                    char *end = username + strlen(username) - 1;
                    while (end > username && *end == ' ') *end-- = '\0';

                    pos += snprintf(output + pos, output_size - pos, "%s\n", username);
                    username = strtok_r(NULL, ",", &saveptr);
                }

                free(list_copy);

                // Remove trailing newline
                if (pos > 0 && output[pos - 1] == '\n') {
                    output[pos - 1] = '\0';
                }
            }
        } else {
            // Regular system message formatting
            snprintf(output, output_size, "%s", content);
        }
    } else {
        fprintf(stderr, "error: unknown message type '%s'\n", type);
        return false;
    }

    return true;
}

EVP_PKEY *rsa_read_privkey_from_file(const char *path) {
    if (!path) {
        fprintf(stderr, "error: no path to read RSA private key from");
        return NULL;
    }

    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "error: failed to open private key file");
        return NULL;
    }

    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *ctx = OSSL_DECODER_CTX_new_for_pkey(
        &key, /* key stored here */
        "PEM", /* input type */
        NULL,
        "RSA", /* key type */
        EVP_PKEY_KEYPAIR, /* pubkey or pub+privkey pair */
        NULL, NULL);

    if (!ctx) {
        fprintf(stderr, "error: failed to create decoder context to read RSA private key");
        fclose(file);
        return NULL;
    }

    if (OSSL_DECODER_from_fp(ctx, file) != 1) {
        fprintf(stderr, "error: failed to decode private key");
        OSSL_DECODER_CTX_free(ctx);
        fclose(file);
        return NULL;
    }

    OSSL_DECODER_CTX_free(ctx);
    fclose(file);

    if (!key) {
        fprintf(stderr, "error: no private key loaded");
        return NULL;
    }

    return key;
}

int rsa_sign_text(const char *text, EVP_PKEY *privkey, unsigned char **signature, unsigned int *signature_len) {
    assert(text);
    assert(privkey);
    assert(signature);
    assert(signature_len);

    // allocate signature buffer
    unsigned char *sig = malloc(EVP_PKEY_size(privkey));
    if (!sig) {
        fprintf(stderr, "error: failed to allocate signature buffer");
        return -1;
    }

    // create signing context
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        fprintf(stderr, "error: failed to create signing context");
        free(sig);
        return -1;
    }

    // initialize signing
    if (EVP_SignInit(ctx, EVP_sha256()) != 1) {
        fprintf(stderr, "error: failed to initialize signing");
        EVP_MD_CTX_free(ctx);
        free(sig);
        return -1;
    }

    // update with text data
    if (EVP_SignUpdate(ctx, text, strlen(text)) != 1) {
        fprintf(stderr, "error: failed to update signing context");
        EVP_MD_CTX_free(ctx);
        free(sig);
        return -1;
    }

    // finalize signature
    unsigned int sig_len = 0;
    if (EVP_SignFinal(ctx, sig, &sig_len, privkey) != 1) {
        fprintf(stderr, "error: failed to finalize signature");
        EVP_MD_CTX_free(ctx);
        free(sig);
        return -1;
    }

    // clean up
    EVP_MD_CTX_free(ctx);

    // return signature and length
    *signature = sig;
    *signature_len = sig_len;

    return 0;
}
