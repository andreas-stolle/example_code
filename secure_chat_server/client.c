#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include <regex.h>
#include <fcntl.h>
struct client_state {
    struct api_state api;
    int eof;
    struct ui_state ui;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    char username[MAX_TOKEN_LENGTH];
};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
                          const char *hostname, uint16_t port) {
    printf("Attempting to connect to %s on port %d...\n", hostname, port);
    int fd;
    struct sockaddr_in addr;

    assert(state);
    assert(hostname);

    /* look up hostname */
    if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    /* create TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("error: cannot allocate server socket");
        return -1;
    }

    /* connect to server */
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("error: cannot connect to server");
        close(fd);
        return -1;
    }
    printf("Connected to server successfully.\n");
    return fd;
}

//FROM EXAMPLE
int ssl_block_connect(SSL *ssl, int fd) {
    int r;

    /* return value:
     *   -1: error
     *    1: success
     */

    /* block until the call succeeds */
    for (;;) {
        r = SSL_connect(ssl);
        if (r == 1) return 1;
        r = ssl_block_if_needed(ssl, fd, r);
        if (r != 1) return -1;
    }
}

// In client.c, modify client_ssl_connect to set non-blocking mode:
static void client_ssl_connect(struct client_state *state) {
    // printf("Starting SSL client setup...\n");
    
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    // printf("SSL_CTX created: %p\n", (void*)ctx);
    
    SSL *ssl = SSL_new(ctx);
    // printf("SSL created: %p\n", (void*)ssl);
    
    // Set socket to non-blocking mode BEFORE SSL setup
    int flags = fcntl(state->api.fd, F_GETFL, 0);
    fcntl(state->api.fd, F_SETFL, flags | O_NONBLOCK);
    // printf("Set socket to non-blocking mode\n");
    
    SSL_set_fd(ssl, state->api.fd);
    // printf("SSL set to fd: %d\n", state->api.fd);
    
    // printf("Attempting SSL_connect...\n");
    ssl_block_connect(ssl, state->api.fd);
    // printf("SSL_connect result: %d\n", result);
    
    // Store in client state
    state->ssl_ctx = ctx;
    state->ssl = ssl;
    state->api.ssl = ssl;
    state->api.ctx = ctx;
    
    // printf("SSL client setup complete. state->api.ssl = %p\n", (void*)state->api.ssl);
}
//chatgpt - "please purge remaining characters from input if the input is too large. im putting it in a validate command function"
static int validate_command(struct client_state *state, char *buffer) {
    size_t len = strlen(buffer);

    // Reject empty input (just pressing Enter)
    if (len == 1 && buffer[0] == '\n') {
        fprintf(stderr, "error: empty input is not allowed\n");
        return -1; // Print error and continue
    }

    // Check for input too long (no newline found)
    if (len > 0 && buffer[len - 1] != '\n' && !feof(stdin)) {
        fprintf(stderr, "error: message too long (max %d characters)\n", MAX_MSG_LENGTH - 1);

        // Clear the remaining characters from the input stream
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);
        return -1; // Print error and continue
    }

    return 0; // Input is valid
}

// In client.c, fix client_process_command to send raw command:
static int client_process_command(struct client_state *state) {
    assert(state);

    char buffer[MAX_MSG_LENGTH];
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        state->eof = 1;
        return 0;
    }

    if (validate_command(state, buffer) != 0) {
        if (state->eof) {
            return 0;
        }
        return 0;
    }

    char command[MAX_MSG_LENGTH];
    snprintf(command, sizeof(command), "%s", trim_whitespace(buffer));
    // printf("DEBUG: Client sending raw command: '%s'\n", command);

    // Send raw command using SSL directly
    ssize_t to_write = strlen(command);
    ssize_t written = 0;
    while (written < to_write) {
        ssize_t r;
        
        if (state->api.ssl) {
            r = ssl_block_write(state->api.ssl, state->api.fd, command + written, to_write - written);
        } else {
            r = send(state->api.fd, command + written, to_write - written, 0);
        }
        
        if (r <= 0) {
            return -1;
        }
        written += r;
    }
    
    // Send newline
    char newline = '\n';
    if (state->api.ssl) {
        ssl_block_write(state->api.ssl, state->api.fd, &newline, 1);
    } else {
        send(state->api.fd, &newline, 1, 0);
    }
    
    // printf("DEBUG: Sent %zd bytes\n", written + 1);
    return 0;
}
static int call_ttp_script(const char *username, const char *hex_signature) {
    pid_t pid;
    int status;

    // printf("Calling TTP script with fork/exec for user: %s\n", username);

    pid = fork();
    if (pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (pid == 0) {
        // Child process - execute the TTP script
        execl("./ttp.py", "ttp.py", "client", username, hex_signature, (char *)NULL);

        // If execl returns, it failed
        perror("execl failed");
        exit(1);
    } else {
        // Parent process - wait for child to complete
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid failed");
            return -1;
        }

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (exit_code == 0) {
                // printf("TTP script executed successfully\n");
                return 0;
            } else {
                fprintf(stderr, "TTP script failed with exit code: %d\n", exit_code);
                return -1;
            }
        } else {
            fprintf(stderr, "TTP script terminated abnormally\n");
            return -1;
        }
    }
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
    struct client_state *state,
    const struct api_msg *msg) {
    
    assert(state);
    assert(msg);

    // parse msg format: SYSTEM_SIGNED|...|...|SIGNATURE:username:hex_signature
    if (strncmp(msg->content, "SYSTEM_SIGNED|", 14) == 0) {
        const char *pipes[3] = {NULL};
        const char *ptr = msg->content;

        // find three pipes
        for (int i = 0; i < 3; i++) {
            pipes[i] = strchr(ptr, '|');
            if (!pipes[i]) {
                fprintf(stderr, "error: malformed SYSTEM_SIGNED message");
                return -1;
            }
            ptr = pipes[i] + 1;
        }

        // set content after third pipe
        const char *content = pipes[2] + 1;

        // verify prefix
        if (strncmp(content, "SIGNATURE:", 10) != 0) {
            fprintf(stderr, "error: expected SIGNATURE prefix in message");
            return -1;
        }

        // parse signature content
        char *signature_content = strdup(content + 10);
        if (!signature_content) {
            perror("error: memory allocation failed");
            return -1;
        }

        char *p;
        char *id = strtok_r(signature_content, ":", &p);
        char *hex_signature = strtok_r(NULL, ":", &p);

        if (!id || !hex_signature) {
            fprintf(stderr, "error: malformed signature format");
            free(signature_content);
            return -1;
        }

        // generate client keys
        if (call_ttp_script(id, hex_signature) != 0) {
            fprintf(stderr, "failed to generate client keys for user");
            free(signature_content);
            return -1;
        }


        // split id (username|timestamp)
        p = NULL;
        char *username = strtok_r(id, "|", &p);
        if (!username) {
            fprintf(stderr, "error: malformed id format");
            free(signature_content);
            return -1;
        }

        // store username
        strncpy(state->username, username, MAX_TOKEN_LENGTH - 1);
        state->username[MAX_TOKEN_LENGTH - 1] = '\0';

        free(signature_content);

        return 0;

        // // get certificate from file (clientkeys/client-{username}-cert.pem)
        // size_t clientkeyfile_len = MAX_TOKEN_LENGTH + strlen("clientkeys/client--cert.pem") + 1;
        // char clientkeyfile[clientkeyfile_len];
        // snprintf(clientkeyfile, clientkeyfile_len, "clientkeys/client-%s-cert.pem", state->username);
        // // open cert file
        // FILE *cert_file = fopen(clientkeyfile, "r");
        // if (!cert_file) {
        //     perror("error: failed to open client certificate file");
        //     return -1;
        // }
        //
        // // read cert file
        // fseek(cert_file, 0, SEEK_END);
        // long cert_size = ftell(cert_file);
        // fseek(cert_file, 0, SEEK_SET);
        //
        // unsigned char *cert_data = malloc(cert_size);
        // if (!cert_data) {
        //     perror("error: memory allocation failed");
        //     fclose(cert_file);
        //     return -1;
        // }
        //
        // size_t bytes_read = fread(cert_data, 1, cert_size, cert_file);
        // fclose(cert_file);
        //
        // if (bytes_read != cert_size) {
        //     fprintf(stderr, "error: failed to read certificate file");
        //     free(cert_data);
        //     return -1;
        // }
        //
        // // send cert registration command to server (/certregister cert_hex_len \n cert_hex_data)
        // // Send command with just the length
        // char certreg_command[256];
        // snprintf(certreg_command, sizeof(certreg_command), "/certregister %zu\n", cert_size);
        //
        // ssize_t to_write = strlen(certreg_command);
        // ssize_t written = 0;
        // while (written < to_write) {
        //     ssize_t r = write(state->api.fd, certreg_command + written, to_write - written);
        //     if (r <= 0) {
        //         perror("error: failed to send certregister command");
        //         free(cert_data);
        //         return -1;
        //     }
        //     written += r;
        // }
        //
        // // Now send raw certificate data
        // written = 0;
        // while (written < cert_size) {
        //     ssize_t r = write(state->api.fd, cert_data + written, cert_size - written);
        //     if (r <= 0) {
        //         perror("error: failed to send certificate data");
        //         free(cert_data);
        //         return -1;
        //     }
        //     written += r;
        // }
        //
        // free(cert_data);
    }

    char formatted_message[MAX_MSG_LENGTH];

    //TODO display messages is 512 and max normal message is smaller so need to check and pass allowedSize
    if (format_message(msg->content, state->api.user, formatted_message, sizeof(formatted_message), MAX_MSG_LENGTH)) {
        printf("%s\n", formatted_message);
    } else {
        fprintf(stderr, "error: failed to format message\n");
    }

    fflush(stdout);

    return 0;
}
/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
    struct api_msg msg;
    int r, success = 1;

    assert(state);

    // printf("DEBUG: handle_server_request called\n");

    /* wait for incoming request, set eof if there are no more requests */
    r = api_recv(&state->api, &msg);
    // printf("DEBUG: api_recv returned: %d\n", r);
    
    if (r < 0) {
        // printf("DEBUG: api_recv error: %s\n", strerror(errno));
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // Non-blocking, no data available
        }
        return -1;
    }
    if (r == 0) {
        // printf("DEBUG: api_recv returned 0 (EOF)\n");
        state->eof = 1;
        return 0;
    }

    // printf("DEBUG: Received message content: '%s'\n", msg.content);

    /* execute request */
    if (execute_request(state, &msg) == 0) {
        success = 0;
    }

    /* clean up state associated with the message */
    api_recv_free(&msg);

    return success;
}
/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
    int fdmax, r;
    fd_set readfds;

    assert(state);

    // printf("DEBUG: handle_incoming called\n");

    /* list file descriptors to wait for */
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(state->api.fd, &readfds);
    fdmax = state->api.fd;

    // printf("DEBUG: About to call select, waiting for input...\n");
    
    /* wait for at least one to become ready */
    r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
    if (r < 0) {
        if (errno == EINTR) return 0;
        perror("error: select failed");
        return -1;
    }
    
    // printf("DEBUG: select returned %d\n", r);
    
    /* handle ready file descriptors */
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
        // printf("DEBUG: STDIN ready, calling client_process_command\n");
        return client_process_command(state);
    }
    
    if (FD_ISSET(state->api.fd, &readfds)) {
        // printf("DEBUG: Server socket ready, calling handle_server_request\n");
        return handle_server_request(state);
    }
    
    // printf("DEBUG: No file descriptors were ready?\n");
    return 0;
}
static int client_state_init(struct client_state *state) {
    /* clear state, invalidate file descriptors */
    memset(state, 0, sizeof(*state));

    return 0;
}

static void client_state_free(struct client_state *state) {
    /* cleanup API state */
    api_state_free(&state->api);

    /* cleanup UI state */
    ui_state_free(&state->ui);
}

static void usage(void) {
    printf("usage:\n");
    printf("  client host port\n");
    exit(1);
}

int main(int argc, char **argv) {
    int fd;
    uint16_t port;
    struct client_state state;

    /* check arguments */
    if (argc != 3) usage();
    if (parse_port(argv[2], &port) != 0) usage();

    /* preparations */
    client_state_init(&state);

    /* connect to server */
    fd = client_connect(&state, argv[1], port);
    if (fd < 0) return 1;

    /* initialize API */
    api_state_init(&state.api, fd);
    
    /* Set up SSL */
    client_ssl_connect(&state);

    /* TODO any additional client initialization */

    /* client things */
    while (!state.eof && handle_incoming(&state) == 0);

    /* clean up */
    printf("cleaning up\n");
    /* TODO any additional client cleanup */
    client_state_free(&state);
    close(fd);

    return 0;
}