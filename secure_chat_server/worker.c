#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "db.h"
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct worker_state {
    struct api_state api;
    int eof;
    int server_fd; /* server <-> worker bidirectional notification channel */
    int server_eof;
    /* TODO worker state variables go here */

    long last_offset;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

static int send_system_message(struct worker_state *state, const char *format, ...) {
    struct api_msg response = {0};
    response.type = MSG_SYSTEM;
    response.timestamp = time(NULL);

    va_list args; //use of va to prevent format string vulnerability
    va_start(args, format);
    vsnprintf(response.content, MAX_MSG_LENGTH, format, args);
    va_end(args);

    return api_send(&state->api, &response);
}

static int msg_iterator(long offset, const char *type, time_t timestamp, const char *sender,
                        const char *recipient, const char *content, void *user_state) {
    struct worker_state *state = user_state;
    struct api_msg msg = {
        .timestamp = timestamp,
        .valid = true,
        .type = (strncmp(type, "PUBLIC", 6) == 0) ? MSG_PUBLIC : MSG_PRIVATE
    };

    if (!sender || !content) { return -1; }

    if (msg.type == MSG_PRIVATE) {
        if (!recipient) { return -1; }
        strncpy(msg.recipient, recipient, MAX_TOKEN_LENGTH - 1);
    }
    strncpy(msg.sender, sender, MAX_TOKEN_LENGTH - 1);
    strncpy(msg.content, content, MAX_MSG_LENGTH - 1);

    api_send(&state->api, &msg);
    state->last_offset = offset;
    return 0;
}

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
    if (!state->api.authenticated) {
        return 0;
    }
    return db_iterate_messages(state->last_offset, state->api.user, msg_iterator, state);
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state) {
    char buf = 0;
    ssize_t r;

    /* we only need to send something to notify the other workers,
     * data does not matter
     */
    r = write(state->server_fd, &buf, sizeof(buf));
    if (r < 0 && errno != EPIPE) {
        perror("error: write of server_fd failed");
        return -1;
    }
    return 0;
}

static int display_previous_messages(struct worker_state *state) {
    assert(state);
    return db_iterate_messages(0, state->api.user, msg_iterator, state);
}

static void store_message(const char *type, const char *sender,
                          const char *recipient, const char *content) {
    char normalized_content[MAX_MSG_LENGTH];
    strncpy(normalized_content, content, MAX_MSG_LENGTH - 1);
    normalized_content[MAX_MSG_LENGTH - 1] = '\0';
    trim_whitespace(normalized_content);

    if (db_store_message(type, time(NULL), sender, recipient, normalized_content) != 0) {
        fprintf(stderr, "error: failed to store message in database");
    }
}

static int handle_private_message(struct worker_state *state, const struct api_msg *msg, const char *content) {
    store_message("PRIVATE", msg->sender, msg->recipient, msg->content);
    if (notify_workers(state) != 0) {
        fprintf(stderr, "error: notify_workers failed\n");
        return -1;
    }
    return 0;
}

static int handle_public_message(struct worker_state *state, const struct api_msg *msg, const char *content) {
    store_message("PUBLIC", msg->sender, NULL, msg->content);
    if (notify_workers(state) != 0) {
        fprintf(stderr, "error: notify_workers failed\n");
        return -1;
    }
    return 0;
}

static int handle_exit_command(struct worker_state *state) {
    // TODO any other cleanup if necessary
    state->eof = 1;
    int logout = db_logout_user(state->api.user);
    if (logout != 0) printf("Logout error");
    return 0;
}

static int handle_login_command(struct worker_state *state, const char *username, const char *password) {
    int status;
    if (state->api.authenticated) {
        status = send_system_message(state, "error: you are already logged in as %s", state->api.user);
    } else {
        switch (db_login_user(username, password)) {
            case 0:
                state->api.authenticated = 1;
                strncpy(state->api.user, username, MAX_TOKEN_LENGTH - 1);
                status = send_system_message(state, "authentication succeeded");
                display_previous_messages(state);
                break;
            case -2:
            case -3:
                status = send_system_message(state, "error: invalid credentials");
                break;
            case -1:
            default:
                status = send_system_message(state, "error: command not currently available");
                break;
        }
    }
    free((void *) username);
    free((void *) password);
    return status;
}

static int verify_client(struct worker_state *state, const char *username) {
    // 1. Create message: username|unix_timestamp
    char message[MAX_TOKEN_LENGTH + 1 + 32];
    time_t currTime = time(NULL);
    snprintf(message, sizeof(message), "%s|%ld", username, currTime);

    // 2. Load private key
    EVP_PKEY *privkey = rsa_read_privkey_from_file("serverkeys/server-key.pem");
    if (!privkey) {
        fprintf(stderr, "error: failed to load private key");
        return -1;
    }

    // 3. Sign the message
    unsigned char *signature = NULL;
    unsigned int sig_len = 0;
    if (rsa_sign_text(message, privkey, &signature, &sig_len) != 0) {
        fprintf(stderr, "error: failed to sign message for user %s\n", username);
        EVP_PKEY_free(privkey);
        return -1;
    }

    // 4. Convert binary signature to hex for transmission
    char *hex_sig = malloc(sig_len * 2 + 1);
    if (!hex_sig) {
        free(signature);
        EVP_PKEY_free(privkey);
        return -1;
    }

    for (size_t i = 0; i < sig_len; i++) {
        sprintf(hex_sig + i * 2, "%02x", signature[i]);
    }
    hex_sig[sig_len * 2] = '\0';

    // 5. Create response with new message type
    struct api_msg response = {0};
    response.type = MSG_SYSTEM_SIGNED; // Use the new type
    response.timestamp = time(NULL);
    snprintf(response.content, MAX_MSG_LENGTH, "SIGNATURE:%s:%s",
             message, hex_sig);

    // 6. Send to client
    int result = api_send(&state->api, &response);

    // 7. Cleanup
    free(signature);
    free(hex_sig);
    EVP_PKEY_free(privkey);

    return result;
}

static int handle_register_command(struct worker_state *state, const char *username, const char *password) {
    int status;
    switch (db_register_user(username, password)) {
        case 0:
            status = send_system_message(state, "registration succeeded"); //return value not handled
            state->api.authenticated = 1;
            strncpy(state->api.user, username, MAX_TOKEN_LENGTH - 1); //log user in
            if (verify_client(state, username) != 0) {
                fprintf(stderr, "error: failed to verify client %s", username);
            }
            display_previous_messages(state);
            break;
        case -2:
            status = send_system_message(state, "error: user %s already exists", username);
            break;
        case -1:
        default:
            status = send_system_message(state, "error: command not currently available");
            break;
    }
    free((void *) username);
    free((void *) password);
    return status;
}

static int handle_users_command(struct worker_state *state) {
    int num_online = db_get_online_user_count();

    if (num_online < 0) {
        return send_system_message(state, "error: command not currently available");
    }

    if (num_online == 0) {
        return send_system_message(state, "no users currently online");
    }

    int size = (num_online * MAX_TOKEN_LENGTH) + (num_online * 2);
    char *buf = malloc(size);
    if (buf == NULL) {
        return send_system_message(state, "error: memory allocation failed");
    }

    int rc = db_get_online_users(buf, size);
    if (rc != 0) {
        free(buf);
        if (rc == -2) {
            return send_system_message(state, "error: too many users online");
        } else {
            return send_system_message(state, "error: command not currently available");
        }
    }

    // The buffer is already null-terminated by db_get_online_users
    if (strlen(buf) == 0) {
        free(buf);
        return send_system_message(state, "no users currently online");
    }

    int result = send_system_message(state, "online users: %s", buf);
    free(buf);
    return result;
}

static int store_cert(struct worker_state *state, const char *username, const unsigned char *cert, int cert_len) {
    if (db_store_user_cert(username, cert, cert_len) != 0) {
        return send_system_message(state, "error: failed to store user certificate");
    }
    return 0;
}

int isLoggedIn(struct worker_state *state) {
    return state->api.authenticated;
}


/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(
    struct worker_state *state,
    struct api_msg *msg) {
    assert(state);
    assert(msg);

    const char *p = skip_whitespace(msg->content);

    if (*p == '/') {
        if (is_command(p, "/exit")) {
            printf("exiting...\n");
            return handle_exit_command(state);
        } else if (is_command(p, "/login")) {
            if (state->api.authenticated) {
                return send_system_message(state, "error: command not currently available");
            }

            p += strlen("/login");

            const char *username = extract_token(p);
            if (!username) {
                return send_system_message(state, "error: invalid command format");
            }

            p = skip_whitespace(p);
            p += strlen(username);

            const char *password = extract_token(p);
            if (!password) {
                free((void *) username);
                return send_system_message(state, "error: invalid command format");
            }
            p = skip_whitespace(p);
            p += strlen(password);
            const char *extra = extract_token(p);
            if (extra != NULL) {
                free((void *) username);
                free((void *) password);
                free((void *) extra);
                return send_system_message(state, "error: invalid command format");
            }


            return handle_login_command(state, username, password);
        } else if (is_command(p, "/register")) {
            if (state->api.authenticated) {
                return send_system_message(state, "error: command not currently available");
            }

            p += strlen("/register");

            const char *username = extract_token(p);
            if (!username) {
                return send_system_message(state, "error: invalid command format");
            }

            p = skip_whitespace(p);
            p += strlen(username);

            const char *password = extract_token(p);
            if (!password) {
                free((void *) username);
                return send_system_message(state, "error: invalid command format");
            }
            p = skip_whitespace(p);
            p += strlen(password);
            const char *extra = extract_token(p);
            if (extra != NULL) {
                free((void *) username);
                free((void *) password);
                free((void *) extra);
                return send_system_message(state, "error: invalid command format");
            }
            return handle_register_command(state, username, password);
        } else if (is_command(p, "/users")) {
            if (!state->api.authenticated) {
                return send_system_message(state, "error: command not currently available");
            }

            p += strlen("/users");
            p = skip_whitespace(p);
            const char *extra_arg = extract_token(p);
            if (extra_arg != NULL) {
                free((void *) extra_arg);
                return send_system_message(state, "error: invalid command format");
            }
            return handle_users_command(state);
        } else if (is_command(p, "/certregister")) {
            if (!state->api.authenticated) {
                return send_system_message(state, "error: command not currently available");
            }

            p += strlen("/certregister");
            p = skip_whitespace(p);

            const char *cert_len_str = extract_token(p);
            if (!cert_len_str) {
                return send_system_message(state, "error: invalid command format");
            }

            // convert to int
            char *endptr;
            long cert_len = strtol(cert_len_str, &endptr, 10);
            if (*endptr != '\0' || cert_len <= 0 || cert_len > 8192 || cert_len > MAX_MSG_LENGTH) {
                printf("Invalid cert length: %s\n", cert_len_str);
                free((void *) cert_len_str);
                return send_system_message(state, "error: invalid public key length");
            }

            p = skip_whitespace(p);
            p += strlen(cert_len_str);

            // read cert manually
            unsigned char *cert = malloc(cert_len);
            if (!cert) {
                free((void *) cert_len_str);
                return send_system_message(state, "error: command not currently available");
            }

            size_t total_read = 0;
            while (total_read < (size_t)cert_len) {
                ssize_t n = read(state->api.fd, cert + total_read, cert_len - total_read);
                if (n <= 0) {
                    free(cert);
                    free((void *) cert_len_str);
                    return send_system_message(state, "error: failed to receive certificate data");
                }
                total_read += n;
            }

            // store cert
            int status = store_cert(state, state->api.user, cert, (int) cert_len);
            free((void *) cert_len_str);
            free(cert);
            return status;
        } else {
            const char *command_end = p;
            while (*command_end && !is_whitespace(command_end) && *command_end != '\0') {
                command_end++;
            }

            char unknown_cmd[32];
            size_t cmd_len = command_end - p;
            if (cmd_len >= sizeof(unknown_cmd)) {
                cmd_len = sizeof(unknown_cmd) - 1;
            }
            strncpy(unknown_cmd, p, cmd_len);
            unknown_cmd[cmd_len] = '\0';

            return send_system_message(state, "error: unknown command %s", unknown_cmd);
        }
    } else if (*p == '@') {
        if (!state->api.authenticated) {
            return send_system_message(state, "error: command not currently available");
        }

        const char *recipient = extract_token(p + 1);
        if (!recipient) {
            return send_system_message(state, "error: invalid command format");
        }

        if (db_user_exists(recipient) != 0) {
            free((void *) recipient);
            return send_system_message(state, "error: user not found");
        }
        strncpy(msg->recipient, recipient, MAX_TOKEN_LENGTH - 1);
        p = skip_whitespace(p + 1 + strlen(recipient));
        free((void *) recipient);

        return handle_private_message(state, msg, p);
    } else {
        if (!state->api.authenticated) {
            return send_system_message(state, "error: command not currently available");
        }
        return handle_public_message(state, msg, p);
    }
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
    struct api_msg msg;
    int r, success = 1;

    assert(state);

    /* wait for incoming request, set eof if there are no more requests */
    r = api_recv(&state->api, &msg);
    if (r < 0) return -1;
    if (r == 0) {
        state->eof = 1;
        return 0;
    }

    /* execute request */
    if (execute_request(state, &msg) != 0) {
        success = 0;
    }

    /* clean up state associated with the message */
    api_recv_free(&msg);

    return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
    char buf[256];
    ssize_t r;

    /* notification from the server that the workers must notify their clients
     * about new messages; these notifications are idempotent so the number
     * does not actually matter, nor does the data sent over the pipe
     */
    errno = 0;
    r = read(state->server_fd, buf, sizeof(buf));
    if (r < 0) {
        perror("error: read server_fd failed");
        return -1;
    }
    if (r == 0) {
        state->server_eof = 1;
        return 0;
    }

    /* notify our client */
    if (handle_s2w_notification(state) != 0) return -1;

    return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
    int fdmax, r, success = 1;
    fd_set readfds;

    assert(state);

    /* list file descriptors to wait for */
    FD_ZERO(&readfds);
    /* wake on incoming messages from client */
    FD_SET(state->api.fd, &readfds);
    /* wake on incoming server notifications */
    if (!state->server_eof)
        FD_SET(state->server_fd, &readfds);
    fdmax = max(state->api.fd, state->server_fd);

    /* wait for at least one to become ready */
    r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
    if (r < 0) {
        if (errno == EINTR) return 0;
        perror("error: select failed");
        return -1;
    }

    /* handle ready file descriptors */
    /* TODO once you implement encryption you may need to call ssl_has_data
     * here due to buffering (see ssl-nonblock example)
     */
    if (FD_ISSET(state->api.fd, &readfds)) {
        if (handle_client_request(state) != 0) success = 0;
    }
    if (FD_ISSET(state->server_fd, &readfds)) {
        if (handle_s2w_read(state) != 0) success = 0;
    }
    return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param server_fd    File descriptor for socket to communicate
 *                     between server and worker
 */
static int worker_state_init(
    struct worker_state *state,
    int connfd,
    int server_fd) {
    /* initialize */
    memset(state, 0, sizeof(*state));
    state->server_fd = server_fd;

    /* set up API state */
    api_state_init(&state->api, connfd);

    /* TODO any additional worker state initialization */

    state->last_offset = 0;

    return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(
    struct worker_state *state) {
    /* TODO any additional worker state cleanup */
    if (state->api.authenticated && strlen(state->api.user) > 0) {
        db_logout_user(state->api.user);
    }
     
    /* clean up API state */
    api_state_free(&state->api); //handles SSL free already

    /* close file descriptors */
    close(state->server_fd);
    close(state->api.fd);
}

//FROM EXAMPLE
int ssl_block_accept(SSL *ssl, int fd) {
    int r;

    /* return value:
     *   -1: error
     *    1: success
     */

    /* block until the call succeeds */
    for (;;) {
        r = SSL_accept(ssl);
        if (r == 1) return 1;
        r = ssl_block_if_needed(ssl, fd, r);
        if (r != 1) return -1;
    }
}

static void worker_ssl_accept(struct worker_state *state, const char *cert_file, const char *key_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL *ssl = SSL_new(ctx);
    SSL_use_certificate_file(ssl, cert_file, SSL_FILETYPE_PEM);
    SSL_use_PrivateKey_file(ssl, key_file, SSL_FILETYPE_PEM);
    SSL_set_fd(ssl, state->api.fd);
    ssl_block_accept(ssl, state->api.fd);
    
    // Store in worker state for later use
    state->ssl_ctx = ctx;
    state->ssl = ssl;
    state->api.ssl = ssl;
    state->api.ctx = ctx;
}


/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param server_fd    File descriptor for socket to communicate
 *                     between server and worker
 */
__attribute__((noreturn))
void worker_start(int connfd, int server_fd) {
    struct worker_state state;
    int success = 1;
    //    if (db_init("chat.db") != 0) {
    //        fprintf(stderr, "Worker: database initialization failed\n");
    //        exit(1);
    //    }

    /* initialize worker state */
    if (worker_state_init(&state, connfd, server_fd) != 0) {
        goto cleanup;
    }
    /* TODO any additional worker initialization */
    //display_previous_messages(&state);
    worker_ssl_accept(&state, "serverkeys/server-cert.pem", "serverkeys/server-key.pem");
    /* handle for incoming requests */
    while (!state.eof) {
        if (handle_incoming(&state) != 0) {
            success = 0;
            break;
        }
    }

cleanup:
    /* cleanup worker */
    /* TODO any additional worker cleanup */
    worker_state_free(&state);
    db_close();
    exit(success ? 0 : 1);
}
