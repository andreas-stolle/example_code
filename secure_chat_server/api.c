#include <assert.h>
#include <string.h>

#include "api.h"

#include <stdio.h>
#include <unistd.h>

#include "util.h"
#include <openssl/ssl.h>  // Add this line
#include <openssl/err.h>  // Add this line
/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
// In api.c, modify api_recv to add debug output
// In api.c, modify api_recv to handle non-blocking reads:
// In api.c, modify api_recv to properly handle EAGAIN:
int api_recv(struct api_state *state, struct api_msg *msg) {
    assert(state && msg);

    char buf[MAX_MSG_LENGTH];
    ssize_t bytes_read = 0;

    memset(msg, 0, sizeof(struct api_msg));
    memset(buf, 0, MAX_MSG_LENGTH);

    // printf("DEBUG: api_recv starting, ssl=%p\n", (void*)state->ssl);

    while (bytes_read < MAX_MSG_LENGTH - 1) {
        ssize_t n;

        if (state->ssl) {
            // printf("api recv: Using ssl\n");
            n = ssl_block_read(state->ssl, state->fd, buf + bytes_read, 1);
        } else {
            printf("api recv: not ssl, using normal\n");
            n = read(state->fd, buf + bytes_read, 1);
        }
        
        // printf("DEBUG: Read %zd bytes", n);
        if (n > 0) {
            // printf(" (char: '%c' = %d)", buf[bytes_read], (unsigned char)buf[bytes_read]);
        }
        // printf("\n");
        
        if (n < 0) {
            // printf("DEBUG: Read error, returning -1\n");
            return -1;
        }
        
        if (n == 0) {
            // Check if this is "would block" or actual EOF
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // printf("DEBUG: Would block (no data), returning -1 with EAGAIN\n");
                return -1; // Return -1 for "no data available"
            } else {
                // printf("DEBUG: Actual EOF, returning 0\n");
                return 0;  // Actual EOF
            }
        }

        if (buf[bytes_read] == '\n') {
            buf[bytes_read] = '\0';
            // printf("DEBUG: Found newline, breaking\n");
            break;
        }
        bytes_read++;
    }

    // printf("DEBUG: Received full buffer: '%s' (length: %zd)\n", buf, bytes_read);

    const char *start = skip_whitespace(buf);
    char *end = buf + strlen(buf) - 1;
    while (end >= buf && is_whitespace(end)) {
        *end = '\0';
        end--;
    }

    msg->timestamp = time(NULL);
    strncpy(msg->content, start, MAX_MSG_LENGTH - 1);
    strncpy(msg->sender, state->user, MAX_TOKEN_LENGTH);

    // printf("DEBUG: Processed message content: '%s'\n", msg->content);

    return 1;
}int api_send(struct api_state *state, const struct api_msg *msg) {
    assert(state && msg);

    // printf("DEBUG: api_send called\n");
    // printf("DEBUG: msg->type = %d\n", msg->type);
    // printf("DEBUG: msg->content = '%s'\n", msg->content);
    // printf("DEBUG: msg->sender = '%s'\n", msg->sender);

    char buf[MAX_MSG_LENGTH + 128];
    int n;

    switch (msg->type) {
        case MSG_PUBLIC:
            // printf("DEBUG: Using MSG_PUBLIC case\n");
            n = snprintf(buf, sizeof(buf), "PUBLIC|%ld|%s|%s\n",
                         (long) msg->timestamp, msg->sender, msg->content);
            // printf("DEBUG: Formatted buffer: '%s'\n", buf);
            break;
        case MSG_PRIVATE:
            // printf("DEBUG: Using MSG_PRIVATE case\n");
            n = snprintf(buf, sizeof(buf), "PRIVATE|%ld|%s|%s|%s\n",
                         (long) msg->timestamp, msg->sender, msg->recipient, msg->content);
            break;
        case MSG_SYSTEM:
            // printf("DEBUG: Using MSG_SYSTEM case\n");
            n = snprintf(buf, sizeof(buf), "SYSTEM|%ld|NULL|%s\n",
                         (long) msg->timestamp, msg->content);
            break;
        case MSG_SYSTEM_SIGNED:
            // printf("DEBUG: Using MSG_SYSTEM_SIGNED case\n");
            n = snprintf(buf, sizeof(buf), "SYSTEM_SIGNED|%ld|NULL|%s\n",
                         (long) msg->timestamp, msg->content);
            break;
        default:
            // printf("DEBUG: Hit default case - msg->type = %d\n", msg->type);
            return -1;
    }
    
    // printf("DEBUG: About to send %d bytes\n", n);
    
    if (state->ssl) {
        // printf("api send: using SSL\n");
        int bytes_written = ssl_block_write(state->ssl, state->fd, buf, n);
        // printf("DEBUG: ssl_block_write returned %d (expected %d)\n", bytes_written, n);
        return bytes_written == n ? 0 : -1;
    } else {
        // printf("api send: not ssl, using normal\n");
        int bytes_written = write(state->fd, buf, n);
        // printf("DEBUG: write returned %d (expected %d)\n", bytes_written, n);
        return bytes_written == n ? 0 : -1;
    }
}
/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {
    assert(msg);

    /* TODO clean up state allocated for msg */
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {
    assert(state);
    if (state->ssl) {
            SSL_shutdown(state->ssl);
            SSL_free(state->ssl);
            state->ssl = NULL;
        }
    if (state->ctx) {
        SSL_CTX_free(state->ctx);
        state->ctx = NULL;
    }
    if (state->fd >= 0) {
        close(state->fd);
        state->fd = -1;
    }
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {
    assert(state);

    memset(state, 0, sizeof(*state));
    state->fd = fd;
    state->authenticated = false;
}

//FROM EXAMPLE
int ssl_block_if_needed(SSL *ssl, int fd, int r) {
  int err, want_read;
  fd_set readfds, writefds;

//   printf("DEBUG: ssl_block_if_needed called with r=%d\n", r);

  /* do we need more input/output? */
  err = SSL_get_error(ssl, r);
//   printf("DEBUG: SSL_get_error returned %d\n", err);
  
  switch (err) {
  case SSL_ERROR_ZERO_RETURN: 
    // printf("DEBUG: SSL_ERROR_ZERO_RETURN\n");
    return 0;
  case SSL_ERROR_WANT_READ:   
    // printf("DEBUG: SSL_ERROR_WANT_READ\n");
    want_read = 1; 
    break;
  case SSL_ERROR_WANT_WRITE:  
    // printf("DEBUG: SSL_ERROR_WANT_WRITE\n");
    want_read = 0; 
    break;
  default:
    // printf("DEBUG: SSL error %d\n", err);
    if (err == SSL_ERROR_SYSCALL && !ERR_peek_error()) {
        // printf("DEBUG: SSL_ERROR_SYSCALL with no error, returning 0\n");
        return 0;
    }

    fprintf(stderr, "SSL call failed, err=%d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* wait for more input/output */
//   printf("DEBUG: Setting up select for %s\n", want_read ? "read" : "write");
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_SET(fd, want_read ? &readfds : &writefds);
  
//   printf("DEBUG: Calling select on fd %d...\n", fd);
  r = select(fd+1, &readfds, &writefds, NULL, NULL);
//   printf("DEBUG: select returned %d\n", r);
  
  if (r != 1) {
    //   printf("DEBUG: select failed or timeout, returning -1\n");
      return -1;
  }

//   printf("DEBUG: select successful, returning 1\n");
  return 1;
}//FROM EXAMPLE
// In api.c, modify ssl_block_read to add debug:
// In api.c, modify ssl_block_read to be truly non-blocking:
int ssl_block_read(SSL *ssl, int fd, void *buf, int len) {
  char *p = buf, *pend = p + len;
  int r;

//   printf("DEBUG: ssl_block_read called, trying to read %d bytes\n", len);

  /* attempt to read */
//   printf("DEBUG: Calling SSL_read...\n");
  r = SSL_read(ssl, p, pend - p);
//   printf("DEBUG: SSL_read returned %d\n", r);
  
  if (r > 0) {
    // printf("DEBUG: Read %d bytes successfully\n", r);
    return r;
  }

  /* check what kind of error we got */
  int err = SSL_get_error(ssl, r);
//   printf("DEBUG: SSL_get_error returned %d\n", err);
  
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
    // printf("DEBUG: SSL wants more data, returning 0 (would block)\n");
    errno = EAGAIN; // Set errno to indicate "would block"
    return 0;
  }
  
  if (err == SSL_ERROR_ZERO_RETURN) {
    // printf("DEBUG: SSL connection closed\n");
    return 0;
  }
  
//   printf("DEBUG: SSL error %d, returning -1\n", err);
  return -1;
}int ssl_block_write(SSL *ssl, int fd, const void *buf, int len) {
  const char *p = buf, *pend = p + len;
  int r;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *   >0: number of bytes written
   */

  /* we may need to do multiple writes in case one returns prematurely */
  while (p < pend) {
    /* attempt to write */
    r = SSL_write(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }
    
    /* do we need to block? */
    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }

  return p - (char *) buf;
}
//FROM EXAMPLE
int ssl_has_data(SSL *ssl) {
  char byte;
  int r;

  /* return value:
   *   0: nothing available
   *   1: data, end-of-file, or error available
   */

  /* verify that at least one byte of user data is available */
  r = SSL_peek(ssl, &byte, sizeof(byte));
  return r > 0 || SSL_get_error(ssl, r) != SSL_ERROR_WANT_READ;
}
