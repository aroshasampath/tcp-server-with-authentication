#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <openssl/sha.h>

#define PORT 50938
#define SID "1039"
#define REGNO "IT24103938"

#define LOG_FILE "server_24103938.log"
#define USER_DB_FILE "users_24103938.txt"

#define BUFFER_SIZE 8192
#define MAX_PAYLOAD 4096

#define TOKEN_EXPIRY 300
#define RATE_LIMIT_WINDOW 10
#define RATE_LIMIT_MAX 10
#define LOGIN_FAIL_LIMIT 3
#define LOGIN_LOCK_SECONDS 60

typedef struct {
    int logged_in;
    char username[64];
    char token[65];
    time_t last_activity;
    int req_count;
    time_t req_window_start;
    int failed_login_count;
    time_t lock_until;
} SessionState;

/* ---------- Utility ---------- */

static void safe_strcpy(char *dst, size_t size, const char *src) {
    if (size == 0) return;
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

static void current_timestamp(char *out, size_t out_size) {
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    if (!tm_now) {
        safe_strcpy(out, out_size, "UNKNOWN_TIME");
        return;
    }
    strftime(out, out_size, "%Y-%m-%d %H:%M:%S", tm_now);
}

static void print_banner(void) {
    printf("============================================================\n");
    printf("IE2102 Secure TCP Server\n");
    printf("REGNO : %s\n", REGNO);
    printf("PORT  : %d\n", PORT);
    printf("SID   : %s\n", SID);
    printf("PID   : %d\n", getpid());
    printf("LOG   : %s\n", LOG_FILE);
    printf("DB    : %s\n", USER_DB_FILE);
    printf("------------------------------------------------------------\n");
    printf("Commands: REGISTER LOGIN LOGOUT WHOAMI ECHO HELP QUIT\n");
    printf("============================================================\n");
    fflush(stdout);
}

static void reap_children(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void send_response(int fd, const char *status, int code, const char *msg) {
    char out[2048];
    snprintf(out, sizeof(out), "%s %d SID:%s %s\n", status, code, SID, msg);
    send(fd, out, strlen(out), 0);
}

/* ---------- Logging ---------- */

static void sanitize_command_for_log(const char *payload, char *out, size_t out_size) {
    char cmd[32] = {0};
    char a1[128] = {0};
    char a2[1024] = {0};

    if (sscanf(payload, "%31s", cmd) != 1) {
        safe_strcpy(out, out_size, "INVALID");
        return;
    }

    if (strcmp(cmd, "REGISTER") == 0 || strcmp(cmd, "LOGIN") == 0) {
        if (sscanf(payload, "%31s %127s %1023s", cmd, a1, a2) == 3) {
            snprintf(out, out_size, "%s %s ****", cmd, a1);
        } else {
            safe_strcpy(out, out_size, cmd);
        }
    } else if (strcmp(cmd, "LOGOUT") == 0 || strcmp(cmd, "WHOAMI") == 0) {
        safe_strcpy(out, out_size, cmd);
    } else if (strcmp(cmd, "ECHO") == 0) {
        char token[128] = {0};
        char msg[512] = {0};
        if (sscanf(payload, "%31s %127s %[^\n]", cmd, token, msg) >= 2) {
            snprintf(out, out_size, "ECHO <token> %.120s", msg);
        } else {
            safe_strcpy(out, out_size, "ECHO");
        }
    } else {
        snprintf(out, out_size, "%.180s", payload);
    }
}

static void write_log_line(const char *ip, int port,
                           const char *username,
                           const char *payload,
                           const char *result) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        return;
    }

    char ts[64];
    char safe_cmd[256];

    current_timestamp(ts, sizeof(ts));
    sanitize_command_for_log(payload, safe_cmd, sizeof(safe_cmd));

    fprintf(fp,
            "[%s] IP:%s:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            ts,
            ip,
            port,
            getpid(),
            (username && username[0]) ? username : "-",
            safe_cmd,
            result);

    fclose(fp);
}

/* ---------- Security / Auth ---------- */

static int is_valid_username(const char *username) {
    size_t len = strlen(username);

    if (len < 3 || len > 32) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        if (!(isalnum((unsigned char)username[i]) || username[i] == '_')) {
            return 0;
        }
    }
    return 1;
}

static int is_valid_password(const char *password) {
    size_t len = strlen(password);
    return (len >= 4 && len <= 64);
}

static void generate_random_string(char *out, size_t len) {
    static const char chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t chars_len = strlen(chars);

    if (len == 0) return;

    for (size_t i = 0; i < len - 1; i++) {
        out[i] = chars[rand() % chars_len];
    }
    out[len - 1] = '\0';
}

static void sha256_hex(const char *input, char *output_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char *)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_hex + (i * 2), "%02x", hash[i]);
    }
    output_hex[64] = '\0';
}

static void salted_hash_password(const char *password, const char *salt, char *out_hash) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", salt, password);
    sha256_hex(combined, out_hash);
}

static int register_user(const char *username, const char *password) {
    if (!is_valid_username(username)) {
        return -2;
    }

    if (!is_valid_password(password)) {
        return -3;
    }

    FILE *fp = fopen(USER_DB_FILE, "a+");
    if (!fp) {
        return -4;
    }

    char file_user[64], file_salt[64], file_hash[128];

    rewind(fp);
    while (fscanf(fp, "%63s %63s %127s", file_user, file_salt, file_hash) == 3) {
        if (strcmp(file_user, username) == 0) {
            fclose(fp);
            return -1;
        }
    }

    char salt[17];
    char hash[65];
    generate_random_string(salt, sizeof(salt));
    salted_hash_password(password, salt, hash);

    fprintf(fp, "%s %s %s\n", username, salt, hash);
    fclose(fp);
    return 0;
}

static int verify_user(const char *username, const char *password) {
    if (!is_valid_username(username) || !is_valid_password(password)) {
        return 0;
    }

    FILE *fp = fopen(USER_DB_FILE, "r");
    if (!fp) {
        return 0;
    }

    char file_user[64], salt[64], stored_hash[128];
    char computed_hash[65];

    while (fscanf(fp, "%63s %63s %127s", file_user, salt, stored_hash) == 3) {
        if (strcmp(file_user, username) == 0) {
            salted_hash_password(password, salt, computed_hash);
            fclose(fp);
            return strcmp(computed_hash, stored_hash) == 0;
        }
    }

    fclose(fp);
    return 0;
}

/* ---------- Session ---------- */

static void init_session(SessionState *s) {
    memset(s, 0, sizeof(*s));
    safe_strcpy(s->username, sizeof(s->username), "-");
}

static int rate_limit_ok(SessionState *s) {
    time_t now = time(NULL);

    if (s->req_window_start == 0 || (now - s->req_window_start) > RATE_LIMIT_WINDOW) {
        s->req_window_start = now;
        s->req_count = 1;
        return 1;
    }

    if (s->req_count >= RATE_LIMIT_MAX) {
        return 0;
    }

    s->req_count++;
    return 1;
}

static int token_valid(SessionState *s, const char *token) {
    if (!s->logged_in) {
        return 0;
    }

    if (strcmp(s->token, token) != 0) {
        return 0;
    }

    time_t now = time(NULL);

    if ((now - s->last_activity) > TOKEN_EXPIRY) {
        s->logged_in = 0;
        safe_strcpy(s->username, sizeof(s->username), "-");
        s->token[0] = '\0';
        return 0;
    }

    s->last_activity = now;
    return 1;
}

/* ---------- Command Processing ---------- */

static void process_command(int fd, const char *payload,
                            const char *ip, int port,
                            SessionState *state) {
    char cmd[32] = {0};
    char a1[128] = {0};
    char a2[1024] = {0};
    char result[256] = {0};

    if (!rate_limit_ok(state)) {
        snprintf(result, sizeof(result), "ERR 429 RATE_LIMIT_EXCEEDED");
        send_response(fd, "ERR", 429, "Rate limit exceeded. Please slow down.");
        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (sscanf(payload, "%31s", cmd) != 1) {
        snprintf(result, sizeof(result), "ERR 400 INVALID_COMMAND");
        send_response(fd, "ERR", 400, "Invalid command.");
        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (strcmp(cmd, "REGISTER") == 0) {
        if (sscanf(payload, "%31s %127s %1023s", cmd, a1, a2) != 3) {
            snprintf(result, sizeof(result), "ERR 400 REGISTER_USAGE");
            send_response(fd, "ERR", 400, "Usage: REGISTER <username> <password>");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        int r = register_user(a1, a2);

        if (r == 0) {
            snprintf(result, sizeof(result), "OK 201 REGISTER_SUCCESS");
            char msg[256];
            snprintf(msg, sizeof(msg), "User '%s' registered successfully.", a1);
            send_response(fd, "OK", 201, msg);
        } else if (r == -1) {
            snprintf(result, sizeof(result), "ERR 409 USER_EXISTS");
            send_response(fd, "ERR", 409, "Username already exists.");
        } else if (r == -2) {
            snprintf(result, sizeof(result), "ERR 400 INVALID_USERNAME");
            send_response(fd, "ERR", 400, "Invalid username. Use letters, numbers, underscore only.");
        } else if (r == -3) {
            snprintf(result, sizeof(result), "ERR 400 INVALID_PASSWORD");
            send_response(fd, "ERR", 400, "Invalid password. Use 4 to 64 characters.");
        } else {
            snprintf(result, sizeof(result), "ERR 500 REGISTER_FAILED");
            send_response(fd, "ERR", 500, "Registration failed.");
        }

        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (strcmp(cmd, "LOGIN") == 0) {
        if (sscanf(payload, "%31s %127s %1023s", cmd, a1, a2) != 3) {
            snprintf(result, sizeof(result), "ERR 400 LOGIN_USAGE");
            send_response(fd, "ERR", 400, "Usage: LOGIN <username> <password>");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        time_t now = time(NULL);

        if (state->lock_until > now) {
            snprintf(result, sizeof(result), "ERR 403 ACCOUNT_LOCKED");
            send_response(fd, "ERR", 403, "Account locked. Too many failed attempts. Reconnect later.");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        if (verify_user(a1, a2)) {
            state->logged_in = 1;
            safe_strcpy(state->username, sizeof(state->username), a1);
            generate_random_string(state->token, sizeof(state->token));
            state->last_activity = time(NULL);
            state->failed_login_count = 0;
            state->lock_until = 0;

            snprintf(result, sizeof(result), "OK 200 LOGIN_SUCCESS");
            char msg[256];
            snprintf(msg, sizeof(msg), "Login successful. TOKEN:%s", state->token);
            send_response(fd, "OK", 200, msg);
            write_log_line(ip, port, state->username, payload, result);
        } else {
            state->failed_login_count++;

            if (state->failed_login_count >= LOGIN_FAIL_LIMIT) {
                state->lock_until = time(NULL) + LOGIN_LOCK_SECONDS;
                snprintf(result, sizeof(result), "ERR 403 ACCOUNT_LOCKED");
                send_response(fd, "ERR", 403, "Too many failed attempts. Account LOCKED.");
            } else {
                int left = LOGIN_FAIL_LIMIT - state->failed_login_count;
                snprintf(result, sizeof(result), "ERR 401 LOGIN_FAILED");
                char msg[256];
                snprintf(msg, sizeof(msg), "Invalid credentials. %d attempt(s) left.", left);
                send_response(fd, "ERR", 401, msg);
            }

            write_log_line(ip, port, state->username, payload, result);
        }
        return;
    }

    if (strcmp(cmd, "LOGOUT") == 0) {
        if (sscanf(payload, "%31s %127s", cmd, a1) != 2) {
            snprintf(result, sizeof(result), "ERR 400 LOGOUT_USAGE");
            send_response(fd, "ERR", 400, "Usage: LOGOUT <token>");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        if (!token_valid(state, a1)) {
            snprintf(result, sizeof(result), "ERR 401 INVALID_TOKEN");
            send_response(fd, "ERR", 401, "Invalid or expired token.");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        snprintf(result, sizeof(result), "OK 200 LOGOUT_SUCCESS");
        send_response(fd, "OK", 200, "Logged out successfully.");
        write_log_line(ip, port, state->username, payload, result);

        state->logged_in = 0;
        safe_strcpy(state->username, sizeof(state->username), "-");
        state->token[0] = '\0';
        return;
    }

    if (strcmp(cmd, "WHOAMI") == 0) {
        if (sscanf(payload, "%31s %127s", cmd, a1) != 2) {
            snprintf(result, sizeof(result), "ERR 400 WHOAMI_USAGE");
            send_response(fd, "ERR", 400, "Usage: WHOAMI <token>");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        if (!token_valid(state, a1)) {
            snprintf(result, sizeof(result), "ERR 401 INVALID_TOKEN");
            send_response(fd, "ERR", 401, "Invalid or expired token.");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        snprintf(result, sizeof(result), "OK 200 WHOAMI_SUCCESS");
        char msg[256];
        snprintf(msg, sizeof(msg), "You are logged in as '%s'.", state->username);
        send_response(fd, "OK", 200, msg);
        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (strcmp(cmd, "ECHO") == 0) {
        char token[128] = {0};
        char message[1024] = {0};

        if (sscanf(payload, "%31s %127s %[^\n]", cmd, token, message) < 3) {
            snprintf(result, sizeof(result), "ERR 400 ECHO_USAGE");
            send_response(fd, "ERR", 400, "Usage: ECHO <token> <message>");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        if (!token_valid(state, token)) {
            snprintf(result, sizeof(result), "ERR 401 INVALID_TOKEN");
            send_response(fd, "ERR", 401, "Invalid or expired token.");
            write_log_line(ip, port, state->username, payload, result);
            return;
        }

        snprintf(result, sizeof(result), "OK 200 ECHO_SUCCESS");
        char msg[1400];
        snprintf(msg, sizeof(msg), "ECHO: %.1200s", message);
        send_response(fd, "OK", 200, msg);
        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (strcmp(cmd, "HELP") == 0) {
        snprintf(result, sizeof(result), "OK 200 HELP");
        send_response(fd, "OK", 200, "Commands: REGISTER LOGIN LOGOUT WHOAMI ECHO HELP QUIT");
        write_log_line(ip, port, state->username, payload, result);
        return;
    }

    if (strcmp(cmd, "QUIT") == 0) {
        snprintf(result, sizeof(result), "OK 200 QUIT");
        send_response(fd, "OK", 200, "Goodbye.");
        write_log_line(ip, port, state->username, payload, result);
        shutdown(fd, SHUT_RDWR);
        return;
    }

    snprintf(result, sizeof(result), "ERR 400 UNKNOWN_COMMAND");
    send_response(fd, "ERR", 400, "Unknown command.");
    write_log_line(ip, port, state->username, payload, result);
}

/* ---------- Client Handler ---------- */

static void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char ip[64];
    safe_strcpy(ip, sizeof(ip), inet_ntoa(client_addr.sin_addr));
    int port = ntohs(client_addr.sin_port);

    printf("[SERVER] Connection from %s:%d\n", ip, port);
    printf("[CHILD %d] Client %s:%d connected\n", getpid(), ip, port);
    fflush(stdout);

    SessionState state;
    init_session(&state);

    char buffer[BUFFER_SIZE];
    int buffer_len = 0;

    while (1) {
        char temp[2048];
        ssize_t n = recv(client_fd, temp, sizeof(temp), 0);

        if (n < 0) {
            perror("recv");
            break;
        }

        if (n == 0) {
            printf("[CHILD %d] Session ended. Exiting.\n", getpid());
            fflush(stdout);
            break;
        }

        if (buffer_len + (int)n >= BUFFER_SIZE) {
            send_response(client_fd, "ERR", 413, "Buffer overflow rejected.");
            write_log_line(ip, port, state.username, "BUFFER_OVERFLOW", "ERR 413 BUFFER_OVERFLOW");
            break;
        }

        memcpy(buffer + buffer_len, temp, (size_t)n);
        buffer_len += (int)n;

        while (1) {
            char *newline = memchr(buffer, '\n', (size_t)buffer_len);
            if (!newline) {
                break;
            }

            int header_len = (int)(newline - buffer);

            if (header_len <= 0 || header_len >= 100) {
                send_response(client_fd, "ERR", 400, "Invalid header.");
                write_log_line(ip, port, state.username, "INVALID_HEADER", "ERR 400 INVALID_HEADER");
                buffer_len = 0;
                break;
            }

            char header[100];
            memcpy(header, buffer, (size_t)header_len);
            header[header_len] = '\0';

            if (strncmp(header, "LEN:", 4) != 0) {
                send_response(client_fd, "ERR", 400, "Invalid length header.");
                write_log_line(ip, port, state.username, "INVALID_LENGTH_HEADER", "ERR 400 INVALID_LENGTH_HEADER");
                buffer_len = 0;
                break;
            }

            char *endptr = NULL;
            long payload_len = strtol(header + 4, &endptr, 10);

            if (*(header + 4) == '\0' || *endptr != '\0' || payload_len < 0) {
                send_response(client_fd, "ERR", 400, "Invalid length.");
                write_log_line(ip, port, state.username, header, "ERR 400 INVALID_LENGTH");
                buffer_len = 0;
                break;
            }

            if (payload_len > MAX_PAYLOAD) {
                send_response(client_fd, "ERR", 413, "Payload too large.");
                write_log_line(ip, port, state.username, header, "ERR 413 PAYLOAD_TOO_LARGE");
                buffer_len = 0;
                break;
            }

            int total_needed = header_len + 1 + (int)payload_len;
            if (buffer_len < total_needed) {
                break;
            }

            char payload[MAX_PAYLOAD + 1];
            memcpy(payload, buffer + header_len + 1, (size_t)payload_len);
            payload[payload_len] = '\0';

            printf("[CHILD %d] RX[%zu]: %.120s\n", getpid(), strlen(payload), payload);
            fflush(stdout);

            process_command(client_fd, payload, ip, port, &state);

            memmove(buffer, buffer + total_needed, (size_t)(buffer_len - total_needed));
            buffer_len -= total_needed;
        }
    }

    close(client_fd);
}

/* ---------- Main ---------- */

int main(void) {
    srand((unsigned int)(time(NULL) ^ getpid()));
    signal(SIGCHLD, reap_children);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    print_banner();

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            close(server_fd);
            handle_client(client_fd, client_addr);
            exit(0);
        } else {
            printf("[SERVER] Forked PID:%d for %s:%d\n",
                   pid,
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));
            fflush(stdout);
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
