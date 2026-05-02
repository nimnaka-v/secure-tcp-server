#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>

#define PORT 50980
#define BUFFER_SIZE 8192
#define MAX_PAYLOAD 4096
#define SID "1029"
#define LOG_FILE "server_IT24102980.log"

int failed_login_attempts = 0;
time_t lockout_until = 0;

int request_count = 0;
time_t rate_window_start = 0;

char current_user[100] = "";
char current_token[100] = "";
int is_logged_in = 0;

// new update for the lab tes- store the time when the server starts

time_t server_start_time = 0;

void send_response(int client_fd, const char *status, int code, const char *message) {
    char response[512];
    snprintf(response, sizeof(response), "%s %d SID:%s %s\n", status, code, SID, message);
    send(client_fd, response, strlen(response), 0);
}

int parse_length_header(const char *header) {
    if (strncmp(header, "LEN:", 4) != 0) {
        return -1;
    }

    const char *num_part = header + 4;
    if (*num_part == '\0') {
        return -1;
    }

    for (int i = 0; num_part[i] != '\0'; i++) {
        if (!isdigit((unsigned char)num_part[i])) {
            return -1;
        }
    }

    return atoi(num_part);
}


void simple_hash(const char *input, char *output) {
    unsigned long hash = 5381;
    int c;

    while ((c = *input++))
        hash = ((hash << 5) + hash) + c;

    sprintf(output, "%lu", hash);
}

int user_exists(const char *username) {
    FILE *fp = fopen("data/users.txt", "r");
    if (!fp) return 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char stored_user[100];
        sscanf(line, "%[^:]", stored_user);

        if (strcmp(stored_user, username) == 0) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

int register_user(const char *username, const char *password) {
    if (user_exists(username)) return 0;

    FILE *fp = fopen("data/users.txt", "a");
    if (!fp) return 0;

    char hash[128];
    simple_hash(password, hash);

    fprintf(fp, "%s:%s\n", username, hash);
    fclose(fp);

    return 1;
}

int verify_user(const char *username, const char *password) {
    FILE *fp = fopen("data/users.txt", "r");
    if (!fp) return 0;

    char line[256];
    char hash[128];
    simple_hash(password, hash);

    while (fgets(line, sizeof(line), fp)) {
        char stored_user[100];
        char stored_hash[128];

        if (sscanf(line, "%99[^:]:%127s", stored_user, stored_hash) == 2) {
            if (strcmp(stored_user, username) == 0 &&
                strcmp(stored_hash, hash) == 0) {
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}




void generate_token(char *token, size_t size) {
    snprintf(token, size, "TK%ld%d", (long)time(NULL), rand() % 10000);
}

int is_token_valid(const char *token) {
    if (!is_logged_in) return 0;
    return strcmp(token, current_token) == 0;
}

int is_valid_username(const char *username) {
    int len = strlen(username);

    if (len < 3 || len > 20) return 0;

    for (int i = 0; username[i] != '\0'; i++) {
        if (!(isalnum((unsigned char)username[i]) || username[i] == '_')) {
            return 0;
        }
    }

    return 1;
}

void log_event(const char *client_ip, int client_port, pid_t pid,
               const char *username, const char *command, const char *result) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(fp, "[%s] %s:%d PID:%d USER:%s CMD:%s RESULT:%s\n",
            timestamp,
            client_ip,
            client_port,
            pid,
            (username && username[0] != '\0') ? username : "-",
            command ? command : "-",
            result ? result : "-");

    fclose(fp);
}

//rate limiting

int is_rate_limited(void) {
    time_t now = time(NULL);

    if (rate_window_start == 0 || (now - rate_window_start) >= 10) {
        rate_window_start = now;
        request_count = 0;
    }

    request_count++;

    if (request_count > 5) {
        return 1;
    }

    return 0;
}

//process payload (tmr rest -- loic build and all)


void process_payload(int client_fd, const char *payload) {
    char command[50] = {0};
    char arg1[100] = {0};
    char arg2[100] = {0};

    int count = sscanf(payload, "%49s %99s %99s", command, arg1, arg2); //splittiing Login user pass

    if (is_rate_limited()) {
        send_response(client_fd, "ERR", 429, "Rate limit exceeded");
        return;
    }

    // REGISTER part

        if (strcmp(command, "REGISTER") == 0) {
        if (count != 3) {
            send_response(client_fd, "ERR", 400, "Usage: REGISTER user pass");
            return;
        }

        if (!is_valid_username(arg1)) {
            send_response(client_fd, "ERR", 400, "Invalid username");
            return;
        }

        if (register_user(arg1, arg2)) {
            send_response(client_fd, "OK", 200, "User registered");
        } else {
            send_response(client_fd, "ERR", 409, "User already exists");
        }
    }

	// LOGIN part
	
        else if (strcmp(command, "LOGIN") == 0) {
        if (count != 3) {
            send_response(client_fd, "ERR", 400, "Usage: LOGIN user pass");
            return;
        }

        time_t now = time(NULL);
        if (lockout_until > now) {
            send_response(client_fd, "ERR", 423, "Account temporarily locked");
            return;
        }

        if (verify_user(arg1, arg2)) {
            strcpy(current_user, arg1);
            generate_token(current_token, sizeof(current_token));
            is_logged_in = 1;
            failed_login_attempts = 0;
            lockout_until = 0;

            char msg[200];
            snprintf(msg, sizeof(msg), "Login successful TOKEN:%s", current_token);
            send_response(client_fd, "OK", 200, msg);
	    log_event("127.0.0.1", 0, getpid(), arg1, "LOGIN", "SUCCESS");

        } else {
            failed_login_attempts++;

            if (failed_login_attempts >= 3) {
                lockout_until = now + 30;
                send_response(client_fd, "ERR", 423, "Too many failed logins. Locked for 30 seconds");
		log_event("127.0.0.1", 0, getpid(), arg1, "LOGIN", "FAILED");

            } else {
                send_response(client_fd, "ERR", 401, "Invalid username or password");
		log_event("127.0.0.1", 0, getpid(), arg1, "LOGIN", "FAILED");
            }
        }
    }

    // LOGOUT part

   	else if (strcmp(command, "LOGOUT") == 0) {
    		if (!is_logged_in) {
        		send_response(client_fd, "ERR", 403, "Not logged in");
        		return;
    		}

    		char user_copy[100];
    		strcpy(user_copy, current_user);

    		log_event("127.0.0.1", 0, getpid(), user_copy, "LOGOUT", "SUCCESS");

    		is_logged_in = 0;
    		current_user[0] = '\0';
    		current_token[0] = '\0';

    		send_response(client_fd, "OK", 200, "Logged out");
	}   

        // Added for lab test: UPTIME command to return how long the server has been running

        else if (strcmp(command, "UPTIME") == 0) {

        	if (count != 1) {

            		send_response(client_fd, "ERR", 400, "Usage: UPTIME");

            		return;

        	}



        	time_t now = time(NULL);

        	long uptime_seconds = (long)(now - server_start_time);



        	char msg[200];

        	snprintf(msg, sizeof(msg), "Server uptime: %ld seconds", uptime_seconds);

        	send_response(client_fd, "OK", 200, msg);

    		}

	// PROTECTED COMMAND (PING)
	
    else if (strcmp(command, "PING") == 0) {
        if (count != 2 || !is_token_valid(arg1)) {
            send_response(client_fd, "ERR", 403, "Invalid or missing token");
            return;
        }

        send_response(client_fd, "OK", 200, "PONG");
    }

    // PROTECTED COMMAND (HELLO)

    else if (strcmp(command, "HELLO") == 0) {
        if (count != 2 || !is_token_valid(arg1)) {
            send_response(client_fd, "ERR", 403, "Invalid or missing token");
            return;
        }

        send_response(client_fd, "OK", 200, "Hello received");
    }

    // DEFAULT

    else {
        send_response(client_fd, "ERR", 400, "Unknown command");
    }
}

void handle_sigchld(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}



int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    srand(time(NULL));

       // Added for lab test -  record the server start time once when the server begins to sttrts

    server_start_time = time(NULL);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Server running on port %d\n", PORT);
    printf("SID:%s\n", SID);

    // SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    //  MAIN ACCEPT LOOP
    while (1) {

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        printf("Client connected: %s:%d\n",
               inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            // CHILD PROCESS

            close(server_fd);

            printf("Child process %d handling client\n", getpid());

            char recv_buffer[BUFFER_SIZE];
            int buffer_used = 0;

            while (1) {
                ssize_t bytes_received = recv(client_fd,
                                              recv_buffer + buffer_used,
                                              sizeof(recv_buffer) - buffer_used - 1,
                                              0);

                if (bytes_received < 0) {
                    perror("recv");
                    break;
                }

                if (bytes_received == 0) {
                    printf("Client disconnected (PID %d)\n", getpid());
                    break;
                }

                buffer_used += bytes_received;
                recv_buffer[buffer_used] = '\0';

                while (1) {
                    char *newline_ptr = memchr(recv_buffer, '\n', buffer_used);
                    if (newline_ptr == NULL) {
                        break;
                    }

                    int header_len = newline_ptr - recv_buffer;
                    char header[128];

                    if (header_len <= 0 || header_len >= (int)sizeof(header)) {
                        send_response(client_fd, "ERR", 400, "Invalid header");
                        buffer_used = 0;
                        break;
                    }

                    memcpy(header, recv_buffer, header_len);
                    header[header_len] = '\0';

                    int payload_len = parse_length_header(header);
                    if (payload_len < 0) {
                        send_response(client_fd, "ERR", 400, "Invalid length");
                        buffer_used = 0;
                        break;
                    }

                    if (payload_len > MAX_PAYLOAD) {
                        send_response(client_fd, "ERR", 413, "Payload too large");
                        buffer_used = 0;
                        break;
                    }

                    int total_needed = header_len + 1 + payload_len;
                    if (buffer_used < total_needed) {
                        break;
                    }

                    char payload[MAX_PAYLOAD + 1];
                    memcpy(payload, recv_buffer + header_len + 1, payload_len);
                    payload[payload_len] = '\0';

                    printf("PID %d -> Payload: %s\n", getpid(), payload);

		    log_event(inet_ntoa(client_addr.sin_addr),
          		ntohs(client_addr.sin_port),
          		getpid(),
          		current_user,
          		payload,
          		"RECEIVED");

                    process_payload(client_fd, payload);

                    memmove(recv_buffer,
                            recv_buffer + total_needed,
                            buffer_used - total_needed);
                    buffer_used -= total_needed;
                    recv_buffer[buffer_used] = '\0';
                }
            }

            close(client_fd);
            printf("Child process %d finished\n", getpid());
            exit(0);
        }

        else {
            // PARENT PROCESS
            close(client_fd);
        }
    }

    close(server_fd);
    return 0;
}
