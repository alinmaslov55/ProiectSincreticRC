#include "../common/crypto.h"
#include "../common/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>

// --- Configuration ---
#define SERVER_IP "127.0.0.1"
#define PORT 8080

// --- UI Macros ---
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CLEAR   "\033[H\033[J"

// --- Global Log Pointer ---
FILE *client_log = NULL;

// --- Helper Functions ---
void log_state(const char *message) {
    if (client_log) {
        fprintf(client_log, "[%ld] %s\n", (long)time(NULL), message);
        fflush(client_log);
    }
}

bool perform_login(SSL *ssl) {
    PacketHeader header = {REQ_LOGIN, sizeof(LoginPayload)};
    LoginPayload login;
    int attempts = 0;
    const int MAX_ATTEMPTS = 3;

    while (attempts < MAX_ATTEMPTS) {
        memset(&login, 0, sizeof(login));

        printf(BLUE BOLD "\n--- OmniTest Secure Login (Attempt %d/%d) ---\n" RESET, attempts + 1, MAX_ATTEMPTS);
        printf("Enter Student ID: ");
        fgets(login.student_id, sizeof(login.student_id), stdin);
        login.student_id[strcspn(login.student_id, "\n")] = 0;

        printf("Enter Password: ");
        fgets(login.password_hash, sizeof(login.password_hash), stdin);
        login.password_hash[strcspn(login.password_hash, "\n")] = 0;

        // Log and Send
        if (client_log) fprintf(client_log, "[TX] Sent: %s (Attempt %d)\n", p_name(header.type), attempts + 1);
        SSL_write(ssl, &header, sizeof(header));
        SSL_write(ssl, &login, sizeof(login));

        // Wait for result
        PacketHeader res_header;
        int bytes = SSL_read(ssl, &res_header, sizeof(res_header));
        
        if (bytes == sizeof(PacketHeader)) {
            if (client_log) fprintf(client_log, "[RX] Received: %s\n", p_name(res_header.type));
            
            if (res_header.type == RES_LOGIN_SUCCESS) {
                return true;
            } else {
                printf(RED "Invalid credentials. Please try again.\n" RESET);
            }
        }
        attempts++;
    }

    log_state("Maximum login attempts reached.");
    return false;
}

void start_exam_session(SSL *ssl) {
    log_state("Initiating Exam Session");
    PacketHeader start_req = {REQ_EXAM_START, 0};
    SSL_write(ssl, &start_req, sizeof(start_req));

    int server_fd = SSL_get_fd(ssl);
    int stdin_fd = fileno(stdin);
    int max_fd = (server_fd > stdin_fd) ? server_fd : stdin_fd;

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        FD_SET(stdin_fd, &read_fds);

        // Multiplexing between Server and Keyboard
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            log_state("Select error occurred");
            break;
        }

        // 1. Data from Server
        if (FD_ISSET(server_fd, &read_fds)) {
            PacketHeader msg_header;
            int bytes = SSL_read(ssl, &msg_header, sizeof(PacketHeader));
            if (bytes <= 0) {
                log_state("Server disconnected abruptly");
                break;
            }

            if (msg_header.type == MSG_EXAM_QUESTION) {
                ExamQuestionPayload q;
                SSL_read(ssl, &q, sizeof(q));
                log_state("Received Question packet");

                printf(CLEAR BLUE "====================================================\n" RESET);
                printf(BOLD " OMNITEST SECURE CAMPUS - EXAM IN PROGRESS\n" RESET);
                const char* t_color = (q.time_remaining < 15) ? RED : GREEN;
                printf(" Time Remaining: %s%d seconds%s\n", t_color, q.time_remaining, RESET);
                printf(BOLD "\n Q%d: %s\n" RESET, q.question_id, q.question_text);
                for (int i = 0; i < 4; i++) printf("  [%d] %s\n", i, q.options[i]);
                printf(YELLOW "\n Your Answer (0-3): " RESET);
                fflush(stdout);
            } 
            else if (msg_header.type == MSG_EXAM_OVER) {
                log_state("Received Exam Over packet");
                ExamResultPayload res;
                SSL_read(ssl, &res, sizeof(res));
                printf(CLEAR YELLOW "====================================================\n" RESET);
                printf(BOLD "              EXAM SESSION COMPLETE\n" RESET);
                printf("\n Final Score: " GREEN BOLD "%d / %d\n" RESET, res.score, res.total_questions);
                printf("\n Press [ENTER] to exit.");
                fflush(stdout);
                
                char dummy[10];
                fgets(dummy, sizeof(dummy), stdin);
                break;
            }
        }

        // 2. Data from Student (Keyboard)
        if (FD_ISSET(stdin_fd, &read_fds)) {
            SubmissionPayload sub;
            if (fgets(sub.answer_text, sizeof(sub.answer_text), stdin)) {
                log_state("User input detected and sent");
                sub.answer_text[strcspn(sub.answer_text, "\n")] = 0;
                
                PacketHeader sub_head = {MSG_SUBMISSION, sizeof(SubmissionPayload)};
                SSL_write(ssl, &sub_head, sizeof(PacketHeader));
                SSL_write(ssl, &sub, sizeof(SubmissionPayload));
            }
        }
    }
}

int main() {
    // Logging Setup
    mkdir("logs", 0777);
    char log_filename[64];
    snprintf(log_filename, sizeof(log_filename), "logs/client_%d.log", getpid());
    client_log = fopen(log_filename, "w");
    log_state("Process Started");

    init_openssl();
    SSL_CTX *ctx = create_context(false);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    log_state("Connecting to server...");
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_state("Connection Failed");
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        log_state("SSL Handshake Failed");
        ERR_print_errors_fp(stderr);
    } else {
        log_state("SSL Tunnel Established");
        if (perform_login(ssl)) {
            start_exam_session(ssl); 
        } else {
            printf(RED "Access Denied: Invalid Credentials.\n" RESET);
        }
        SSL_shutdown(ssl);
    }

    log_state("Exiting normally");
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    if (client_log) fclose(client_log);

    return 0;
}