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

// --- UI Macros (Fixed: Added CYAN) ---
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CYAN    "\033[1;36m"
#define CLEAR   "\033[H\033[J"

FILE *client_log = NULL;

const char* p_name(PacketType type) {
    switch(type) {
        case REQ_LOGIN: return "REQ_LOGIN";
        case RES_LOGIN_SUCCESS: return "RES_LOGIN_SUCCESS";
        case RES_LOGIN_FAILED: return "RES_LOGIN_FAILED";
        case REQ_EXAM_START: return "REQ_EXAM_START";
        case MSG_EXAM_QUESTION: return "MSG_EXAM_QUESTION";
        case MSG_SUBMISSION: return "MSG_SUBMISSION";
        case RES_SUBMISSION_ACK: return "RES_SUBMISSION_ACK";
        case MSG_EXAM_OVER: return "MSG_EXAM_OVER";
        default: return "UNKNOWN_PACKET";
    }
}

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
    while (attempts < 3) {
        memset(&login, 0, sizeof(login));
        printf(BLUE BOLD "\n--- OmniTest Login (Attempt %d/3) ---\n" RESET, attempts + 1);
        printf("ID: "); if(!fgets(login.student_id, 16, stdin)) break;
        login.student_id[strcspn(login.student_id, "\n")] = 0;
        printf("Pass: "); if(!fgets(login.password_hash, 64, stdin)) break;
        login.password_hash[strcspn(login.password_hash, "\n")] = 0;

        SSL_write(ssl, &header, sizeof(header));
        SSL_write(ssl, &login, sizeof(login));

        PacketHeader res;
        if (SSL_read(ssl, &res, sizeof(res)) <= 0) break;
        if (res.type == RES_LOGIN_SUCCESS) return true;
        
        printf(RED "Invalid credentials.\n" RESET);
        attempts++;
    }
    return false;
}

// Fixed: Changed return type from void to bool to support retry logic
bool start_exam_session(SSL *ssl) {
    PacketHeader start_req = {REQ_EXAM_START, 0};
    SSL_write(ssl, &start_req, sizeof(start_req));

    // Peek to see if server sends a question or closes the connection
    PacketHeader first_check;
    int bytes = SSL_read(ssl, &first_check, sizeof(first_check));
    
    if (bytes <= 0) {
        // Server closed connection because it is in REGISTRATION mode
        return false; 
    }

    // If we are here, the server sent the first question or signal
    bool session_active = true;
    int server_fd = SSL_get_fd(ssl);
    int stdin_fd = fileno(stdin);
    int max_fd = (server_fd > stdin_fd) ? server_fd : stdin_fd;

    while (session_active) {
        // Re-process the first_check header we already read if it was a question
        PacketHeader current_h = first_check;
        bool skip_read = true; // For the very first iteration

        while (session_active) {
            if (!skip_read) {
                fd_set read_fds;
                FD_ZERO(&read_fds);
                FD_SET(server_fd, &read_fds);
                FD_SET(stdin_fd, &read_fds);
                if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) break;

                if (FD_ISSET(server_fd, &read_fds)) {
                    if (SSL_read(ssl, &current_h, sizeof(PacketHeader)) <= 0) break;
                } else if (FD_ISSET(stdin_fd, &read_fds)) {
                    SubmissionPayload sub;
                    if (fgets(sub.answer_text, sizeof(sub.answer_text), stdin)) {
                        sub.answer_text[strcspn(sub.answer_text, "\n")] = 0;
                        PacketHeader sub_head = {MSG_SUBMISSION, sizeof(SubmissionPayload)};
                        SSL_write(ssl, &sub_head, sizeof(PacketHeader));
                        SSL_write(ssl, &sub, sizeof(SubmissionPayload));
                    }
                    continue;
                }
            }
            skip_read = false;

            if (current_h.type == MSG_EXAM_QUESTION) {
                ExamQuestionPayload q;
                SSL_read(ssl, &q, sizeof(q));
                printf(CLEAR BLUE "====================================================\n" RESET);
                printf(BOLD " OMNITEST SECURE CAMPUS - EXAM IN PROGRESS\n" RESET);
                printf(" Time Remaining: %d seconds\n", q.time_remaining);
                printf(BOLD "\n Q%d: %s\n" RESET, q.question_id, q.question_text);
                for (int i = 0; i < 4; i++) printf("  [%d] %s\n", i, q.options[i]);
                printf(YELLOW "\n Your Answer (0-3): " RESET);
                fflush(stdout);
            } 
            else if (current_h.type == MSG_EXAM_OVER) {
                ExamResultPayload res;
                SSL_read(ssl, &res, sizeof(res));
                printf(CLEAR YELLOW "====================================================\n" RESET);
                printf(BOLD "              EXAM SESSION COMPLETE\n" RESET);
                printf("\n Final Score: " GREEN BOLD "%d / %d\n" RESET, res.score, res.total_questions);
                printf("\n Press [ENTER] to exit.");
                fflush(stdout);
                getchar();
                session_active = false;
            }
        }
    }
    return true;
}

int main() {
    mkdir("logs", 0777);
    char log_filename[64];
    snprintf(log_filename, sizeof(log_filename), "logs/client_%d.log", getpid());
    client_log = fopen(log_filename, "w");

    init_openssl();
    SSL_CTX *ctx = create_context(false);
    bool exam_finished = false;

    printf(YELLOW BOLD "OmniTest Secure Client: Connecting to Proctor...\n" RESET);

    while (!exam_finished) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
        inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            printf(RED "Proctor Node Offline. Retrying in 5s...\n" RESET);
            close(sock);
            sleep(5);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            sleep(5);
            continue;
        }

        if (perform_login(ssl)) {
            // Check if start_exam_session returns true (Exam taken) or false (Still in Registration)
            if (start_exam_session(ssl)) {
                exam_finished = true; 
            } else {
                printf(CYAN "Status: Registered. Waiting for Proctor to signal 'START'...\n" RESET);
            }
        } else {
            printf(RED "Fatal: Authentication failed.\n" RESET);
            exam_finished = true;
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);

        if (!exam_finished) sleep(5);
    }

    SSL_CTX_free(ctx);
    cleanup_openssl();
    if (client_log) fclose(client_log);
    return 0;
}