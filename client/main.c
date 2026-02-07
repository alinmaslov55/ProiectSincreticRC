#include "../common/crypto.h"
#include "../common/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <stdbool.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080

// UI COLOR Macros
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define CLEAR   "\033[H\033[J"

// Function Prototypes
bool perform_login(SSL *ssl);
void start_exam_session(SSL *ssl);

int main() {
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // 1. Global OpenSSL and Context Init
    init_openssl();
    ctx = create_context(false); // client mode

    // 2. Standard Socket Creation
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 3. Connect to Server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to Proctor failed");
        exit(EXIT_FAILURE);
    }

    // 4. Wrap Socket with SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        printf("SSL Handshake failed.\n");
    } else {
        printf("Secure tunnel established via %s\n", SSL_get_cipher(ssl));

        // 5. Workflow: Login -> Exam
        if (perform_login(ssl)) {
            printf("SUCCESS: Authenticated by Proctor Node.\n");
            start_exam_session(ssl); 
        } else {
            printf("FAILED: Authentication rejected. Access Denied.\n");
        }
        
        // 6. Graceful Shutdown
        SSL_shutdown(ssl);
    }

    // 7. Resource Cleanup
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}

bool perform_login(SSL *ssl) {
    PacketHeader header;
    LoginPayload login;

    // Clear memory to avoid sending garbage bytes
    memset(&header, 0, sizeof(PacketHeader));
    memset(&login, 0, sizeof(LoginPayload));

    // Fill credentials (Mocking user input for now)
    strncpy(login.student_id, "STUDENT001", sizeof(login.student_id) - 1);
    strncpy(login.password_hash, "hashed_pass_123", sizeof(login.password_hash) - 1);

    header.type = REQ_LOGIN;
    header.payload_len = sizeof(LoginPayload);

    // Send credentials over encrypted channel
    SSL_write(ssl, &header, sizeof(PacketHeader));
    SSL_write(ssl, &login, sizeof(LoginPayload));

    // Wait for authentication response
    PacketHeader res_header;
    int bytes = SSL_read(ssl, &res_header, sizeof(PacketHeader));

    if (bytes == sizeof(PacketHeader) && res_header.type == RES_LOGIN_SUCCESS) {
        return true;
    }
    return false;
}

void start_exam_session(SSL *ssl) {
    PacketHeader header = {REQ_EXAM_START, 0};
    SSL_write(ssl, &header, sizeof(PacketHeader));

    while (1) {
        PacketHeader msg_header;
        int bytes = SSL_read(ssl, &msg_header, sizeof(PacketHeader));

        if (bytes <= 0) break;

        if (msg_header.type == MSG_EXAM_QUESTION) {
            ExamQuestionPayload q;
            SSL_read(ssl, &q, sizeof(ExamQuestionPayload));

            // UI Refresh: Clear screen and draw header
            printf(CLEAR);
            printf(BLUE "====================================================\n" RESET);
            printf(BOLD " OMNITEST SECURE CAMPUS - EXAM IN PROGRESS\n" RESET);
            printf(BLUE "====================================================\n" RESET);

            // Dynamic Timer Color
            const char* timer_color = (q.time_remaining < 15) ? RED : GREEN;
            printf(" Time Remaining: %s%d seconds%s\n\n", timer_color, q.time_remaining, RESET);

            // Question Display
            printf(BOLD " Q%d: %s\n" RESET, q.question_id, q.question_text);
            for (int i = 0; i < 4; i++) {
                printf("  [%d] %s\n", i, q.options[i]);
            }
            printf(BLUE "\n----------------------------------------------------\n" RESET);
            printf(YELLOW " Your Answer (0-3): " RESET);
            fflush(stdout);

            // Input Handling
            SubmissionPayload sub;
            sub.question_id = q.question_id;
            if (fgets(sub.answer_text, sizeof(sub.answer_text), stdin)) {
                sub.answer_text[strcspn(sub.answer_text, "\n")] = 0;
                
                PacketHeader sub_head = {MSG_SUBMISSION, sizeof(SubmissionPayload)};
                SSL_write(ssl, &sub_head, sizeof(PacketHeader));
                SSL_write(ssl, &sub, sizeof(SubmissionPayload));
            }
        } 
        else if (msg_header.type == MSG_EXAM_OVER) {
            ExamResultPayload res;
            SSL_read(ssl, &res, sizeof(ExamResultPayload));

            printf(CLEAR);
            printf(YELLOW "====================================================\n" RESET);
            printf(BOLD "              EXAM SESSION COMPLETE\n" RESET);
            printf(YELLOW "====================================================\n\n" RESET);
            printf(" Final Score: " GREEN BOLD "%d / %d\n" RESET, res.score, res.total_questions);
            printf("\n Results have been submitted to the Proctor.\n");
            printf(" Press [ENTER] to exit.");
            getchar();
            break;
        }
    }
}