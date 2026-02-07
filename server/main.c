#include "../common/crypto.h"
#include "../common/protocol.h"
#include "db_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

// --- Macros ---
#define PORT 8080
#define EXAM_DURATION_SEC 60

// UI/Console Formatting Macros
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"

// Structure to pass data to the thread
typedef struct {
    int socket;
    SSL_CTX *ctx;
} client_data_t;

// --- Thread Logging Helper ---
/**
 * Creates a unique log file for each thread to track state transitions.
 */
FILE* open_thread_log() {
    mkdir("logs", 0777);
    char filename[64];
    snprintf(filename, sizeof(filename), "logs/server_thread_%lu.log", (unsigned long)pthread_self());
    FILE *fp = fopen(filename, "w");
    if (fp) {
        setvbuf(fp, NULL, _IOLBF, 0); // Line buffered for real-time visibility
        fprintf(fp, "[%ld] --- PROCTOR THREAD START ---\n", time(NULL));
    }
    return fp;
}

void *handle_student(void *arg) {
    client_data_t *data = (client_data_t*)arg;
    int client_sock = data->socket;
    SSL* ssl = SSL_new(data->ctx);
    FILE* log_fp = open_thread_log();
    
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        if (log_fp) fprintf(log_fp, "[ERROR] SSL Handshake failed.\n");
        ERR_print_errors_fp(stderr);
    } else {
        if (log_fp) fprintf(log_fp, "[INFO] Secure connection established.\n");
        
        PacketHeader header;
        // 1. Authentication Phase
        if (SSL_read(ssl, &header, sizeof(PacketHeader)) == sizeof(PacketHeader) && header.type == REQ_LOGIN) {
            LoginPayload login;
            SSL_read(ssl, &login, sizeof(LoginPayload));
            if (log_fp) fprintf(log_fp, "[AUTH] Login request for ID: %s\n", login.student_id);

            if (db_verify_login(login.student_id, login.password_hash)) {
                if (log_fp) fprintf(log_fp, "[AUTH] SUCCESS.\n");
                SSL_write(ssl, &(PacketHeader){RES_LOGIN_SUCCESS, 0}, sizeof(PacketHeader));

                // 2. Exam Start Transition
                if (SSL_read(ssl, &header, sizeof(PacketHeader)) == sizeof(PacketHeader) && header.type == REQ_EXAM_START) {
                    if (log_fp) fprintf(log_fp, "[EXAM] Session initiated.\n");
                    
                    time_t end_time = time(NULL) + EXAM_DURATION_SEC;
                    int current_q_idx = 0;
                    int student_score = 0;
                    int total_qs = db_get_question_count();

                    // Pulse timeout: Ensures SSL_read doesn't hang the thread indefinitely
                    struct timeval tv = {5, 0}; 
                    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(struct timeval));

                    // 3. Quiz Cycle
                    while (current_q_idx < total_qs && time(NULL) < end_time) {
                        Question *q_ptr = db_get_question(current_q_idx);
                        if (!q_ptr) break;

                        ExamQuestionPayload q_pay;
                        memset(&q_pay, 0, sizeof(q_pay));
                        q_pay.question_id = q_ptr->id;
                        q_pay.time_remaining = (int)(end_time - time(NULL));
                        strncpy(q_pay.question_text, q_ptr->text, sizeof(q_pay.question_text)-1);
                        for(int i=0; i<4; i++) strncpy(q_pay.options[i], q_ptr->options[i], 63);

                        if (log_fp) fprintf(log_fp, "[FLOW] Pushing Question %d\n", q_ptr->id);
                        SSL_write(ssl, &(PacketHeader){MSG_EXAM_QUESTION, sizeof(q_pay)}, sizeof(PacketHeader));
                        SSL_write(ssl, &q_pay, sizeof(q_pay));

                        // Wait for Client Answer
                        PacketHeader sub_head;
                        int bytes = SSL_read(ssl, &sub_head, sizeof(PacketHeader));
                        if (bytes > 0 && sub_head.type == MSG_SUBMISSION) {
                            SubmissionPayload sub_pay;
                            SSL_read(ssl, &sub_pay, sizeof(SubmissionPayload));
                            
                            int choice = atoi(sub_pay.answer_text);
                            if (log_fp) fprintf(log_fp, "[FLOW] Answer received for Q%d: %d\n", q_ptr->id, choice);
                            
                            if (choice == q_ptr->correct_option) student_score++;
                            
                            SSL_write(ssl, &(PacketHeader){RES_SUBMISSION_ACK, 0}, sizeof(PacketHeader));
                            current_q_idx++;
                        }
                    }

                    // 4. Persistence & Score Summary
                    if (log_fp) fprintf(log_fp, "[RESULT] Student finished. Score: %d/%d\n", student_score, total_qs);
                    db_log_result(login.student_id, student_score, total_qs);

                    ExamResultPayload res_pay = {student_score, total_qs};
                    SSL_write(ssl, &(PacketHeader){MSG_EXAM_OVER, sizeof(res_pay)}, sizeof(PacketHeader));
                    SSL_write(ssl, &res_pay, sizeof(res_pay));
                }
            } else {
                if (log_fp) fprintf(log_fp, "[AUTH] FAILED.\n");
                SSL_write(ssl, &(PacketHeader){RES_LOGIN_FAILED, 0}, sizeof(PacketHeader));
            }
        }
        SSL_shutdown(ssl);
    }

    if (log_fp) {
        fprintf(log_fp, "[%ld] --- THREAD TERMINATED ---\n", time(NULL));
        fclose(log_fp);
    }

    SSL_free(ssl);
    close(client_sock);
    free(data);
    pthread_detach(pthread_self());
    return NULL;
}

int main() {
    int server_sock;
    struct sockaddr_in addr;

    // Initialization
    init_openssl();
    SSL_CTX *ctx = create_context(true);
    configure_server_context(ctx);
    db_init();

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    listen(server_sock, 10);
    printf(BLUE BOLD "Proctor Node: " GREEN "ONLINE" RESET "\n");
    printf(YELLOW "Monitoring logs/server_thread_*.log for activity...\n" RESET);

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &len);

        if (client_sock >= 0) {
            pthread_t thread_id;
            client_data_t *data = malloc(sizeof(client_data_t));
            data->socket = client_sock;
            data->ctx = ctx;
            if (pthread_create(&thread_id, NULL, handle_student, data) != 0) {
                perror("Thread creation failed");
                free(data);
                close(client_sock);
            }
        }
    }

    // Cleanup (Unreachable in this infinite loop, but good practice)
    db_cleanup();
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}