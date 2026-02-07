#include "../common/crypto.h"
#include "../common/protocol.h"
#include "db_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <sys/time.h>

#define PORT 8080
#define EXAM_DURATION_SEC 60

typedef struct {
    int socket;
    SSL_CTX *ctx;
} client_data_t;

void *handle_student(void *arg) {
    client_data_t *data = (client_data_t*)arg;
    int client_sock = data->socket;
    SSL* ssl = SSL_new(data->ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        PacketHeader header;
        // 1. Authentication Phase
        if (SSL_read(ssl, &header, sizeof(PacketHeader)) == sizeof(PacketHeader) && header.type == REQ_LOGIN) {
            LoginPayload login;
            SSL_read(ssl, &login, sizeof(LoginPayload));

            if (db_verify_login(login.student_id, login.password_hash)) {
                SSL_write(ssl, &(PacketHeader){RES_LOGIN_SUCCESS, 0}, sizeof(PacketHeader));

                // 2. Exam Initialization
                if (SSL_read(ssl, &header, sizeof(PacketHeader)) == sizeof(PacketHeader) && header.type == REQ_EXAM_START) {
                    time_t end_time = time(NULL) + EXAM_DURATION_SEC;
                    int current_q_idx = 0;
                    int student_score = 0;
                    int total_qs = db_get_question_count();

                    // Pulse timeout for the socket to keep the loop responsive
                    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){5, 0}, sizeof(struct timeval));

                    // 3. Quiz Workflow Loop
                    while (current_q_idx < total_qs && time(NULL) < end_time) {
                        Question *q_ptr = db_get_question(current_q_idx);
                        
                        // Prepare Quiz Payload
                        ExamQuestionPayload q_pay;
                        memset(&q_pay, 0, sizeof(q_pay));
                        q_pay.question_id = q_ptr->id;
                        q_pay.time_remaining = (int)(end_time - time(NULL));
                        strncpy(q_pay.question_text, q_ptr->text, sizeof(q_pay.question_text)-1);
                        for(int i=0; i<4; i++) {
                            strncpy(q_pay.options[i], q_ptr->options[i], sizeof(q_pay.options[i])-1);
                        }

                        // Send Question
                        SSL_write(ssl, &(PacketHeader){MSG_EXAM_QUESTION, sizeof(q_pay)}, sizeof(PacketHeader));
                        SSL_write(ssl, &q_pay, sizeof(q_pay));

                        // 4. Answer Validation (State: Waiting for Choice)
                        PacketHeader sub_head;
                        int bytes = SSL_read(ssl, &sub_head, sizeof(PacketHeader));
                        
                        if (bytes > 0 && sub_head.type == MSG_SUBMISSION) {
                            SubmissionPayload sub_pay;
                            SSL_read(ssl, &sub_pay, sizeof(SubmissionPayload));
                            
                            // Grade the answer (simple atoi for index 0-3)
                            int choice = atoi(sub_pay.answer_text);
                            if (choice == q_ptr->correct_option) {
                                student_score++;
                            }

                            SSL_write(ssl, &(PacketHeader){RES_SUBMISSION_ACK, 0}, sizeof(PacketHeader));
                            current_q_idx++;
                        }
                    }

                    // 5. Enterprise Module: Persistence & Results
                    db_log_result(login.student_id, student_score, total_qs);

                    ExamResultPayload res_pay = {student_score, total_qs};
                    SSL_write(ssl, &(PacketHeader){MSG_EXAM_OVER, sizeof(res_pay)}, sizeof(PacketHeader));
                    SSL_write(ssl, &res_pay, sizeof(res_pay));
                    
                    printf("[Enterprise] Results saved for %s: %d/%d\n", login.student_id, student_score, total_qs);
                }
            } else {
                SSL_write(ssl, &(PacketHeader){RES_LOGIN_FAILED, 0}, sizeof(PacketHeader));
            }
        }
        SSL_shutdown(ssl);
    }

    // Cleanup
    SSL_free(ssl);
    close(client_sock);
    free(data);
    pthread_detach(pthread_self());
    return NULL;
}

int main() {
    int server_sock;
    struct sockaddr_in addr;

    db_init();

    init_openssl();
    SSL_CTX *ctx = create_context(true);
    configure_server_context(ctx);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Fix "Address already in use" error
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
    printf("Proctor Node: Waiting for students on port %d...\n", PORT);

    while(1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);

        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &len);
        if (client_sock < 0) {
            perror("Unable to accept");
            continue;
        }

        pthread_t thread_id;
        client_data_t *data = malloc(sizeof(client_data_t));
        data->socket = client_sock;
        data->ctx = ctx;

        // Delegate to thread and CONTINUE main loop immediately
        if (pthread_create(&thread_id, NULL, handle_student, data) != 0) {
            perror("Could not create thread");
            free(data);
            close(client_sock);
        }
    }

    // Note: In a real app, you'd need a way to break the loop to reach these
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}