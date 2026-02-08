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

// --- Configuration & Macros ---
#define PORT 8080
#define EXAM_DURATION_SEC 60

#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"

typedef struct {
    int socket;
    SSL_CTX *ctx;
} client_data_t;

// --- Helper Functions ---

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

FILE* open_thread_log() {
    mkdir("logs", 0777);
    char filename[64];
    snprintf(filename, sizeof(filename), "logs/server_thread_%lu.log", (unsigned long)pthread_self());
    FILE *fp = fopen(filename, "w");
    if (fp) {
        setvbuf(fp, NULL, _IOLBF, 0); 
        fprintf(fp, "[%ld] --- PROCTOR SESSION START ---\n", time(NULL));
    }
    return fp;
}

// --- Admin Console Thread ---
void *admin_console(void *arg) {
    (void)arg;
    char command[64];
    printf(YELLOW "\n[Admin] Console ready. Commands: 'start', 'status', 'results', 'exit'\n" RESET);

    while (1) {
        printf(BOLD "admin> " RESET);
        fflush(stdout);
        if (fgets(command, sizeof(command), stdin) == NULL) break;
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "start") == 0) {
            db_set_mode(MODE_EXAMINATION);
            printf(GREEN BOLD "\n[SYSTEM] Switched to EXAMINATION MODE. Students can now begin tests.\n" RESET);
        } 
        else if (strcmp(command, "status") == 0) {
            ServerMode m = db_get_mode();
            printf(BLUE "\n--- Server Status ---\n");
            printf("Mode: %s\n", m == MODE_REGISTRATION ? "REGISTRATION" : "EXAMINATION");
            printf("Questions loaded: %d\n", db_get_question_count());
            printf("---------------------\n" RESET);
        }
        else if (strcmp(command, "results") == 0) {
            printf(BLUE "\n--- Latest Exam Results ---\n" RESET);
            // Formats the CSV for terminal viewing
            system("column -s, -t < exam_results.csv | tail -n 15");
            printf(BLUE "---------------------------\n" RESET);
        }
        else if (strcmp(command, "exit") == 0) {
            printf(RED "Closing server...\n" RESET);
            exit(0);
        }
    }
    return NULL;
}

// --- Student Handler Thread ---
void *handle_student(void *arg) {
    client_data_t *data = (client_data_t*)arg;
    int client_sock = data->socket;
    SSL* ssl = SSL_new(data->ctx);
    FILE* log_fp = open_thread_log();
    
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        if (log_fp) fprintf(log_fp, "[ERROR] SSL Handshake failed.\n");
    } else {
        bool authenticated = false;
        int auth_attempts = 0;
        char student_id[16] = {0};

        // 1. Auth/Registration Loop
        while (auth_attempts < 3 && !authenticated) {
            PacketHeader header;
            if (SSL_read(ssl, &header, sizeof(PacketHeader)) <= 0) break;

            if (header.type == REQ_LOGIN) {
                LoginPayload login;
                SSL_read(ssl, &login, sizeof(LoginPayload));
                
                if (db_verify_login(login.student_id, login.password_hash)) {
                    authenticated = true;
                    strncpy(student_id, login.student_id, 15);
                    if (log_fp) fprintf(log_fp, "[AUTH] %s: SUCCESS (Mode: %d)\n", student_id, db_get_mode());
                    SSL_write(ssl, &(PacketHeader){RES_LOGIN_SUCCESS, 0}, sizeof(PacketHeader));
                } else {
                    auth_attempts++;
                    if (log_fp) fprintf(log_fp, "[AUTH] FAILED attempt for %s\n", login.student_id);
                    SSL_write(ssl, &(PacketHeader){RES_LOGIN_FAILED, 0}, sizeof(PacketHeader));
                }
            }
        }

        // 2. Examination Logic (Gated by Admin Mode)
        if (authenticated && db_get_mode() == MODE_EXAMINATION) {
            PacketHeader header;
            if (SSL_read(ssl, &header, sizeof(PacketHeader)) > 0 && header.type == REQ_EXAM_START) {
                
                int total_qs = db_get_question_count();
                if (total_qs <= 0) {
                    if (log_fp) fprintf(log_fp, "[ERROR] No questions in DB.\n");
                    goto cleanup;
                }

                // --- Fisher-Yates Shuffle Implementation ---
                int *indices = malloc(total_qs * sizeof(int));
                for (int i = 0; i < total_qs; i++) indices[i] = i;

                struct timeval tv;
                gettimeofday(&tv, NULL);
                unsigned int seed = (unsigned int)(tv.tv_usec ^ (unsigned long)pthread_self());
                
                for (int i = total_qs - 1; i > 0; i--) {
                    int j = rand_r(&seed) % (i + 1);
                    int temp = indices[i];
                    indices[i] = indices[j];
                    indices[j] = temp;
                }

                if (log_fp) fprintf(log_fp, "[EXAM] Started for %s (Randomized order)\n", student_id);
                
                time_t end_time = time(NULL) + EXAM_DURATION_SEC;
                int q_ptr_idx = 0, score = 0;
                setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval){5, 0}, sizeof(struct timeval));

                // 3. Quiz Cycle
                while (q_ptr_idx < total_qs && time(NULL) < end_time) {
                    Question *q = db_get_question(indices[q_ptr_idx]);
                    
                    ExamQuestionPayload q_pay;
                    memset(&q_pay, 0, sizeof(q_pay));
                    q_pay.question_id = q->id;
                    q_pay.time_remaining = (int)(end_time - time(NULL));
                    strncpy(q_pay.question_text, q->text, 255);
                    for(int i=0; i<4; i++) strncpy(q_pay.options[i], q->options[i], 63);

                    SSL_write(ssl, &(PacketHeader){MSG_EXAM_QUESTION, sizeof(q_pay)}, sizeof(PacketHeader));
                    SSL_write(ssl, &q_pay, sizeof(q_pay));

                    PacketHeader sub_h;
                    if (SSL_read(ssl, &sub_h, sizeof(PacketHeader)) > 0 && sub_h.type == MSG_SUBMISSION) {
                        SubmissionPayload s_pay;
                        SSL_read(ssl, &s_pay, sizeof(SubmissionPayload));
                        if (atoi(s_pay.answer_text) == q->correct_option) score++;
                        SSL_write(ssl, &(PacketHeader){RES_SUBMISSION_ACK, 0}, sizeof(PacketHeader));
                        q_ptr_idx++;
                    }
                }

                db_log_result(student_id, score, total_qs);
                ExamResultPayload r_pay = {score, total_qs};
                SSL_write(ssl, &(PacketHeader){MSG_EXAM_OVER, sizeof(r_pay)}, sizeof(PacketHeader));
                SSL_write(ssl, &r_pay, sizeof(r_pay));
                
                free(indices);
            }
        } else if (authenticated && db_get_mode() == MODE_REGISTRATION) {
            if (log_fp) fprintf(log_fp, "[REG] %s registered/verified. Session parked.\n", student_id);
        }
    }

cleanup:
    SSL_shutdown(ssl);
    if (log_fp) fclose(log_fp);
    SSL_free(ssl);
    close(client_sock);
    free(data);
    pthread_detach(pthread_self());
    return NULL;
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context(true);
    configure_server_context(ctx);
    db_init();

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY };
    if(bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed"); exit(1);
    }

    listen(server_sock, 10);
    printf(BLUE BOLD "Proctor Node: " GREEN "ONLINE" RESET "\n");

    pthread_t admin_tid;
    pthread_create(&admin_tid, NULL, admin_console, NULL);

    while(1) {
        struct sockaddr_in c_addr;
        socklen_t len = sizeof(c_addr);
        int c_sock = accept(server_sock, (struct sockaddr*)&c_addr, &len);
        if (c_sock >= 0) {
            client_data_t *data = malloc(sizeof(client_data_t));
            data->socket = c_sock;
            data->ctx = ctx;
            pthread_t tid;
            pthread_create(&tid, NULL, handle_student, data);
        }
    }

    db_cleanup();
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}