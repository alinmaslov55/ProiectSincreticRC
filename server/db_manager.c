#include "db_manager.h"
#include "../common/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN 16
#define HASH_LEN 32
#define ITERATIONS 10000

// --- UI Macros ---
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"

typedef struct Student {
    char id[16];
    char password_hash[128]; // Marit dela 64 HEX_SALT:HEX_HASH
    struct Student *next;
} Student;

static Student *head = NULL;
static Question question_bank[100]; 
static int total_questions = 0;
static ServerMode current_mode = MODE_REGISTRATION;

// Mutexes
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

void to_hex(unsigned char *src, int len, char *dst) {
    for (int i = 0; i < len; i++) {
        sprintf(dst + (i * 2), "%02x", src[i]);
    }
}

void db_set_mode(ServerMode mode) {
    pthread_mutex_lock(&db_mutex);
    current_mode = mode;
    pthread_mutex_unlock(&db_mutex);
}

ServerMode db_get_mode() {
    return current_mode;
}

void db_save_student_to_disk(const char *id, const char *combined_hash) {
    pthread_mutex_lock(&file_mutex);
    FILE *fp = fopen("registered_students.txt", "a");
    if (fp) {
        fprintf(fp, "%s %s\n", id, combined_hash);
        fclose(fp);
    }
    pthread_mutex_unlock(&file_mutex);
}

void db_add_student_node(const char *id, const char *combined_hash) {
    Student *s = malloc(sizeof(Student));
    if (!s) return;
    strncpy(s->id, id, 15);
    s->id[15] = '\0';
    strncpy(s->password_hash, combined_hash, 127);
    s->password_hash[127] = '\0';
    
    pthread_mutex_lock(&db_mutex);
    s->next = head;
    head = s;
    pthread_mutex_unlock(&db_mutex);
}

void db_add_student(const char *id, const char *password) {
    unsigned char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
    char hex_salt[SALT_LEN * 2 + 1];
    char hex_hash[HASH_LEN * 2 + 1];
    char combined[128];

    // 1. Generam Salt random
    RAND_bytes(salt, SALT_LEN);

    // 2. Obtinem hash folosind PBKDF2
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 
                      ITERATIONS, EVP_sha256(), HASH_LEN, hash);

    to_hex(salt, SALT_LEN, hex_salt);
    to_hex(hash, HASH_LEN, hex_hash);

    // 3. Formatam stringul final ca "HEX_SALT:HEX_HASH"
    snprintf(combined, sizeof(combined), "%s:%s", hex_salt, hex_hash);
    db_add_student_node(id, combined);
}

int db_verify_login(const char *id, const char *password) {
    pthread_mutex_lock(&db_mutex);
    Student *curr = head;
    while (curr) {
        if (strcmp(curr->id, id) == 0) {
            char stored_copy[128];
            strncpy(stored_copy, curr->password_hash, 127);
            stored_copy[127] = '\0';
            pthread_mutex_unlock(&db_mutex);

            char *hex_salt = strtok(stored_copy, ":");
            char *hex_hash = strtok(NULL, ":");

            if (!hex_salt || !hex_hash) return 0;

            unsigned char salt[SALT_LEN];
            unsigned char test_hash[HASH_LEN];
            
            for(int i = 0; i < SALT_LEN; i++) 
                sscanf(hex_salt + (i * 2), "%02hhx", &salt[i]);

            PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, 
                              ITERATIONS, EVP_sha256(), HASH_LEN, test_hash);

            char hex_test_hash[HASH_LEN * 2 + 1];
            to_hex(test_hash, HASH_LEN, hex_test_hash);

            return (strcmp(hex_test_hash, hex_hash) == 0);
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&db_mutex);
    
    if (db_get_mode() == MODE_REGISTRATION) {
        db_add_student(id, password);
        // Save the newly created hash from the head of the list
        db_save_student_to_disk(id, head->password_hash);
        return 1;
    }
    return 0;
}

void db_load_questions() {
    FILE *fp = fopen("questions.txt", "r");
    if (!fp) {
        printf(RED "[ERROR] Could not open questions.txt!\n" RESET);
        return;
    }

    pthread_mutex_lock(&db_mutex);
    char line[512];
    total_questions = 0;

    while (fgets(line, sizeof(line), fp) && total_questions < 100) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) < 10) continue; 

        Question *q = &question_bank[total_questions];
        
        char *token = strtok(line, "|");
        if (!token) continue;
        strncpy(q->text, token, sizeof(q->text) - 1);

        int valid_parse = 1;
        for (int i = 0; i < 4; i++) {
            token = strtok(NULL, "|");
            if (token) strncpy(q->options[i], token, 63);
            else valid_parse = 0;
        }

        token = strtok(NULL, "|");
        if (token && valid_parse) {
            q->correct_option = atoi(token);
            q->id = total_questions + 1;
            total_questions++;
        }
    }
    pthread_mutex_unlock(&db_mutex);
    fclose(fp);
    printf(GREEN "[DB] Loaded %d questions from file.\n" RESET, total_questions);
}

Question* db_get_question(int index) {
    if (index >= 0 && index < total_questions) {
        return &question_bank[index];
    }
    return NULL;
}

int db_get_question_count(void) {
    return total_questions;
}

void db_log_result(const char* student_id, int score, int total) {
    pthread_mutex_lock(&file_mutex);
    FILE *check_fp = fopen("exam_results.csv", "r");
    bool write_header = (check_fp == NULL);
    if (check_fp) fclose(check_fp);

    FILE *fp = fopen("exam_results.csv", "a");
    if (fp) {
        if (write_header) {
            fprintf(fp, "UnixTime,Date,StudentID,Score,Total,Percentage,Status\n");
        }
        float percentage = total > 0 ? ((float)score / (float)total) * 100.0 : 0;
        const char* status = (percentage >= 50.0) ? "PASS" : "FAIL";
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char date_str[20];
        strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", t);

        fprintf(fp, "%ld,%s,%s,%d,%d,%.2f%%,%s\n", 
                (long)now, date_str, student_id, score, total, percentage, status);
        fclose(fp);
    }
    pthread_mutex_unlock(&file_mutex);
}

void db_init() {
    db_load_questions();

    FILE *fp = fopen("registered_students.txt", "r");
    if (fp) {
        char id[16], combined_hash[128];
        while (fscanf(fp, "%15s %127s", id, combined_hash) == 2) {
            db_add_student_node(id, combined_hash);
        }
        fclose(fp);
    }
    printf(BLUE "[DB] Registry initialized. Mode: REGISTRATION.\n" RESET);
}

void db_cleanup() {
    pthread_mutex_lock(&db_mutex);
    Student *curr = head;
    while (curr) {
        Student *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    head = NULL;
    pthread_mutex_unlock(&db_mutex);
}