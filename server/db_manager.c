#include "db_manager.h"
#include "../common/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

// Internal Linked List for Students
typedef struct Student {
    char id[16];
    char password_hash[64];
    struct Student *next;
} Student;

static Student *head = NULL;
static Question question_bank[10];
static int total_questions = 0;

// Mutexes for Thread Safety
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Helper to add students safely
void db_add_student(const char *id, const char *hash) {
    Student *s = malloc(sizeof(Student));
    if (!s) return;

    pthread_mutex_lock(&db_mutex);
    memset(s->id, 0, sizeof(s->id));
    strncpy(s->id, id, sizeof(s->id) - 1);
    memset(s->password_hash, 0, sizeof(s->password_hash));
    strncpy(s->password_hash, hash, sizeof(s->password_hash) - 1);
    s->next = head;
    head = s;
    pthread_mutex_unlock(&db_mutex);
}

// Helper to add questions to the bank
void db_add_quiz_question(int id, const char* text, const char* o0, const char* o1, const char* o2, const char* o3, int correct) {
    if (total_questions >= 10) return;
    
    Question *q = &question_bank[total_questions];
    q->id = id;
    strncpy(q->text, text, sizeof(q->text) - 1);
    strncpy(q->options[0], o0, 63);
    strncpy(q->options[1], o1, 63);
    strncpy(q->options[2], o2, 63);
    strncpy(q->options[3], o3, 63);
    q->correct_option = correct;
    
    total_questions++;
}

void db_init() {
    // 1. Load Actors
    db_add_student("STUDENT001", "hashed_pass_123");
    db_add_student("STUDENT002", "password_test");

    // 2. Load Questions (The Logic)
    db_add_quiz_question(1, "What is the capital of France?", "London", "Paris", "Berlin", "Rome", 1);
    db_add_quiz_question(2, "Which language is this project in?", "Python", "Java", "C", "C++", 2);
    db_add_quiz_question(3, "Size of char in C?", "1 byte", "2 bytes", "4 bytes", "8 bytes", 0);

    printf("[DB] Registry and Question Bank (count: %d) initialized.\n", total_questions);
}

int db_verify_login(const char *id, const char *hash) {
    int found = 0;
    pthread_mutex_lock(&db_mutex);
    Student *curr = head;
    while (curr) {
        if (strcmp(curr->id, id) == 0 && strcmp(curr->password_hash, hash) == 0) {
            found = 1;
            break;
        }
        curr = curr->next;
    }
    pthread_mutex_unlock(&db_mutex);
    return found;
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
    FILE *fp = fopen("exam_results.csv", "a");
    if (fp) {
        fprintf(fp, "%ld,%s,%d/%d\n", (long)time(NULL), student_id, score, total);
        fclose(fp);
    }
    pthread_mutex_unlock(&file_mutex);
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