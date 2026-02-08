#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <stdbool.h>

// Server Operational Modes
typedef enum {
    MODE_REGISTRATION,
    MODE_EXAMINATION
} ServerMode;

typedef struct {
    int id;
    char text[256];
    char options[4][64];
    int correct_option; // 0 to 3
} Question;

// Lifecycle & State
void db_init(void);
void db_cleanup(void);
void db_set_mode(ServerMode mode);
ServerMode db_get_mode(void);

// Student Management
int db_verify_login(const char *id, const char *hash);
void db_add_student(const char *id, const char *hash);
void db_save_student_to_disk(const char *id, const char *hash);

// Question Bank
void db_add_quiz_question(int id, const char* text, const char* o0, const char* o1, const char* o2, const char* o3, int correct);
Question* db_get_question(int index);
int db_get_question_count(void);

// Persistence
void db_log_result(const char* student_id, int score, int total);

#endif // DB_MANAGER_H