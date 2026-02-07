#ifndef DB_MANAGER_H
#define DB_MANAGER_H

#include <stdbool.h>

typedef struct {
    int id;
    char text[256];
    char options[4][64];
    int correct_option; // 0 la 3
} Question;

void db_init(void);
int db_verify_login(const char *id, const char *hash);
void db_add_student(const char *id, const char *hash);
void db_cleanup(void);

void db_load_questions();
Question* db_get_question(int index);
int db_get_question_count(void);
void db_log_result(const char* student_id, int score, int total);

#endif // DB_MANAGER_H