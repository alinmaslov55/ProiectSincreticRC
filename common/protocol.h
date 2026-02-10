#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAX_NAME_LEN 64
#define MAX_BUFFER 1024

/**
 * __attribute__((packed)) - instructiune care compiler pentru a preveni sa adauge padding/spatii intre campurile din strcuturi
 */

// Packet Types
typedef enum {
    REQ_LOGIN,
    RES_LOGIN_SUCCESS,
    RES_LOGIN_FAILED,
    REQ_EXAM_START,
    MSG_EXAM_QUESTION,
    MSG_EXAM_OVER,
    MSG_SUBMISSION,
    RES_SUBMISSION_ACK,
    ERR_TIMEOUT
} PacketType;

typedef struct __attribute__((packed)) {
    int score;
    int total_questions;
} ExamResultPayload;

typedef struct __attribute__((packed)) {
    int question_id;
    char answer_text[128];
} SubmissionPayload;

typedef struct __attribute__((packed)) {
    int question_id;
    char question_text[256];
    char options[4][64]; // quiz -> has 4 choices
    int time_remaining; // Seconds left
} ExamQuestionPayload;

typedef struct __attribute__((packed)){
    PacketType type;
    uint32_t payload_len;
} PacketHeader;

typedef struct __attribute__((packed)) {
    char student_id[16];
    char password_hash[64];
} LoginPayload;

const char* get_packet_name(PacketType type);

#endif // PROTOCOL_H