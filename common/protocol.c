#include "protocol.h"

const char* get_packet_name(PacketType type) {
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