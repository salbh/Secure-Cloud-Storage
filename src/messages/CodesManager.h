#ifndef SECURE_CLOUD_STORAGE_CODESMANAGER_H
#define SECURE_CLOUD_STORAGE_CODESMANAGER_H

#include <cstdint>

// Result of an operation
enum class Result : int {
    ACK = 0,
    NACK = 1
};

// Type of message
enum class Message : int {
    AUTHENTICATION_REQUEST = 2,
    UPLOAD_REQUEST = 3,
    UPLOAD_CHUNK = 4,
    DOWNLOAD_REQUEST = 5,
    DOWNLOAD_ACK = 6,
    DOWNLOAD_CHUNK = 7,
    DELETE_REQUEST = 8,
    DELETE_ASK = 9,
    DELETE_CONFIRM = 10,
    LIST_REQUEST = 11,
    LIST_ACK = 12,
    LIST_RESPONSE = 13,
    RENAME_REQUEST = 14,
    LOGOUT_REQUEST = 15
};

// Error condition
enum class Error : int {
    USERNAME_NOT_FOUND = 16,
    FILENAME_ALREADY_EXISTS = 17,
    FILENAME_NOT_FOUND = 18
};

enum class Return : int {
    SUCCESS = 19,
    AUTHENTICATION_SUCCESS = 20,
    AUTHENTICATION_FAILURE = 21,
    ENCRYPTION_FAILURE = 22,
    SEND_FAILURE = 23,
    RECEIVE_FAILURE = 24,
    DECRYPTION_FAILURE = 25,
    WRONG_COUNTER = 26,
    WRONG_MSG_CODE = 27,
};

#endif //SECURE_CLOUD_STORAGE_CODESMANAGER_H