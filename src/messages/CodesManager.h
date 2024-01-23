#ifndef SECURE_CLOUD_STORAGE_CODESMANAGER_H
#define SECURE_CLOUD_STORAGE_CODESMANAGER_H

#include <cstdint>

// Result of an operation
enum class Result : int {
    ACK = 0,
    NACK = 1
};

// Operation message code
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

// Error message code
enum class Error : int {
    USERNAME_NOT_FOUND = 16,
    FILENAME_ALREADY_EXISTS = 17,
    FILE_NOT_FOUND = 18
};

// Return code
enum class Return : int {
    SUCCESS = 19,
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ENCRYPTION_FAILURE,
    SEND_FAILURE,
    RECEIVE_FAILURE,
    DECRYPTION_FAILURE,
    WRONG_COUNTER,
    WRONG_MSG_CODE,
    WRONG_PATH,
    FILE_ALREADY_EXISTS,
    FILE_NOT_FOUND,
};

#endif //SECURE_CLOUD_STORAGE_CODESMANAGER_H