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
    DOWNLOAD_CHUNK = 6,
    DELETE_REQUEST = 7,
    DELETE_ASK = 8,
    DELETE_CONFIRM = 9,
    LIST_REQUEST = 10,
    LIST_SIZE = 11,
    LIST_RESPONSE = 12,
    RENAME_REQUEST = 13,
    LOGOUT_REQUEST = 14
};

// Error condition
enum class Error : int {
    USERNAME_NOT_FOUND = 15,
    FILENAME_ALREADY_EXISTS = 16,
    FILENAME_NOT_FOUND = 17
};

#endif //SECURE_CLOUD_STORAGE_CODESMANAGER_H