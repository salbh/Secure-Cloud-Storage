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
    LIST_RESPONSE = 12,
    RENAME_REQUEST = 13,
    LOGOUT_REQUEST = 14
};

// Error condition
enum class Error : int {
    USERNAME_NOT_FOUND = 14,
    FILENAME_ALREADY_EXISTS = 15,
    FILENAME_NOT_FOUND = 16
};

#endif //SECURE_CLOUD_STORAGE_CODESMANAGER_H