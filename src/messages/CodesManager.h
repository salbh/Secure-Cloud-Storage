#ifndef SECURE_CLOUD_STORAGE_CODESMANAGER_H
#define SECURE_CLOUD_STORAGE_CODESMANAGER_H

#include <cstdint>

// Result of an operation
enum class Result : uint8_t {
    ACK = 0,
    NACK = 1
};

// Type of message
enum class Message : uint8_t {
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
enum class Error : uint8_t {
    USERNAME_NOT_FOUND = 16,
    FILENAME_ALREADY_EXISTS = 17,
    FILENAME_NOT_FOUND = 18
};

#endif //SECURE_CLOUD_STORAGE_CODESMANAGER_H