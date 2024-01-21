cmake_minimum_required(VERSION 3.26)
project(Secure_Cloud_Storage)

set(CMAKE_CXX_STANDARD 17)

include_directories(src/crypto)
include_directories(src/messages)
include_directories(src/modules)
include_directories(src/utils)

# Add your source files as a library
add_library(Secure_Cloud STATIC
        src/crypto/AesGcm.cpp
        src/crypto/AesGcm.h
        src/crypto/CertificateManager.cpp
        src/crypto/CertificateManager.h
        src/crypto/DiffieHellman.cpp
        src/crypto/DiffieHellman.h
        src/crypto/DigitalSignatureManager.cpp
        src/crypto/DigitalSignatureManager.h
        src/crypto/Hash.cpp
        src/crypto/Hash.h
        src/messages/Authentication.cpp
        src/messages/Authentication.h
        src/messages/Delete.cpp
        src/messages/Delete.h
        src/messages/Download.cpp
        src/messages/Download.h
        src/messages/List.cpp
        src/messages/List.h
        src/messages/Rename.cpp
        src/messages/Rename.h
        src/messages/SimpleMessage.cpp
        src/messages/SimpleMessage.h
        src/messages/CodesManager.h
        src/messages/Upload.cpp
        src/messages/Upload.h
        src/messages/Generic.cpp
        src/modules/Client.cpp
        src/modules/Client.h
        src/modules/ClientMain.cpp
        src/modules/Server.cpp
        src/modules/Server.h
        src/modules/ServerMain.cpp
        src/utils/Config.h
        src/utils/ExtractPublicKey.cpp
        src/utils/FileManager.cpp
        src/utils/FileManager.h
        src/utils/SocketManager.cpp
        src/utils/SocketManager.h
)

# Create an executable for each test file
set(TEST_FILES
        test/AesGcmTest.cpp
        test/CertificateManagerTest.cpp
        test/DiffieHellmanTest.cpp
        test/FileManagerTest.cpp
        test/SocketManagerTest.cpp
        test/KeyTest.cpp
        test/DigitalSignatureManagerTest.cpp
        test/HashTest.cpp
)

foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
    add_executable(${TEST_NAME} ${TEST_FILE})
    target_link_libraries(${TEST_NAME}
            Secure_Cloud
            ssl
            crypto
            stdc++fs
            pthread
    )
endforeach()

# Create the client executable
add_executable(ClientExecutable
        src/modules/ClientMain.cpp
)

target_link_libraries(ClientExecutable
        Secure_Cloud
        ssl
        crypto
        stdc++fs
        pthread
)

add_executable(ServerExecutable
        src/modules/ServerMain.cpp
)

target_link_libraries(ServerExecutable
        Secure_Cloud
        ssl
        crypto
        stdc++fs
        pthread
)
