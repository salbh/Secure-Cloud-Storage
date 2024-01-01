#include "FileManager.h"
#include "Config.h"
#include <cmath>
#include <stdexcept>
#include <cstring>

using std::cerr, std::cout, std::endl, std::ifstream, std::ofstream,
        std::ios, std::runtime_error, std::streampos, std::streamsize, std::ceil, std::exception;

FileManager::FileManager(const string &file_path, OpenMode open_mode)
        : m_open_mode(open_mode), m_in_file(), m_out_file(),
          m_file_size(0), m_chunks_num(0), m_last_chunk_size(0) {
    openFile(file_path);
}

FileManager::~FileManager() {
    if (m_open_mode == OpenMode::READ) {
        m_in_file.close();
    } else if (m_open_mode == OpenMode::WRITE) {
        m_out_file.close();
    }
}

streamsize FileManager::getFileSize() const {
    return m_file_size;
}

streamsize FileManager::getChunksNum() const {
    return m_chunks_num;
}

streamsize FileManager::getLastChunkSize() const {
    return m_last_chunk_size;
}

int FileManager::readChunk(char *buffer, streamsize size) {
    if (m_open_mode == READ) {
        m_in_file.read(buffer, size);
    } else {
        cerr << "FileManager - Error while reading chunk" << endl;
        return -1;
    }
    return 0;
}

int FileManager::writeChunk(const char *buffer, streamsize size) {
    if (m_open_mode == WRITE) {
        m_out_file.write(buffer, size);
    } else {
        cerr << "FileManager - Error while writing chunk" << endl;
        return -1;
    }
    return 0;
}

bool FileManager::isFilePresent(const string &file_path) {
    ifstream in_data(file_path, ios::binary);
    return in_data.is_open();
}

bool FileManager::isStringValid(const string &input_string) {
    const char whitelist[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@";
    if (strspn(input_string.c_str(), whitelist) < input_string.length()) {
        cerr << "FileManager - Error! Characters not allowed" << endl;
        cout << "Allowed characters are: ";
        for (const char *ptr = whitelist; *ptr; ptr++) {
            cout << *ptr;
        }
        cout << endl;
        return false;
    }

    if (input_string.empty()) {
        cerr << "FileManager - Error! Filename cannot be empty" << endl;
        return false;
    }

    if (input_string.length() > Config::FILE_NAME_LEN) {
        cerr << "FileManager - Error! The string is too long. Maximum allowed length is "
             << Config::FILE_NAME_LEN << " characters" << endl;
        return false;
    }

    if (input_string == "." || input_string == "..") {
        cerr << "FileManager - Error! Invalid string. Reserved names not allowed" << endl;
        return false;
    }
    return true;
}

void FileManager::openFile(const string &file_path) {
    try {
        if (m_open_mode == OpenMode::READ) {
            m_in_file.open(file_path, ios::binary);
            if (!m_in_file.is_open()) {
                throw runtime_error("Failed to open file for reading");
            }
            initFileInfo(computeFileSize(m_in_file));
        } else if (m_open_mode == OpenMode::WRITE) {
            if (isFilePresent(file_path)) {
                throw runtime_error("File already exists");
            }
            m_out_file.open(file_path, ios::binary);
            if (!m_out_file.is_open()) {
                throw runtime_error("Failed to open file for writing");
            }
        }
    } catch (const exception &e) {
        cerr << "FileManager - Error! " << e.what() << endl;
    }
}

streamsize FileManager::computeFileSize(ifstream &in_file) {
    streampos begin = in_file.tellg();
    in_file.seekg(0, ios::end);
    streampos end = in_file.tellg();
    if (end < begin) {
        throw runtime_error("Failed to determine file size");
    }
    return end - begin;
}

void FileManager::initFileInfo(streamsize file_size) {
    m_file_size = file_size;
    m_chunks_num = ceil((double) m_file_size / (double) Config::CHUNK_SIZE);
    if (m_file_size % Config::CHUNK_SIZE != 0) {
        m_last_chunk_size = m_file_size % Config::CHUNK_SIZE;
    } else {
        m_last_chunk_size = Config::CHUNK_SIZE;
    }
}




