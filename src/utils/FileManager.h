#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <iostream>
#include <fstream>
#include <string>

using std::string;
using std::ifstream;
using std::ofstream;
using std::streamsize;

class FileManager {

public:
    enum OpenMode {
        READ, WRITE
    };

    FileManager();

    FileManager(const string &file_path, OpenMode open_mode);

    ~FileManager();

    streamsize getFileSize() const;

    streamsize getChunksNum() const;

    streamsize getLastChunkSize() const;

    void closeFile();

    int readChunk(uint8_t *buffer, streamsize size);

    int writeChunk(uint8_t *buffer, streamsize size);

    void initFileInfo(streamsize file_size);

    static streamsize computeFileSize(const string& file_path);

    static string getFilesList(const string &path);

    static bool isFilePresent(const string &file_path);

    static bool isStringValid(const string &input_string);

    static bool isNumeric(const string& str);

private:
    OpenMode m_open_mode;
    ifstream m_in_file;
    ofstream m_out_file;

    streamsize m_file_size{};
    streamsize m_chunks_num{};
    streamsize m_last_chunk_size{};

    void openFile(const string &file_path);


};

#endif // FILE_MANAGER_H
