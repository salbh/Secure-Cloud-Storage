#ifndef SECURE_CLOUD_STORAGE_HASH_H
#define SECURE_CLOUD_STORAGE_HASH_H


class Hash {

public:
    void generateSHA256(unsigned char *input_buffer, unsigned long input_buffer_size, unsigned char *&digest,
                        unsigned int &digest_size);
};


#endif //SECURE_CLOUD_STORAGE_HASH_H
