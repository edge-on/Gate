#pragma once

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <array>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cassandra.h>

#include <openssl/sha.h>

namespace Mmap
{
    const size_t MAX_DATA_RECORDS = 100000; // 100K
    const size_t SYSTEM_DATA_RECORDS = 10;

    struct __attribute__((packed)) SSLMetadata
    {
        uint32_t version = 0; // 4 Byte

        char domain[260];       // 260 Byte
        char certificate[4096]; // 4096 Byte
        char privKey[8192];     // 8192 Byte
    }; // 12552 Byte

    struct __attribute__((packed)) SystemMetadata
    {
        char key[256];      // 256 Byte
        char valueStr[256]; // 256 Byte
        uint64_t valueInt;  // 16 Byte
    }; // 528 Byte

    class SSL
    {
    private:
        char *mmapBase = nullptr;
        SSLMetadata *sslMetadata = nullptr;
        SystemMetadata *systemMetadata = nullptr;

        size_t totalFileSize = 0;
        int32_t freeListHeadIdx = -1;

    public:
        bool init(const char *filepath);

        bool getSSL(std::string domain, SSLMetadata &data);
        bool appendSSL(std::string domain, SSLMetadata data);
        bool deleteSSL(std::string domain);

        uint64_t getCurrentVersion();

        uint64_t murmurHash64(const std::string &str, uint32_t seed);

        ~SSL();
    };
}