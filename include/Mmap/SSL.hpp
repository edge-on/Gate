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

namespace Mmap
{
    const size_t SYSTEM_DATA_RECORDS = 10;

    struct __attribute__((packed)) SystemMetadata
    {
        char key[256];         // 256 Byte
        char valueStr[256];    // 256 Byte
        uint64_t valueInt = 0; // 16 Byte
    }; // 528 Byte

    enum
    {
        VERSIONING = 0
    };

    class SSL
    {
    private:
        char *mmapBase = nullptr;
        SystemMetadata *systemMetadata = nullptr;

        size_t totalFileSize = 0;
        int32_t freeListHeadIdx = -1;

    public:
        bool init(const char *filepath);

        uint64_t getCurrentVersion();

        bool setVersion(uint64_t version);

        ~SSL();
    };
}