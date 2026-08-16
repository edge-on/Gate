#include "Mmap/SSL.hpp"
#include <cstring>
#include <algorithm>

Mmap::SSL::~SSL()
{
    if (mmapBase && totalFileSize > 0)
        munmap(mmapBase, totalFileSize);
}

bool Mmap::SSL::init(const char *filepath)
{
    size_t systemDataSize = SYSTEM_DATA_RECORDS * sizeof(SystemMetadata);
    totalFileSize = systemDataSize;

    bool is_new_file = (access(filepath, F_OK) == -1);

    int fd = open(filepath, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd == -1)
        return false;

    if (ftruncate(fd, totalFileSize) == -1)
    {
        close(fd);
        return false;
    }

    void *map = mmap(nullptr, totalFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (map == MAP_FAILED)
        return false;

    mmapBase = static_cast<char *>(map);
    systemMetadata = reinterpret_cast<SystemMetadata *>(mmapBase);

    if (is_new_file)
    {
        for (size_t i = 0; i < SYSTEM_DATA_RECORDS; ++i)
        {
            memset(&systemMetadata[i].key, 0, sizeof(systemMetadata[i].key));
            memset(&systemMetadata[i].valueStr, 0, sizeof(systemMetadata[i].valueStr));
        }

        memcpy(systemMetadata[VERSIONING].key, "version", 8);
        systemMetadata[VERSIONING].valueInt = 0;
    }

    return true;
}

uint64_t Mmap::SSL::getCurrentVersion()
{
    return systemMetadata[VERSIONING].valueInt;
}

bool Mmap::SSL::setVersion(uint64_t v)
{
    systemMetadata[VERSIONING].valueInt = v;

    return true;
}