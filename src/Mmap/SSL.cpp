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
    totalFileSize = systemDataSize + (MAX_DATA_RECORDS * sizeof(SSLMetadata));

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

    // 0 = Version
    systemMetadata = reinterpret_cast<SystemMetadata *>(mmapBase);

    sslMetadata = reinterpret_cast<SSLMetadata *>(mmapBase + systemDataSize);

    if (is_new_file)
    {
        freeListHeadIdx = 0;
        for (size_t i = 0; i < MAX_DATA_RECORDS; ++i)
        {
            memset(&sslMetadata[i], 0, sizeof(SSLMetadata));
            sslMetadata[i].version = -1;
        }

        for (size_t i = 0; i < SYSTEM_DATA_RECORDS; ++i)
        {
            memset(&systemMetadata[i].key, 0, sizeof(systemMetadata[i].key));
            memset(&systemMetadata[i].valueStr, 0, sizeof(systemMetadata[i].valueStr));
        }

        memcpy(systemMetadata[0].key, "version", 8);
        systemMetadata[0].valueInt = 0;
    }

    return true;
}

bool Mmap::SSL::getSSL(std::string domain, SSLMetadata &data)
{
    uint64_t hash = murmurHash64(domain, 42);

    if (hash >= MAX_DATA_RECORDS)
        return false;

    if (sslMetadata[hash].version == -1)
        return false;

    if (strncmp(sslMetadata[hash].domain, domain.c_str(), sizeof(sslMetadata[hash].domain)) != 0)
        return false;

    data = sslMetadata[hash];
    return true;
}

bool Mmap::SSL::appendSSL(std::string domain, const SSLMetadata data)
{
    uint64_t hash = murmurHash64(domain, 42);

    if (hash >= MAX_DATA_RECORDS)
        return false;

    if (systemMetadata[0].valueInt <= data.version)
        return false;

    memset(&sslMetadata[hash], 0, sizeof(SSLMetadata));

    strncpy(sslMetadata[hash].domain, data.domain, sizeof(sslMetadata[hash].domain) - 1);
    strncpy(sslMetadata[hash].certificate, data.certificate, sizeof(sslMetadata[hash].certificate) - 1);
    strncpy(sslMetadata[hash].privKey, data.privKey, sizeof(sslMetadata[hash].privKey) - 1);
    sslMetadata[hash].version = data.version;

    systemMetadata[0].valueInt = data.version;

    return true;
}

bool Mmap::SSL::deleteSSL(std::string domain)
{
    uint64_t hash = murmurHash64(domain, 42);

    if (hash >= MAX_DATA_RECORDS || sslMetadata[hash].version == -1)
        return false;

    if (strncmp(sslMetadata[hash].domain, domain.c_str(), sizeof(sslMetadata[hash].domain)) != 0)
        return false;

    memset(&sslMetadata[hash], 0, sizeof(SSLMetadata));
    sslMetadata[hash].version = -1;

    return true;
}

uint64_t Mmap::SSL::getCurrentVersion()
{
    return systemMetadata[0].valueInt;
}

uint64_t Mmap::SSL::murmurHash64(const std::string &str, uint32_t seed)
{
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;

    uint64_t h = seed ^ (str.length() * m);

    const char *data = str.data();
    size_t nblocks = str.length() / 8;

    for (size_t i = 0; i < nblocks; i++)
    {
        uint64_t k;
        std::memcpy(&k, data + (i * 8), sizeof(uint64_t));

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char *data2 = reinterpret_cast<const unsigned char *>(data + (nblocks * 8));
    switch (str.length() & 7)
    {
    case 7:
        h ^= static_cast<uint64_t>(data2[6]) << 48;
        [[fallthrough]];
    case 6:
        h ^= static_cast<uint64_t>(data2[5]) << 40;
        [[fallthrough]];
    case 5:
        h ^= static_cast<uint64_t>(data2[4]) << 32;
        [[fallthrough]];
    case 4:
        h ^= static_cast<uint64_t>(data2[3]) << 24;
        [[fallthrough]];
    case 3:
        h ^= static_cast<uint64_t>(data2[2]) << 16;
        [[fallthrough]];
    case 2:
        h ^= static_cast<uint64_t>(data2[1]) << 8;
        [[fallthrough]];
    case 1:
        h ^= static_cast<uint64_t>(data2[0]);
        h *= m;
    };

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    return h % MAX_DATA_RECORDS;
}