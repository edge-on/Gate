#include "Mmap/SSL.hpp"

Mmap::SSL::~SSL()
{
    if (mmapBase)
        munmap(mmapBase, totalFileSize);
}

bool Mmap::SSL::init(const char *filepath)
{
    totalFileSize = MAX_DATA_RECORDS * sizeof(SSLMetadata);

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

    sslMetadata = reinterpret_cast<SSLMetadata *>(mmapBase);

    if (is_new_file)
    {
        freeListHeadIdx = 0;
        for (size_t i = 0; i < MAX_DATA_RECORDS; ++i)
        {
            CassUuid uuid;
            uuid.clock_seq_and_node = 0;
            uuid.time_and_version = 0;

            memset(sslMetadata[i].certificate, 0, sizeof(sslMetadata[i].certificate));
            memset(sslMetadata[i].privKey, 0, sizeof(sslMetadata[i].privKey));
            sslMetadata[i].version = -1;
        }
    }

    return true;
}

bool Mmap::SSL::getSSL(std::string domain)
{
    uint64_t hash = murmurHash64(domain);

    if (hash < 0 || hash > MAX_DATA_RECORDS)
        return false;

    return true;
}

bool Mmap::SSL::appendSSL(std::string domain, SSLMetadata data)
{
    uint64_t hash = murmurHash64(domain);

    if (hash < 0 || hash > MAX_DATA_RECORDS)
        return false;

    memcpy(sslMetadata[hash].domain, data.domain, strlen(data.domain));
    sslMetadata[hash].version = data.version;
    memcpy(sslMetadata[hash].certificate, data.domain, strlen(data.certificate));
    memcpy(sslMetadata[hash].privKey, data.domain, strlen(data.privKey));

    return true;
}

bool Mmap::SSL::deleteSSL(std::string domain)
{
    uint64_t hash = murmurHash64(domain);

    if (hash < 0 || hash > MAX_DATA_RECORDS)
        return false;

    memset(sslMetadata[hash].certificate, 0, sizeof(sslMetadata[hash].certificate));
    memset(sslMetadata[hash].privKey, 0, sizeof(sslMetadata[hash].privKey));
    sslMetadata[hash].version = -1;

    return true;
}

uint64_t Mmap::SSL::murmurHash64(const std::string &str, uint32_t seed = 42)
{
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;

    uint64_t h = seed ^ (str.length() * m);

    const uint64_t *data = reinterpret_cast<const uint64_t *>(str.data());
    const uint64_t *end = data + (str.length() / 8);

    while (data != end)
    {
        uint64_t k = *data++;

        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    const unsigned char *data2 = reinterpret_cast<const unsigned char *>(data);
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