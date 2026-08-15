#include "Maxmind/DB.hpp"

MMDB_s Maxmind::DB::mmdb;

void Maxmind::DB::init(const char *path)
{
    int status = MMDB_open(path, MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS)
        return;

    int fd = open(path, O_RDONLY);
    if (fd >= 0)
    {
        struct stat st{};
        if (fstat(fd, &st) == 0)
        {
            size_t size = st.st_size;
            size_t pagesize = sysconf(_SC_PAGESIZE);
            for (size_t offset = 0; offset < size; offset += pagesize)
            {
                volatile char *buf;
                pread(fd, &buf, 1, offset);
            }
        }
        close(fd);
    }
}

uint32_t Maxmind::DB::getVal(const char *val)
{
    uint32_t v;

    int gaiError, mmdbError;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, val, &gaiError, &mmdbError);

    if (gaiError != 0)
    {
        std::cerr << "Error: " << gai_strerror(gaiError) << std::endl;
    }
    else if (mmdbError != MMDB_SUCCESS)
    {
        std::cerr << "MMDB Lookup error: " << MMDB_strerror(mmdbError) << std::endl;
    }
    else if (result.found_entry)
    {
        MMDB_entry_data_s entryData;
        int status = MMDB_get_value(&result.entry, &entryData, "autonomous_system_number", NULL);

        if (status == MMDB_SUCCESS && entryData.has_data)
        {
            if (entryData.type == MMDB_DATA_TYPE_UINT32)
            {
                v = entryData.uint32;
            }
        }
    }

    return v;
}