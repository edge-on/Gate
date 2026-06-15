#pragma once

#include <thread>
#include <unordered_map>
#include <vector>

#define BUFFER_SIZE (1024 * 16)

class Gen
{
public:
    typedef struct
    {
        int fd;
    } Connection;

    typedef struct
    {
        std::thread::id id;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;

        std::unordered_map<int, Connection> connections;
    } Thread;

    static std::vector<std::thread> threads;
    static std::unordered_map<int, Thread> activeThreads;
};