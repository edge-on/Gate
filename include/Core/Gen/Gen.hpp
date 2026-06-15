#pragma once

#include <thread>
#include <unordered_map>
#include <vector>

#define BUFFER_SIZE (1024 * 16)
#define QUEUE_DEPTH 8192

class Gen
{
public:
    typedef enum
    {
        STATE_ACCEPT_MULTSHOT,
        STATE_READ_CLIENT,
        STATE_WRITE_CLIENT,
        STATE_POLL_ADD
    } State;

    typedef struct
    {
        int fd;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;
    } Connection;

    typedef struct
    {
        std::thread::id id;
        std::unordered_map<int, Connection> connections;

        struct io_uring *ring;

        bool isShutdown = false;
    } Thread;

    static std::vector<std::thread> threads;
    static std::unordered_map<int, Thread> activeThreads;
};