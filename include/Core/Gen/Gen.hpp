#pragma once

#include <liburing.h>

#include <thread>
#include <unordered_map>
#include <vector>

#define BUFFER_SIZE 16384
#define QUEUE_DEPTH 4096

class Gen
{
public:
    typedef enum
    {
        STATE_ACCEPT_MULTISHOT,
        STATE_TLS_CONNECTING,
        STATE_READ_CLIENT,
        STATE_WRITE_ORIGIN,
        STATE_READ_ORIGIN,
        STATE_WRITE_CLIENT,
        STATE_POLL_ADD
    } State;

    typedef enum
    {
        H2,
        H1
    } Protocol;

    typedef enum
    {
        TYPE_CLIENT,
        TYPE_ORIGIN
    } Type;

    typedef struct
    {
        int fd = -1;
        int peerFd = -1;

        Type type;
        Protocol protocol;
        State lastOpType;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;
    } Connection;

    typedef struct
    {
        SSL *ssl;
        BIO *rbio;
        BIO *wbio;

        bool handshakeDone = false;
    } SslStructure;

    typedef struct
    {
        std::thread::id id;

        // FD -> Connection
        std::unordered_map<int, Connection> connections;
        // FD -> SSL
        std::unordered_map<int, SslStructure> ssl;

        struct io_uring ring;

        // Port -> FD
        std::unordered_map<int, int> listeners;

        bool isShutdown = false;
    } Thread;

    static std::vector<std::thread> threads;
    static std::unordered_map<int, Thread> activeThreads;
};