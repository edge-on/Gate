#pragma once

#include <liburing.h>

#include "Core/Ssl/Ssl.hpp"

#include <thread>
#include <unordered_map>
#include <vector>
#include <array>
#include <list>
#include <utility>

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

    typedef enum
    {
        TCP_RAW,
        TCP_TLS
    } ProtocolState;

    typedef struct
    {
        int fd = -1;
        int peerFd = -1;

        Type type;
        State lastOpType;
        Protocol protocol;
        ProtocolState protocolState;

        int writeOffset = 0;

        bool backendIsUnreachable = false;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;

        std::list<std::pair<std::array<char, BUFFER_SIZE>, int>> writeQueue;
    } Connection;

    typedef struct
    {
        SSL *ssl;
        BIO *rbio;
        BIO *wbio;

        bool handshakeDone = false;

        size_t writeOffset;
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

    typedef struct
    {
        std::string domain;

        SSL_CTX *ctx;
    } Zone;

    static std::unordered_map<std::string, Zone> zones;
};