#pragma once

#include <liburing.h>

#include <sys/socket.h>
#include <arpa/inet.h>

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
        // Socket
        STATE_ACCEPT_MULTISHOT,

        // Client
        STATE_TLS_CONNECTING,
        STATE_READ_CLIENT,
        STATE_WRITE_CLIENT,

        // Origin
        STATE_ORIGIN_CONNECTING,
        STATE_WRITE_ORIGIN,
        STATE_READ_ORIGIN,

        // DNS
        STATE_CONNECT_RESOLVER,
        STATE_WRITE_RESOLVER,
        STATE_READ_RESOLVER
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
        int resolverFd = -1;

        int peerFd = -1;

        sockaddr_in originAddr{};

        Type type;
        State lastOpType;
        Protocol protocol;
        ProtocolState protocolState;

        int writeOffset = 0;

        bool backendIsUnreachable = false;

        bool isWritingClient = false;

        bool isReadingClient = false;
        bool isReadingOrigin = false;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;

        char resolverPacket[512];
        std::string host;

        std::list<std::pair<std::array<char, BUFFER_SIZE>, int>> writeQueue;
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

        ssize_t bandwith = 0;

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