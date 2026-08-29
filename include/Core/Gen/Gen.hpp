#pragma once

#include <liburing.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <thread>
#include <unordered_map>
#include <vector>
#include <array>
#include <list>
#include <utility>

#include <sys/eventfd.h>

#include <string>
#include <openssl/ssl.h>
#include <mutex>
#include <atomic>

#include <deque>

#include "Core/Gen/ZoneMap.hpp"

#define BUFFER_SIZE 16384
#define QUEUE_DEPTH 4096

class Gen
{
public:
    typedef enum
    {
        /* ================ HTTP/1.1 ================ */
        // Socket
        H1_STATE_ACCEPT_MULTISHOT,

        // Client
        H1_STATE_TLS_CONNECTING,
        H1_STATE_READ_CLIENT,
        H1_STATE_WRITE_CLIENT,

        // Origin
        H1_STATE_ORIGIN_CONNECTING,
        H1_STATE_WRITE_ORIGIN,
        H1_STATE_READ_ORIGIN,

        // DNS
        H1_STATE_CONNECT_RESOLVER,
        H1_STATE_WRITE_RESOLVER,
        H1_STATE_READ_RESOLVER,

        // TLS
        H1_STATE_TLS_WAKEUP,
        /* ================ HTTP/1.1 ================ */

        /* ================ HTTP/3 ================ */
        // Client
        H3_STATE_READ_CLIENT,
        H3_STATE_WRITE_CLIENT,

        // Origin
        H3_STATE_ORIGIN_CONNECTING,
        H3_STATE_READ_ORIGIN,
        H3_STATE_WRITE_ORIGIN
        /* ================ HTTP/3 ================ */
    } State;

    typedef enum
    {
        CONTINUE,
        BREAK
    };

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
        TCP_TLS,
        TCP_PENDING_SSL
    } ProtocolState;

    struct PendingTlsResumeItem
    {
        int thread;
        int fd;
        bool success;
    };

    struct ThreadWakeup
    {
        int eventFd = -1;
        std::mutex queueMutex;
        std::deque<PendingTlsResumeItem> resumeQueue;

        void init()
        {
            eventFd = eventfd(0, EFD_NONBLOCK);
        }

        void push(PendingTlsResumeItem item)
        {
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                resumeQueue.push_back(item);
            }
            uint64_t one = 1;
            write(eventFd, &one, sizeof(one));
        }

        std::deque<PendingTlsResumeItem> drain()
        {
            uint64_t val;
            read(eventFd, &val, sizeof(val));

            std::deque<PendingTlsResumeItem> out;
            {
                std::lock_guard<std::mutex> lock(queueMutex);
                out.swap(resumeQueue);
            }
            return out;
        }
    };

    using Zone = ::Zone;

    typedef struct
    {
        int fd = -1;
        int resolverFd = -1;
        int peerFd = -1;
        int thread = -1;
        int gen = -1;

        sockaddr_in originAddr{};

        Type type;
        State lastOpType;
        Protocol protocol;
        ProtocolState protocolState;

        int writeOffset = 0;
        int writeOriginOffset = 0;

        bool backendIsUnreachable = false;

        bool isWritingClient = false;
        bool isWritingOrigin = false;

        bool isReadingClient = false;
        bool isReadingOrigin = false;

        bool isConnectedOrigin = false;

        bool isBlocked = false;
        bool pendingClose = false;

        bool missingSni = false;

        char in_raw_buffer[BUFFER_SIZE];
        char in_plain_buffer[BUFFER_SIZE];
        ssize_t in_len = 0;

        char out_raw_buffer[BUFFER_SIZE];
        char out_plain_buffer[BUFFER_SIZE];
        ssize_t out_len = 0;

        char resolverPacket[512];
        std::string host;

        std::string domain;
        Zone *zone = nullptr;

        std::list<std::pair<std::array<char, BUFFER_SIZE>, int>> writeQueue;
        std::list<std::pair<std::array<char, BUFFER_SIZE>, int>> writeOriginQueue;
    } H1Connection;

    typedef struct
    {
        int connFd;
        int gen = 0;
    } Generation;

    typedef struct
    {
        SSL *ssl;
        BIO *rbio;
        BIO *wbio;

        bool handshakeDone = false;
    } SslStructure;

    typedef struct
    {
        int udpFd = -1;
        
        std::thread::id id;

        ssize_t activeConnections = 0;

        ThreadWakeup wakeup;

        // FD -> Connection
        std::unordered_map<int, H1Connection> connections;
        // FD -> SSL
        std::unordered_map<int, SslStructure> ssl;
        // FD -> Gen
        std::unordered_map<int, Generation> generations;

        struct io_uring ring;

        // Port -> FD
        std::unordered_map<int, int> listeners;

        bool isShutdown = false;
    } Thread;

    static std::vector<std::thread> threads;
    static std::unordered_map<int, Thread> activeThreads;

    static ZoneMap zones;
};