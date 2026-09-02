#pragma once

#include <quiche.h>
#include <map>

#include "Core/Gen/H1/Gen.hpp"
#include "Core/Gen/H3/Gen.hpp"

class Gen
{
public:
    typedef enum
    {
        STATE_TLS_WAKEUP = 15
    } State;

    typedef enum
    {
        CONTINUE,
        BREAK
    };

    typedef enum
    {
        TYPE_CLIENT,
        TYPE_ORIGIN
    } Type;

    typedef enum
    {
        H1,
        H3
    } Protocol;

    typedef struct
    {
        Protocol protocol;

        H1::Gen::H1Connection *h1conn;
        H3::Gen::H3Connection *h3conn;
    } IoContext;

    typedef struct
    {
        /* ================== HTTP/3 ================== */
        quiche_config *config;

        int dcid = -1;
        /* ================== HTTP/3 ================== */

        /* ================== HTTP/1.1 ================== */
        SSL *ssl;
        BIO *rbio;
        BIO *wbio;

        bool handshakeDone = false;
        /* ================== HTTP/1.1 ================== */

        IoContext ioCtx;
    } SslStructure;

    typedef struct
    {
        int connFd;
        int gen = 0;
    } Generation;

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
        int udpFd = -1;

        std::thread::id id;

        ssize_t activeConnections = 0;

        ThreadWakeup wakeup;

        // FD -> Connection
        std::unordered_map<int, H1::Gen::H1Connection> h1connections;
        // DCID -> Connection
        std::map<std::array<char, 18>, H3::Gen::H3Connection> h3connections;

        // FD -> SSL
        std::unordered_map<int, SslStructure> h1ssl;
        // DCID -> SSL
        std::map<std::array<char, 18>, SslStructure> h3ssl;

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