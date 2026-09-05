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

        int thread = -1;

        std::string key;
        int fd = -1;
    } IoContext;

    typedef struct
    {
        /* ================== HTTP/3 ================== */
        quiche_config *config;

        std::array<uint8_t, 18> dcid;
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

        std::string key;
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

        Protocol protocol;

        std::thread::id id;

        ssize_t activeConnections = 0;

        ThreadWakeup wakeup;

        /* ============= H1 ============= */
        // FD -> Connection
        std::unordered_map<int, H1::Gen::H1Connection> h1connections;
        // FD -> SSL
        std::unordered_map<int, SslStructure> h1ssl;
        /* ============= H1 ============= */

        /* ============= H3 ============= */
        // Conn Key -> Connection
        std::unordered_map<std::string, H3::Gen::H3Connection> h3connections;
        // Conn Key -> SSL
        std::unordered_map<std::string, SslStructure> h3ssl;
        // Int -> Key
        std::unordered_map<uint32_t, H3::Gen::H3KeyPeer> h3keys;
        /* ============= H3 ============= */

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