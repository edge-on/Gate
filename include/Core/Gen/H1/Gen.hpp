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

namespace H1
{
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
        } State;

        typedef enum
        {
            TCP_RAW,
            TCP_TLS,
            TCP_PENDING_SSL
        } ProtocolState;

        typedef struct
        {
            int fd = -1;
            int resolverFd = -1;
            int peerFd = -1;
            int thread = -1;
            int gen = -1;

            sockaddr_in originAddr{};

            int type;
            State lastOpType;
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
    };
}