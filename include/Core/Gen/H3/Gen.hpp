#pragma once

#include <cstring>
#include <cstdint>
#include <queue>
#include <sys/socket.h>

#include "Core/Gen/ZoneMap.hpp"

#define LOCAL_CONN_ID_LEN 16
#define MAX_DATAGRAM_SIZE 1350

namespace H3
{
    class Gen
    {
    public:
        typedef enum
        {
            /* ================ HTTP/3 ================ */
            // Client
            H3_STATE_READ_CLIENT = 10,
            H3_STATE_WRITE_CLIENT = 11,

            // Origin
            H3_STATE_ORIGIN_CONNECTING = 12,
            H3_STATE_READ_ORIGIN = 13,
            H3_STATE_WRITE_ORIGIN = 14
            /* ================ HTTP/3 ================ */
        } State;

        typedef struct
        {
            uint32_t streamId;

            int state;

            bool missingSni = false;
            char resolverPacket[512];
            std::string host;

            std::string domain;
            Zone *zone = nullptr;

            struct msghdr msg{};
            struct iovec iov;
            quiche_send_info send_info;
        } H3Connection;

        typedef struct
        {
            int bufGroup;
            struct msghdr msgHdr;
        } ThreadUDPConfig;

        inline static thread_local ThreadUDPConfig localUdpConfig;
    };
} // namespace Gen