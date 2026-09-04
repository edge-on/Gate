#pragma once

#include <cstring>
#include <cstdint>
#include <queue>
#include <sys/socket.h>

#include <quiche.h>

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

        typedef enum
        {
            ASSIGNED,
            INGRESS
        } DCIDType;

        typedef struct
        {
            uint32_t streamId;

            int state;

            std::string peerDcid;

            bool missingSni = false;
            char resolverPacket[512];

            std::string host;
            std::string domain;

            Zone *zone = nullptr;

            struct msghdr msg{};
            struct iovec iov;

            quiche_send_info sendInfo;
            quiche_conn *conn;

            DCIDType dcidType;
        } H3Connection;

        typedef struct
        {
            int bufGroup;
            struct msghdr msgHdr;
        } ThreadUDPConfig;

        inline static thread_local ThreadUDPConfig localUdpConfig;

        enum quichePktType
        {
            QUICHE_PACKET_TYPE_INITIAL = 1,
            QUICHE_PACKET_TYPE_RETRY = 2,
            QUICHE_PACKET_TYPE_HANDSHAKE = 3,
            QUICHE_PACKET_TYPE_ZERO_RTT = 4,
            QUICHE_PACKET_TYPE_SHORT = 5,
            QUICHE_PACKET_TYPE_VERSION_NEGOTIATION = 6,
        };
    };
} // namespace Gen