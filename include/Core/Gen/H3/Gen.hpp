#pragma once

#include <cstring>
#include <cstdint>
#include <queue>
#include <sys/socket.h>

#include <list>
#include <array>

#include <quiche.h>

#include "Core/Gen/ZoneMap.hpp"

#include "Core/Gen/Defines.hpp"

namespace H3
{
    class Gen
    {
    public:
        typedef enum
        {
            /* ================ HTTP/3 ================ */
            // Client
            H3_STATE_READ_CLIENT = 300,
            H3_STATE_WRITE_CLIENT = 301,
            H3_STATE_WRITE_CLIENT_CONNECTIONLESS = 302,

            // Origin
            H3_STATE_ORIGIN_CONNECTING = 310,
            H3_STATE_READ_ORIGIN = 311,
            H3_STATE_WRITE_ORIGIN = 312
            /* ================ HTTP/3 ================ */
        } State;

        typedef enum
        {
            ASSIGNED,
            INGRESS
        } DCIDType;

        typedef struct
        {
            struct msghdr msg{};
            struct iovec iov;
            quiche_send_info sendInfo;

            uint8_t out[DATAGRAM_SIZE];
        } Response;

        typedef struct
        {
            uint32_t streamId;

            int threadId;

            uint32_t keyPeering;

            std::string key;
            std::string peerDcid;

            bool missingSni = false;
            bool established = false;
            char resolverPacket[512];

            bool writeInFlight = false;

            std::string host;
            std::string domain;

            Zone *zone = nullptr;

            DCIDType dcidType;

            quiche_conn *conn;
            quiche_h3_conn *h3;

            // Buffer Pools
            std::list<std::pair<std::array<char, DATAGRAM_SIZE>, int>> readQueue;
            std::list<Response> writeQueue;
        } H3Connection;

        typedef struct
        {
            struct msghdr msg{};
            struct iovec iov;

            struct sockaddr_storage peerAddrStorage;

            uint8_t out[DATAGRAM_SIZE];
        } ConnectionlessH3Context;

        typedef struct
        {
            std::string key;
        } H3KeyPeer;

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

        typedef struct
        {
            uint32_t version = 0;
            uint8_t type = 0;

            uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
            size_t scidLen = sizeof(scid);

            uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
            size_t dcidLen = sizeof(dcid);

            uint8_t token[256];
            size_t tokenLen = sizeof(token);
        } HdrInfoCtx;

        typedef struct {
            std::string method;
            std::string host;
            std::string path;

            std::vector<std::string> headers;
        } RecvIOCtx;
    };
} // namespace Gen