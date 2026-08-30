#pragma once

#include <cstring>
#include <cstdint>
#include <queue>
#include <sys/socket.h>

#include "Core/Gen/Gen.hpp"

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
            H3_STATE_READ_CLIENT,
            H3_STATE_WRITE_CLIENT,

            // Origin
            H3_STATE_ORIGIN_CONNECTING,
            H3_STATE_READ_ORIGIN,
            H3_STATE_WRITE_ORIGIN
            /* ================ HTTP/3 ================ */
        } State;

        typedef struct
        {
            uint32_t streamId;

            State state;
        } H3Connection;

        typedef struct
        {
            int bufGroup;
            struct msghdr msgHdr;
        } ThreadUDPConfig;

        inline static thread_local ThreadUDPConfig localUdpConfig;
    };
} // namespace Gen