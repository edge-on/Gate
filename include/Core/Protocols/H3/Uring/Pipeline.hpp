#pragma once

#include <liburing.h>
#include <iostream>

#include "Core/Gen/H3/Gen.hpp"
#include "Utils/Uring/H3/H3.hpp"
#include "Utils/Pages.hpp"

#include "Utils/Uring/Uring.hpp"
#include "Utils/Uring/BufferPool.hpp"

namespace Pipeline
{
    class H3
    {
    public:
        H3(struct io_uring *ring /* in */, int thread /* in */, int fd /* in */);

        void queueReadClient();
        void queueWriteClient(::H3::Gen::H3Connection &conn /* in */);
        void queueWriteClientCtx();

        void queueConnectOrigin(::H3::Gen::H3Connection &conn /* in */);
        void queueReadOrigin(::H3::Gen::H3Connection &conn /* in */);
        void queueWriteOrigin(::H3::Gen::H3Connection &conn /* in */);

        void queueConnectResolver(::H3::Gen::H3Connection &conn /* in */, char *ip /* in */);
        void queueWriteResolver(::H3::Gen::H3Connection &conn /* in */);
        void queueReadResolver(::H3::Gen::H3Connection &conn /* in */);

        Uring::BufferPool *pool;

    private:
        struct io_uring *ring;
        int thread;
        int fd;
    };
} // namespace Pipeline