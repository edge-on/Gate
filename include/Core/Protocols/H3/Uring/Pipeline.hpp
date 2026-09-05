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
        H3(struct io_uring *ring, int thread, int fd);

        void queueReadClient();
        void queueWriteClient(::H3::Gen::H3Connection &conn);
        void queueWriteClientCtx();

        void queueReadOrigin(::H3::Gen::H3Connection &conn);
        void queueWriteOrigin(::H3::Gen::H3Connection &conn);

        Uring::BufferPool *pool;

    private:
        struct io_uring *ring;
        int thread;
        int fd;
    };
} // namespace Pipeline