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

        void queueReadClient(uint32_t dcid);
        void queueWriteClient();

        void queueReadOrigin();
        void queueWriteOrigin();

        Uring::BufferPool *pool;

    private:
        struct io_uring *ring;
        int thread;
        int fd;
    };
} // namespace Pipeline