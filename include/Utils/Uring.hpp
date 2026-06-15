#pragma once

#include <liburing.h>

namespace Utils
{
    class Uring
    {
    public:
        static struct io_uring_sqe *getSqe(struct io_uring *ring);
    };
} // namespace Utils
