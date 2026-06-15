#pragma once

#include <liburing.h>
#include <stdio.h>

namespace Utils
{
    class Uring
    {
    public:
        static struct io_uring_sqe *getSqe(struct io_uring *ring);

        static void makeNonBlocking(int fd);
    };
} // namespace Utils
