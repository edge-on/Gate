#include "Utils/Uring.hpp"

struct io_uring_sqe *Utils::Uring::getSqe(struct io_uring *ring)
{
    if (!ring)
        return nullptr;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
    {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    return sqe;
}