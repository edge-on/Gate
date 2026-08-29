#include "Core/Protocols/H3/Uring/Pipeline.hpp"

Pipeline::H3::H3(struct io_uring *ring, int thread, int fd)
{
    this->ring = ring;
    this->thread = thread;
    this->fd = fd;
}

void Pipeline::H3::queueReadClient()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    io_uring_prep_recv_multishot(sqe, fd, nullptr, BUFFER_SIZE, 0);
    uint64_t data = (uint64_t)::H3::Gen::H3_STATE_READ_CLIENT;
    io_uring_sqe_set_data64(sqe, data);
}

void Pipeline::H3::queueWriteClient()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = (uint64_t)::H3::Gen::H3_STATE_WRITE_CLIENT;
    io_uring_sqe_set_data64(sqe, data);
}

void Pipeline::H3::queueReadOrigin()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = (uint64_t)::H3::Gen::H3_STATE_READ_ORIGIN;
    io_uring_sqe_set_data64(sqe, data);
}

void Pipeline::H3::queueWriteOrigin()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = (uint64_t)::H3::Gen::H3_STATE_WRITE_ORIGIN;
    io_uring_sqe_set_data64(sqe, data);
}