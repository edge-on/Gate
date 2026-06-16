#include "Core/Uring/Pipeline.hpp"

Pipeline::Pipeline(struct io_uring *ring, int thread)
{
    this->ring = ring;
    this->thread = thread;
}

void Pipeline::queueMultishotAccept(int serverFd)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_ACCEPT_MULTISHOT << 32) | (uint32_t)serverFd;
    io_uring_prep_multishot_accept(sqe, serverFd, nullptr, nullptr, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueReadClient(Gen::Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_READ_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_read(sqe, conn.fd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueWriteOrigin(Gen::Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_WRITE_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.fd, conn.in_plain_buffer, conn.in_len, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueReadOrigin(Gen::Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_READ_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_read(sqe, conn.fd, conn.in_plain_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueWriteClient(Gen::Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_WRITE_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.fd, conn.out_raw_buffer, conn.out_len, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queuePollAdd(Gen::Connection &conn)
{
}