#include "Core/Protocols/H3/Uring/Pipeline.hpp"

Pipeline::H3::H3(struct io_uring *ring, int thread, int fd)
{
    this->ring = ring;
    this->thread = thread;
    this->fd = fd;

    pool = new Uring::BufferPool();
    pool->setup(this->ring, 1024 * 1024, 2048, 1, 32768);
}

void Pipeline::H3::queueReadClient()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_READ_CLIENT << 32) | (uint32_t)fd;

    conn.msgHdr.msg_namelen = sizeof(struct sockaddr_storage);
    conn.msgHdr.msg_controllen = 0;

    conn.buf_group = pool->pickGroup();

    io_uring_prep_recvmsg_multishot(sqe, conn.fd, &conn.msgHdr, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = (uint16_t)conn.buf_group;
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H3::queueWriteClient()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_WRITE_CLIENT << 32) | (uint32_t)fd;
    io_uring_sqe_set_data64(sqe, data);
}

void Pipeline::H3::queueReadOrigin()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_READ_ORIGIN << 32) | (uint32_t)fd;
    io_uring_sqe_set_data64(sqe, data);
}

void Pipeline::H3::queueWriteOrigin()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_WRITE_ORIGIN << 32) | (uint32_t)fd;
    io_uring_sqe_set_data64(sqe, data);
}