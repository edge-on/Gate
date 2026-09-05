#include "Core/Protocols/H3/Uring/Pipeline.hpp"

Pipeline::H3::H3(struct io_uring *ring, int thread, int fd)
{
    this->ring = ring;
    this->thread = thread;
    this->fd = fd;

    ::H3::Gen::localUdpConfig.msgHdr.msg_name = nullptr;
    ::H3::Gen::localUdpConfig.msgHdr.msg_namelen = sizeof(struct sockaddr_storage);
    ::H3::Gen::localUdpConfig.msgHdr.msg_controllen = 0;

    pool = new Uring::BufferPool();
    pool->setup(this->ring, 1024 * 1024, 2048, 1, 32768);
}

void Pipeline::H3::queueReadClient()
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    ::H3::Gen::localUdpConfig.bufGroup = pool->pickGroup();

    ::H3::Gen::localUdpConfig.msgHdr.msg_namelen = sizeof(struct sockaddr_in);
    ::H3::Gen::localUdpConfig.msgHdr.msg_controllen = 0;

    io_uring_prep_recvmsg_multishot(sqe, fd, &::H3::Gen::localUdpConfig.msgHdr, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = (uint16_t)::H3::Gen::localUdpConfig.bufGroup;
    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_READ_CLIENT << 32) | (uint32_t)0;
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H3::queueWriteClient(::H3::Gen::H3Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    auto &front = conn.writeQueue.front();

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_WRITE_CLIENT << 32) | (uint32_t)conn.keyPeering;
    io_uring_prep_sendmsg(sqe, fd, &front.msg, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H3::queueReadOrigin(::H3::Gen::H3Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_READ_ORIGIN << 32) | (uint32_t)0;
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H3::queueWriteOrigin(::H3::Gen::H3Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)::H3::Gen::H3_STATE_WRITE_ORIGIN << 32) | (uint32_t)0;
    // io_uring_prep_sendmsg(sqe, fd, &conn.msg, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}