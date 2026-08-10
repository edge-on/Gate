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
    io_uring_prep_multishot_accept(sqe, serverFd, nullptr, nullptr, SOCK_NONBLOCK);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueTlsConnecting(Gen::Connection &conn)
{
    if (conn.isReadingClient)
        return;

    if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
        return;

    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingClient = true;

    uint64_t data = ((uint64_t)Gen::STATE_TLS_CONNECTING << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.fd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueReadClient(Gen::Connection &conn)
{
    if (conn.isReadingClient)
        return;

    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingClient = true;

    uint64_t data = ((uint64_t)Gen::STATE_READ_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.fd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueConnectOrigin(Gen::Connection &originConn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_ORIGIN_CONNECTING << 32) | (uint32_t)originConn.peerFd;
    io_uring_prep_connect(sqe, originConn.fd,
                          (struct sockaddr *)&originConn.originAddr,
                          sizeof(originConn.originAddr));
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueWriteOrigin(Gen::Connection &conn)
{
    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    // If thats an TLS request, we will take the plain buffer becase of decrypting
    // If thats an Raw request, we will take the raw buffer, becase there's no decrypting
    auto *src = (conn.protocolState == Gen::TCP_TLS ? conn.in_plain_buffer : conn.in_raw_buffer);

    uint64_t data = ((uint64_t)Gen::STATE_WRITE_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.peerFd, src, conn.in_len, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueReadOrigin(Gen::Connection &conn)
{
    if (conn.isReadingOrigin)
        return;

    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingOrigin = true;

    uint64_t data = ((uint64_t)Gen::STATE_READ_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.peerFd, conn.out_plain_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueWriteClient(Gen::Connection &conn)
{
    if (conn.writeQueue.empty())
        return;

    struct io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    auto &front = conn.writeQueue.front();

    char *src = front.first.data();
    ssize_t len = front.second;

    uint64_t data = ((uint64_t)Gen::STATE_WRITE_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.fd, src + conn.writeOffset, len - conn.writeOffset, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueConnectResolver(Gen::Connection &conn)
{
    io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    sockaddr_in addr{};
    addr.sin_addr.s_addr = inet_addr(Main::resolverIp);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);

    uint64_t data = ((uint64_t)Gen::STATE_CONNECT_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_connect(sqe, conn.resolverFd, (sockaddr *)&addr, sizeof(addr));
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueWriteResolver(Gen::Connection &conn)
{
    io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_WRITE_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.resolverFd, conn.resolverPacket, conn.out_len, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::queueReadResolver(Gen::Connection &conn)
{
    io_uring_sqe *sqe = Utils::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::STATE_READ_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.resolverFd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::write502Page(Gen::Connection &conn)
{
    std::string page = Pages::getPage("pages/502.html");

    std::string req =
        "HTTP/1.1 502 Bad Gateway\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: " +
        std::to_string(page.size()) + "\r\n"
                                      "Connection: close\r\n"
                                      "Server: EdgeOn-Proxy/1.0\r\n"
                                      "\r\n" +
        page;

    int offset = 0;
    while (offset < (int)req.size())
    {
        ssize_t len = std::min(BUFFER_SIZE - 256, int(req.size() - offset));

        std::pair<std::array<char, BUFFER_SIZE>, int> chunk;

        if (Gen::activeThreads[thread].ssl[conn.fd].handshakeDone)
        {
            SSL_write(Gen::activeThreads[thread].ssl[conn.fd].ssl, req.data() + offset, len);
            int bytes = BIO_read(Gen::activeThreads[thread].ssl[conn.fd].wbio, chunk.first.data(), BUFFER_SIZE);
            chunk.second = bytes;
        }
        else
        {
            memcpy(chunk.first.data(), req.data() + offset, len);
            chunk.second = len;
        }

        conn.writeQueue.push_back(std::move(chunk));

        offset += len;
    }
}