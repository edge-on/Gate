#include "Core/Protocols/H1/Uring/Pipeline.hpp"

Pipeline::H1::H1(struct io_uring *ring, int thread)
{
    this->ring = ring;
    this->thread = thread;
}

void Pipeline::H1::queueMultishotAccept(int serverFd)
{
    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_ACCEPT_MULTISHOT << 32) | (uint32_t)serverFd;
    io_uring_prep_multishot_accept(sqe, serverFd, nullptr, nullptr, SOCK_NONBLOCK);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueTlsConnecting(Gen::H1::H1Connection &conn)
{
    if (conn.isReadingClient)
        return;

    if (Gen::Global::activeThreads[thread].ssl[conn.fd].handshakeDone)
        return;

    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingClient = true;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_TLS_CONNECTING << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.fd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueReadClient(Gen::H1::H1Connection &conn)
{
    if (conn.isReadingClient)
        return;

    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingClient = true;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_READ_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.fd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueConnectOrigin(Gen::H1::H1Connection &originConn)
{
    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_ORIGIN_CONNECTING << 32) | (uint32_t)originConn.peerFd;
    io_uring_prep_connect(sqe, originConn.fd,
                          (struct sockaddr *)&originConn.originAddr,
                          sizeof(originConn.originAddr));
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueWriteOrigin(Gen::H1::H1Connection &conn)
{
    if (conn.writeOriginQueue.empty())
        return;

    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    auto &front = conn.writeOriginQueue.front();

    char *src = front.first.data();
    ssize_t len = front.second;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_WRITE_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.peerFd, src + conn.writeOriginOffset, len - conn.writeOriginOffset, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueReadOrigin(Gen::H1::H1Connection &conn)
{
    if (conn.isReadingOrigin)
        return;

    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    conn.isReadingOrigin = true;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_READ_ORIGIN << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.peerFd, conn.out_plain_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueWriteClient(Gen::H1::H1Connection &conn)
{
    if (conn.writeQueue.empty())
        return;

    struct io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    auto &front = conn.writeQueue.front();

    char *src = front.first.data();
    ssize_t len = front.second;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_WRITE_CLIENT << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.fd, src + conn.writeOffset, len - conn.writeOffset, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueConnectResolver(Gen::H1::H1Connection &conn, char *ip)
{
    io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    sockaddr_in addr{};
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_CONNECT_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_connect(sqe, conn.resolverFd, (sockaddr *)&addr, sizeof(addr));
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueWriteResolver(Gen::H1::H1Connection &conn)
{
    io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_WRITE_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_write(sqe, conn.resolverFd, conn.resolverPacket, conn.out_len, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::queueReadResolver(Gen::H1::H1Connection &conn)
{
    io_uring_sqe *sqe = Utils::H1::Uring::getSqe(ring);
    if (!sqe)
        return;

    uint64_t data = ((uint64_t)Gen::H1::H1_STATE_READ_RESOLVER << 32) | (uint32_t)conn.fd;
    io_uring_prep_recv(sqe, conn.resolverFd, conn.in_raw_buffer, BUFFER_SIZE, 0);
    io_uring_sqe_set_data(sqe, (void *)data);
}

void Pipeline::H1::writePage(Gen::H1::H1Connection &conn, std::string p)
{
    conn.pendingClose = true;

    std::string page = Pages::getPage("pages/" + p + ".html");

    std::string req =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
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

        if (Gen::Global::activeThreads[thread].ssl[conn.fd].handshakeDone)
        {
            auto &ssl = Gen::Global::activeThreads[thread].ssl[conn.fd];
            int written = 0;
            while (written < len)
            {
                int r = SSL_write(ssl.ssl, req.data() + offset + written, len - written);
                if (r <= 0)
                {
                    int err = SSL_get_error(ssl.ssl, r);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                        break;
                    continue;
                }
                written += r;
            }
            int bytes = BIO_read(ssl.wbio, chunk.first.data(), BUFFER_SIZE);
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