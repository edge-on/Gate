#include "Core/EdgeServer.hpp"

EdgeServer::EdgeServer()
{
}

void EdgeServer::start()
{
    initSSL();

    initClientServer();

    startWorkers();
}

void EdgeServer::initClientServer()
{
    client_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (client_listen == -1)
    {
        perror("client socket");
    }

    sockaddr_in client_addr;
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(client_port);

    int opt = 1;
    setsockopt(client_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(client_listen, (sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        perror("client bind");
    }

    if (listen(client_listen, SOMAXCONN) < 0)
    {
        perror("client listen");
    }

    EpollUtility::makeNonBlocking(client_listen);
}

void EdgeServer::initSSL()
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate_file(ctx, "SSL/localhost.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "SSL/localhost-key.pem", SSL_FILETYPE_PEM);

    bridge_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_PrivateKey_file(bridge_ctx, "SSL/localhost-key.pem", SSL_FILETYPE_PEM);
}

void EdgeServer::startWorkers()
{
    epoll_fd = epoll_create1(0);

    epoll_event client_event{};
    client_event.events = EPOLLIN | EPOLLET;
    client_event.data.fd = client_listen;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_listen, &client_event) < 0)
    {
        perror("epoll_ctl");
    }

    epoll_event events[MAX_EVENTS];

    while (true)
    {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < n; ++i)
        {
            if (events[i].data.fd == client_listen)
            {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);

                while (true)
                {
                    int client_fd = accept(client_listen, (sockaddr *)&client_addr, &client_len);
                    if (client_fd == -1)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            break;
                        }
                        else
                        {
                            perror("accept");
                            break;
                        }
                    }

                    EpollUtility::makeNonBlocking(client_fd);

                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, client_fd);
                    SSL_set_accept_state(ssl);

                    int bridge_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (bridge_fd == -1)
                    {
                        perror("bridge bridge");
                    }

                    EpollUtility::makeNonBlocking(bridge_fd);

                    SSL *bridge_ssl = SSL_new(bridge_ctx);
                    SSL_set_fd(bridge_ssl, bridge_fd);
                    SSL_set_connect_state(bridge_ssl);

                    sockaddr_in bridge_addr;
                    bridge_addr.sin_family = AF_INET;
                    bridge_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
                    bridge_addr.sin_port = htons(bridge_port);

                    int ret = connect(bridge_fd,
                                      (sockaddr *)&bridge_addr,
                                      sizeof(bridge_addr));

                    if (ret == -1)
                    {
                        if (errno != EINPROGRESS)
                        {
                            perror("bridge connect");
                        }
                    }

                    epoll_event bridge_event{};
                    bridge_event.events = EPOLLOUT | EPOLLET;
                    bridge_event.data.fd = bridge_fd;

                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bridge_fd, &bridge_event) < 0)
                    {
                        perror("epoll_ctl");
                    }

                    Connection bridge;
                    bridge.fd = bridge_fd;
                    bridge.peer_fd = client_fd;
                    bridge.ssl = bridge_ssl;
                    bridge.type = ConnType::BRIDGE;
                    bridge.handshake_done = false;

                    connections.emplace(bridge_fd, std::move(bridge));

                    Connection conn;
                    conn.fd = client_fd;
                    conn.ssl = ssl;
                    conn.peer_fd = bridge_fd;
                    conn.type = ConnType::CLIENT;
                    conn.handshake_done = false;

                    connections.emplace(client_fd, std::move(conn));

                    epoll_event client_event{};
                    client_event.events = EPOLLIN | EPOLLET;
                    client_event.data.fd = client_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);
                }
            }
            else
            {
                auto it = connections.find(events[i].data.fd);
                if (it == connections.end())
                    continue;

                Connection &conn = it->second;

                if (conn.type == ConnType::BRIDGE && !conn.tcp_connected)
                {
                    if (events[i].events & EPOLLOUT)
                    {
                        int err = 0;
                        socklen_t len = sizeof(err);

                        getsockopt(conn.fd, SOL_SOCKET, SO_ERROR, &err, &len);

                        if (err == 0)
                        {
                            conn.tcp_connected = true;

                            EpollUtility::enableWrite(conn.fd, epoll_fd);
                        }
                        else
                        {
                            closeConnection(conn);
                        }
                    }

                    continue;
                }

                if (!conn.handshake_done)
                {
                    int ret;

                    if (conn.type == ConnType::CLIENT)
                        ret = SSL_accept(conn.ssl);
                    else
                        ret = SSL_connect(conn.ssl);

                    if (ret == 1)
                    {
                        conn.handshake_done = true;

                        EpollUtility::disableWrite(conn.fd, epoll_fd);
                    }
                    else
                    {
                        int err = SSL_get_error(conn.ssl, ret);

                        if (err == SSL_ERROR_WANT_READ ||
                            err == SSL_ERROR_WANT_WRITE)
                            continue;

                        closeConnection(conn);
                    }

                    continue;
                }

                if (events[i].events & EPOLLIN)
                    handleRead(conn);

                if (events[i].events & EPOLLOUT)
                    handleWrite(conn);
            }
        }
    }

    close(client_listen);
}

int EdgeServer::handleRead(Connection &conn)
{
    char buffer[4096];

    std::string head = conn.type == ConnType::BRIDGE ? "Bridge Read: " : "Client Read: ";

    while (true)
    {
        int bytes = SSL_read(conn.ssl, buffer, sizeof(buffer));

        if (bytes > 0)
        {
            auto it = connections.find(conn.peer_fd);
            if (it == connections.end())
                return -1;

            std::cout << head;
            std::cout.write(buffer, bytes);
            std::cout << "\n";

            Connection &peer = it->second;
            peer.out_buffer.append(buffer, bytes);

            if (handleWrite(peer) == 0)
            {
                EpollUtility::enableWrite(peer.fd, epoll_fd);
            }
        }
        else
        {
            int err = SSL_get_error(conn.ssl, bytes);

            if (err == SSL_ERROR_WANT_READ ||
                err == SSL_ERROR_WANT_WRITE)
                break;

            closeConnection(conn);
            return -1;
        }
    }

    return 1;
}

int EdgeServer::handleWrite(Connection &conn)
{
    std::string head = conn.type == ConnType::BRIDGE ? "Bridge Write: " : "Client Write: ";

    std::cout << head << conn.write_offset << std::endl;
    std::cout << head << conn.out_buffer.size() << std::endl;

    while (conn.write_offset < conn.out_buffer.size())
    {
        int written = SSL_write(
            conn.ssl,
            conn.out_buffer.data() + conn.write_offset,
            conn.out_buffer.size() - conn.write_offset);

        std::cout << head;
        std::cout.write(conn.out_buffer.data(), conn.out_buffer.size());
        std::cout << "\n";

        if (written > 0)
        {
            conn.write_offset += written;
        }
        else
        {
            int err = SSL_get_error(conn.ssl, written);

            if (err == SSL_ERROR_WANT_WRITE ||
                err == SSL_ERROR_WANT_READ)
                return 0;

            closeConnection(conn);
            return -1;
        }
    }

    if (conn.write_offset == conn.out_buffer.size())
    {
        conn.out_buffer.clear();
        conn.write_offset = 0;
        EpollUtility::disableWrite(conn.fd, epoll_fd);
    }

    return 1;
}

void EdgeServer::closeConnection(Connection &conn)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn.fd, nullptr);

    SSL_shutdown(conn.ssl);
    SSL_free(conn.ssl);
    close(conn.fd);

    int peer = conn.peer_fd;

    connections.erase(conn.fd);

    auto it = connections.find(peer);
    if (it != connections.end())
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, peer, nullptr);
        SSL_shutdown(it->second.ssl);
        SSL_free(it->second.ssl);
        close(it->second.fd);
        connections.erase(peer);
    }
}

void EdgeServer::sendCommand(Connection &conn, int &cmd, std::string &payload)
{
    uint32_t len = htonl(payload.size());

    uint8_t c = static_cast<uint8_t>(cmd);
    conn.out_buffer.push_back(static_cast<char>(c));
    conn.out_buffer.append(reinterpret_cast<char *>(&len), 4);
    conn.out_buffer.append(payload);

    EpollUtility::enableWrite(conn.fd, epoll_fd);
}

EdgeServer &EdgeServer::setPort(int PORT)
{
    this->client_port = PORT;
    return *this;
}