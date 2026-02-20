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

    makeNonBlocking(client_listen);
}

void EdgeServer::initSSL()
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate_file(ctx, "SSL/localhost.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "SSL/localhost-key.pem", SSL_FILETYPE_PEM);
}

void EdgeServer::startWorkers()
{
    int epoll_fd = epoll_create1(0);

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

                    makeNonBlocking(client_fd);

                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, client_fd);
                    SSL_set_accept_state(ssl);

                    int bridge_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (bridge_fd == -1)
                    {
                        perror("bridge bridge");
                    }

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

                    SSL *bridge_ssl = SSL_new(ctx);
                    SSL_set_fd(bridge_ssl, bridge_fd);

                    Bridge bridge;
                    bridge.fd = bridge_fd;
                    bridge.handshake_done = false;
                    bridge.ssl = bridge_ssl;

                    bridges.emplace(bridge_fd, std::move(bridge));

                    Connection conn;
                    conn.fd = client_fd;
                    conn.ssl = ssl;
                    conn.bridge_fd = bridge_fd;
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
                auto &conn = connections[events[i].data.fd];

                if (!conn.handshake_done)
                {
                    int ret = SSL_accept(conn.ssl);

                    if (ret == 1)
                    {
                        conn.handshake_done = true;
                    }
                    else
                    {
                        int err = SSL_get_error(conn.ssl, ret);

                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                        {
                            continue;
                        }

                        SSL_free(conn.ssl);
                        close(conn.fd);

                        connections.erase(conn.fd);
                    }
                }
                else
                {
                    if (events[i].events & EPOLLIN && conn.type == ConnType::CLIENT)
                    {
                        handleClient(conn);
                    }
                }
            }
        }
    }

    close(client_listen);
}

int EdgeServer::handleClient(Connection &clientConn)
{
    char buffer[4096];

    int bytes = SSL_read(clientConn.ssl, buffer, sizeof(buffer));
    if (bytes <= 0)
    {
        int err = SSL_get_error(clientConn.ssl, bytes);

        SSL_shutdown(clientConn.ssl);
        SSL_free(clientConn.ssl);
        close(clientConn.fd);
        connections.erase(clientConn.fd);

        return err;
    }

    std::string httpPayload(buffer, bytes);

    int command = static_cast<uint8_t>(Commands::HTTP_REQUEST);

    sendCommand(bridges[clientConn.bridge_fd].ssl, command, httpPayload);

    return 1;
}

void EdgeServer::sendCommand(SSL *ssl, int &cmd, std::string &payload)
{
    uint8_t c = static_cast<uint8_t>(cmd);
    uint32_t net_len = htonl(payload.size());

    SSL_write(ssl, &c, 1);
    SSL_write(ssl, &net_len, 4);
    SSL_write(ssl, payload.data(), payload.size());
}

EdgeServer &EdgeServer::setPort(int PORT)
{
    this->client_port = PORT;
    return *this;
}

int EdgeServer::makeNonBlocking(int sfd)
{
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    flags |= O_NONBLOCK;
    return fcntl(sfd, F_SETFL, flags);
}