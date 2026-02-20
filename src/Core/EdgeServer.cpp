#include "Core/EdgeServer.hpp"

EdgeServer::EdgeServer()
{
}

void EdgeServer::start()
{
    initSSL();

    initClientServer();
    initBackendServer();

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

void EdgeServer::initBackendServer()
{
    backend_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (client_listen == -1)
    {
        perror("backend socket");
    }

    sockaddr_in backend_addr;
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    backend_addr.sin_port = htons(backend_port);

    int opt = 1;
    setsockopt(backend_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(backend_listen, (sockaddr *)&backend_addr, sizeof(backend_addr)) < 0)
    {
        perror("backend bind");
    }

    if (listen(backend_listen, SOMAXCONN) < 0)
    {
        perror("backend list");
    }

    makeNonBlocking(backend_listen);
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

    epoll_event backend_event{};
    backend_event.events = EPOLLIN | EPOLLET;
    backend_event.data.fd = backend_listen;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, backend_listen, &backend_event) < 0)
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

                    Connection conn;
                    conn.fd = client_fd;
                    conn.ssl = ssl;
                    conn.type = ConnType::CLIENT;
                    conn.handshake_done = false;

                    connections.emplace(client_fd, std::move(conn));

                    epoll_event client_event{};
                    client_event.events = EPOLLIN | EPOLLET;
                    client_event.data.fd = client_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);
                }
            }
            else if (events[i].data.fd == backend_listen)
            {
                sockaddr_in backend_addr{};
                socklen_t backend_len = sizeof(backend_addr);

                while (true)
                {
                    int backend_fd = accept(backend_listen, (sockaddr *)&backend_addr, &backend_len);
                    if (backend_fd == -1)
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

                    makeNonBlocking(backend_fd);

                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, backend_fd);
                    SSL_set_accept_state(ssl);

                    Connection conn;
                    conn.fd = backend_fd;
                    conn.ssl = ssl;
                    conn.type = ConnType::BACKEND;
                    conn.handshake_done = false;

                    connections.emplace(backend_fd, std::move(conn));

                    epoll_event backend_event{};
                    backend_event.events = EPOLLIN | EPOLLET;
                    backend_event.data.fd = backend_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, backend_fd, &backend_event);
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
                    switch (conn.type)
                    {
                    case ConnType::BACKEND:
                        handleBackend(conn);
                        break;

                    case ConnType::CLIENT:
                        handleClient(conn);
                        break;
                    }
                }
            }
        }
    }

    close(client_listen);
}

int EdgeServer::handleBackend(Connection &conn)
{
    char temp[4096];

    while (true)
    {
        int bytes = SSL_read(conn.ssl, temp, sizeof(temp));

        if (bytes <= 0)
        {
            int err = SSL_get_error(conn.ssl, bytes);

            if (err == SSL_ERROR_WANT_READ ||
                err == SSL_ERROR_WANT_WRITE)
            {
                break;
            }

            return -1;
        }

        conn.buffer.insert(conn.buffer.end(), temp, temp + bytes);
    }

    while (true)
    {
        switch (conn.state)
        {
        case ReadState::READ_CMD:
            if (conn.buffer.size() < 1)
                return 1;

            conn.cmd = conn.buffer[0];
            conn.buffer.erase(conn.buffer.begin());
            conn.state = ReadState::READ_LEN;
            break;

        case ReadState::READ_LEN:
            if (conn.buffer.size() < 4)
                return 1;

            uint32_t net_len;
            memcpy(&net_len, conn.buffer.data(), 4);
            conn.len = ntohl(net_len);

            conn.buffer.erase(conn.buffer.begin(), conn.buffer.begin() + 4);
            conn.state = ReadState::READ_PAYLOAD;
            break;

        case ReadState::READ_PAYLOAD:
            if (conn.buffer.size() < conn.len)
                return 1;

            std::string payload(conn.buffer.begin(),
                                conn.buffer.begin() + conn.len);

            conn.buffer.erase(conn.buffer.begin(),
                              conn.buffer.begin() + conn.len);

            int command = (int)conn.cmd;
            handleCommands(conn, command, payload);

            conn.state = ReadState::READ_CMD;
            break;
        }
    }

    return 1;
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

    auto it = backends.find("localhost.com");
    if (it == backends.end())
    {
        std::cout << "Backend not registered\n";
        return -1;
    }

    int backendFd = it->second;
    Connection &backendConn = connections[backendFd];

    uint8_t cmd = static_cast<uint8_t>(Commands::HTTP_REQUEST);
    uint32_t net_len = htonl(httpPayload.size());

    SSL_write(backendConn.ssl, &cmd, 1);
    SSL_write(backendConn.ssl, &net_len, 4);
    SSL_write(backendConn.ssl, httpPayload.data(), httpPayload.size());

    uint8_t respCmd;
    uint32_t respNetLen;

    if (!read_exact(backendConn.ssl, &respCmd, 1))
        return -1;

    if (!read_exact(backendConn.ssl, &respNetLen, 4))
        return -1;

    uint32_t respLen = ntohl(respNetLen);

    if (respLen > 10 * 1024 * 1024)
    {
        std::cout << "Backend payload too large\n";
        return -1;
    }

    std::vector<char> respBuf(respLen);

    if (respLen > 0)
    {
        if (!read_exact(backendConn.ssl, respBuf.data(), respLen))
            return -1;
    }

    std::string backendResponse(respBuf.data(), respBuf.size());

    SSL_write(clientConn.ssl,
              backendResponse.data(),
              backendResponse.size());

    return 1;
}

bool EdgeServer::read_exact(SSL *ssl, void *buffer, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
        int bytes = SSL_read(ssl,
                             (char *)buffer + total,
                             len - total);

        if (bytes <= 0)
        {
            int err = SSL_get_error(ssl, bytes);

            if (err == SSL_ERROR_WANT_READ ||
                err == SSL_ERROR_WANT_WRITE)
                continue;

            return false;
        }

        total += bytes;
    }

    return true;
}

int EdgeServer::handleCommands(Connection &conn, int &command, std::string &payload)
{
    switch (command)
    {
    case static_cast<int>(Commands::SESSION_INIT):
        if (!conn.session_initialized)
        {
            conn.session_initialized = true;
            backends["localhost.com"] = conn.fd;
            std::cout << "Backend added to trust backend connections" << std::endl;
        }

        int cmd = static_cast<uint8_t>(Commands::RESPONSE_OK);
        std::string payload = "Success";

        sendCommand(conn.ssl, cmd, payload);

        break;
    }

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