#pragma once

#include <string.h>
#include <liburing.h>

#include <array>
#include <utility>

#include <sys/poll.h>

#include <unordered_map>

#include "Core/Ssl/Ssl.hpp"

#include "Core/Gen/H1/Gen.hpp"
#include "Core/Gen/Gen.hpp"

#include "Core/Proxy/Proxy.hpp"

#include "Cassandra/Scylla/Origin.hpp"

#include "Core/Security/Headers.hpp"

#include "Utils/Pages.hpp"
#include "Utils/Http.hpp"

#include "Core/Thread/Operational.hpp"

#include "Core/Protocols/H3/Uring/Pipeline.hpp"
#include "Core/Protocols/H1/Uring/Pipeline.hpp"
#include "Core/Protocols/H1/H1.hpp"

#include "Main.hpp"

class Core
{
public:
    Core();
    ~Core();

    void start();

private:
    SSL_CTX *ctx;
    quiche_config *quicheConf;

    void worker(int thread);
};