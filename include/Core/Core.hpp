#pragma once

#include <string.h>
#include <liburing.h>

#include "Core/Ssl/Ssl.hpp"
#include "Core/Gen/Gen.hpp"
#include "Core/Uring/Pipeline.hpp"
#include "Core/Proxy/Proxy.hpp"

#include "Cassandra/Scylla/Origin.hpp"

#include "Utils/Http.hpp"

#include "Main.hpp"

class Core
{
public:
    Core();
    ~Core();

    void start();

private:
    SSL_CTX *ctx;

    void worker(int thread);
};