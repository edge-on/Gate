#pragma once

#include <string.h>
#include <liburing.h>

#include <array>
#include <utility>

#include <unordered_map>

#include "Core/Ssl/Ssl.hpp"
#include "Core/Gen/Gen.hpp"
#include "Core/Uring/Pipeline.hpp"
#include "Core/Proxy/Proxy.hpp"

#include "Cassandra/Scylla/Origin.hpp"

#include "Utils/Pages.hpp"
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

    void memoryWorker(int thread);
    void worker(int thread);
};