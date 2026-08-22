#pragma once

#include <openssl/ssl.h>

#include <sys/types.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

struct Zone
{
    std::string domain;
    std::string host;

    std::atomic<ssize_t> outbound{0};
    std::atomic<ssize_t> inbound{0};

    std::atomic<ssize_t> dnsQueries{0};

    std::atomic<SSL_CTX *> ctx{nullptr};
};

class ZoneMap
{
public:
    ZoneMap() = default;

    ZoneMap(const ZoneMap &) = delete;
    ZoneMap &operator=(const ZoneMap &) = delete;

    ~ZoneMap()
    {
        Node *curr = head.next.load(std::memory_order_relaxed);
        while (curr)
        {
            Node *next = curr->next.load(std::memory_order_relaxed);
            destroy(curr);
            curr = next;
        }

        for (int s = 0; s < kSegments; ++s)
            delete[] segments[s].load(std::memory_order_relaxed);

        RetiredCtx *retired = retiredContexts.load(std::memory_order_relaxed);
        while (retired)
        {
            RetiredCtx *next = retired->next;
            SSL_CTX_free(retired->ctx);
            delete retired;
            retired = next;
        }
    }

    Zone *find(std::string_view domain)
    {
        const uint64_t hash = hashKey(domain);
        const uint64_t order = dataOrder(hash);

        Node *curr = getBucket(hash & (bucketCount.load(std::memory_order_acquire) - 1))
                         ->next.load(std::memory_order_acquire);

        while (curr && compare(curr, order, domain) < 0)
            curr = curr->next.load(std::memory_order_acquire);

        if (curr && compare(curr, order, domain) == 0)
            return &static_cast<DataNode *>(curr)->zone;

        return nullptr;
    }

    Zone *findOrCreate(std::string_view domain)
    {
        const uint64_t hash = hashKey(domain);
        Node *bucket = getBucket(hash & (bucketCount.load(std::memory_order_acquire) - 1));

        bool created = false;
        Node *node = link(bucket, dataOrder(hash), domain, true, &created);

        if (created)
            grow(itemCount.fetch_add(1, std::memory_order_relaxed) + 1);

        return &static_cast<DataNode *>(node)->zone;
    }

    void replaceCtx(Zone *zone, SSL_CTX *ctx)
    {
        SSL_CTX *previous = zone->ctx.exchange(ctx, std::memory_order_acq_rel);
        if (!previous || previous == ctx)
            return;

        auto *retired = new RetiredCtx{previous, retiredContexts.load(std::memory_order_relaxed)};
        while (!retiredContexts.compare_exchange_weak(retired->next, retired,
                                                      std::memory_order_release,
                                                      std::memory_order_relaxed))
        {
        }
    }

    template <typename Fn>
    void forEach(Fn &&fn)
    {
        Node *curr = head.next.load(std::memory_order_acquire);
        while (curr)
        {
            if (curr->order & 1)
            {
                auto *node = static_cast<DataNode *>(curr);
                fn(node->key, node->zone);
            }
            curr = curr->next.load(std::memory_order_acquire);
        }
    }

    size_t size() const { return itemCount.load(std::memory_order_relaxed); }

private:
    struct Node
    {
        uint64_t order;
        std::atomic<Node *> next{nullptr};

        explicit Node(uint64_t o) : order(o) {}
    };

    struct DataNode : Node
    {
        std::string key;
        Zone zone;

        DataNode(uint64_t o, std::string_view k) : Node(o), key(k) { zone.domain = key; }
    };

    struct RetiredCtx
    {
        SSL_CTX *ctx;
        RetiredCtx *next;
    };

    static constexpr int kSegments = 48;
    static constexpr size_t kMaxBuckets = size_t(1) << (kSegments - 1);
    static constexpr size_t kLoadFactor = 2;

    static int segmentOf(size_t bucket)
    {
        return bucket < 2 ? 0 : 63 - __builtin_clzll(bucket);
    }

    static size_t segmentBase(int segment)
    {
        return segment == 0 ? 0 : size_t(1) << segment;
    }

    static size_t segmentSize(int segment)
    {
        return segment == 0 ? 2 : size_t(1) << segment;
    }

    static uint64_t reverseBits(uint64_t v)
    {
        v = ((v >> 1) & 0x5555555555555555ULL) | ((v & 0x5555555555555555ULL) << 1);
        v = ((v >> 2) & 0x3333333333333333ULL) | ((v & 0x3333333333333333ULL) << 2);
        v = ((v >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((v & 0x0F0F0F0F0F0F0F0FULL) << 4);
        return __builtin_bswap64(v);
    }

    static uint64_t hashKey(std::string_view key)
    {
        uint64_t h = std::hash<std::string_view>{}(key);

        h ^= h >> 30;
        h *= 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 27;
        h *= 0x94D049BB133111EBULL;
        h ^= h >> 31;

        return h;
    }

    static uint64_t dataOrder(uint64_t hash) { return reverseBits(hash | (1ULL << 63)); }
    static uint64_t dummyOrder(size_t bucket) { return reverseBits(bucket); }

    static int compare(Node *node, uint64_t order, std::string_view key)
    {
        if (node->order != order)
            return node->order < order ? -1 : 1;

        if (!(order & 1))
            return 0;

        const int c = std::string_view(static_cast<DataNode *>(node)->key).compare(key);
        return c < 0 ? -1 : (c > 0 ? 1 : 0);
    }

    static void destroy(Node *node)
    {
        if (node->order & 1)
            delete static_cast<DataNode *>(node);
        else
            delete node;
    }

    Node *link(Node *start, uint64_t order, std::string_view key, bool data, bool *created)
    {
        Node *fresh = nullptr;

        while (true)
        {
            Node *prev = start;
            Node *curr = prev->next.load(std::memory_order_acquire);

            while (curr && compare(curr, order, key) < 0)
            {
                prev = curr;
                curr = curr->next.load(std::memory_order_acquire);
            }

            if (curr && compare(curr, order, key) == 0)
            {
                if (fresh)
                    destroy(fresh);

                *created = false;
                return curr;
            }

            if (!fresh)
                fresh = data ? static_cast<Node *>(new DataNode(order, key)) : new Node(order);

            fresh->next.store(curr, std::memory_order_relaxed);

            if (prev->next.compare_exchange_weak(curr, fresh,
                                                 std::memory_order_release,
                                                 std::memory_order_relaxed))
            {
                *created = true;
                return fresh;
            }
        }
    }

    std::atomic<Node *> *bucketSlot(size_t bucket)
    {
        const int s = segmentOf(bucket);

        std::atomic<Node *> *segment = segments[s].load(std::memory_order_acquire);
        if (!segment)
        {
            auto *fresh = new std::atomic<Node *>[segmentSize(s)]();

            if (segments[s].compare_exchange_strong(segment, fresh,
                                                    std::memory_order_release,
                                                    std::memory_order_acquire))
                segment = fresh;
            else
                delete[] fresh;
        }

        return &segment[bucket - segmentBase(s)];
    }

    Node *getBucket(size_t bucket)
    {
        if (bucket == 0)
            return &head;

        std::atomic<Node *> *slot = bucketSlot(bucket);

        Node *node = slot->load(std::memory_order_acquire);
        if (node)
            return node;

        const size_t parent = bucket & ~(size_t(1) << segmentOf(bucket));

        bool created = false;
        Node *dummy = link(getBucket(parent), dummyOrder(bucket), std::string_view{}, false, &created);

        if (slot->compare_exchange_strong(node, dummy,
                                          std::memory_order_release,
                                          std::memory_order_acquire))
            return dummy;

        return node;
    }

    void grow(size_t count)
    {
        size_t buckets = bucketCount.load(std::memory_order_relaxed);

        if (buckets >= kMaxBuckets || count <= buckets * kLoadFactor)
            return;

        bucketCount.compare_exchange_strong(buckets, buckets * 2,
                                            std::memory_order_release,
                                            std::memory_order_relaxed);
    }

    Node head{0};

    std::atomic<std::atomic<Node *> *> segments[kSegments]{};

    std::atomic<size_t> bucketCount{2};
    std::atomic<size_t> itemCount{0};

    std::atomic<RetiredCtx *> retiredContexts{nullptr};
};
