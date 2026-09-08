#include "Core/Transports/Resolver/Resolver.hpp"

Transports::Resolver::ResolverPacket Transports::Resolver::getResolverPacket(char *host)
{
    ResolverPacket rp;

    rp.resolverPacket[0] = 0x12;
    rp.resolverPacket[1] = 0x34;
    rp.resolverPacket[2] = 0x01;
    rp.resolverPacket[3] = 0x00;
    rp.resolverPacket[5] = 1;

    char *qname = &rp.resolverPacket[12];
    DNSClient::formatName(qname, host);
    int qlen = strlen((char *)qname) + 1;
    rp.resolverPacket[12 + qlen + 1] = 1;
    rp.resolverPacket[12 + qlen + 3] = 1;

    rp.outLen = 12 + qlen + 4;

    return rp;
}