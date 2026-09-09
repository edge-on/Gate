#include "Core/Transports/Resolver/Resolver.hpp"

Transports::Resolver::ResolverPacket Transports::Resolver::getResolverPacket(char *host)
{
    ResolverPacket rp;
    memset(&rp, 0, sizeof(rp));

    rp.resolverPacket[0] = 0x12;
    rp.resolverPacket[1] = 0x34;
    rp.resolverPacket[2] = 0x01;
    rp.resolverPacket[3] = 0x00;
    rp.resolverPacket[4] = 0x00;
    rp.resolverPacket[5] = 0x01;
    rp.resolverPacket[6] = 0x00;
    rp.resolverPacket[7] = 0x00;

    char *qname = (char *)&rp.resolverPacket[12];
    DNSClient::formatName(qname, host);
    int qlen = strlen(qname);

    int currentIdx = 12 + qlen + 1;

    rp.resolverPacket[currentIdx] = 0x00;
    rp.resolverPacket[currentIdx + 1] = 0x01;

    rp.resolverPacket[currentIdx + 2] = 0x00;
    rp.resolverPacket[currentIdx + 3] = 0x01;

    rp.outLen = currentIdx + 4;

    return rp;
}