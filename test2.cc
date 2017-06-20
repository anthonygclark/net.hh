#include <iostream>
#include <chrono>
#include <thread>

#include "net.hh"

int main()
{
    unsigned char static_mem[512] = {0};

    // flat buffer, notice no #define USE_NET_BUFFER
    net::Buffer b{static_mem, sizeof(static_mem)};

    net::ipv4::socket s{SOCK_DGRAM};
    net::ipv4::address a{net::ipv4::address::ANY, 9999};

    s.sendto(b, a);
}
