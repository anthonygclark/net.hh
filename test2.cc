#include <iostream>
#include <chrono>
#include <thread>

#include "net.hh"

int main()
{
    unsigned char static_mem[512] = {0};

    // flat buffer, notice no #define USE_NET_BUFFER
    net::Buffer b{static_mem, sizeof(static_mem)};

    net::IPv4_Socket s{SOCK_DGRAM};
    net::Address a{AF_INET, net::Address::ANY_4, 9999};

    s.sendto(b, a);
}
