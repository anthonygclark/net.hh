#include <iostream>

#define USE_NET_BUFFER
#include "net.hh"

int main()
{
    auto b = net::make_buffer<char>(188);

    net::ipv6::socket s{SOCK_DGRAM};
    net::ipv6::address a{"::1", 9999};

    s.sendto(*b.get(), a, MSG_DONTROUTE);
}
