#include <iostream>

#define USE_NET_BUFFER
#include "net.hh"

int main()
{
    auto b = net::make_buffer<char>(188);

    net::IPv6_Socket s{SOCK_DGRAM};
    net::Address a{AF_INET6, "::1", 9999};

    s.sendto(*b.get(), a);
}
