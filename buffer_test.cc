#include <iostream>

#define USE_NET_BUFFER
#include "net.hh"

int main()
{
    auto p = net::make_buffer(188);
    
    net::BufferImpl<> b1{256};
    auto b2 = std::move(b1);

    net::BufferImpl<> b3 = b2;
}
