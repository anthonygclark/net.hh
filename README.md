## net.hh

An attempt to simplify the Berkley Sockets API

* Removes boilerplate
* APIs return objects where applicable (instead of half-filled socket structures and error codes)
* Exceptions.
* Header only. Inclusion of `net_buffer.hh` is optional via `USE_NET_BUFFER` macro.

### Example

```c++
#define USE_NET_BUFFER
#include "net.hh"

int main()
{
    /* UDP Socket which will interact with IPv4 address */
    net::ipv4::socket sock4 {SOCK_DGRAM};
    /* TCP Socket which will interact with IPv6 address */
    net::ipv6::socket sock6 {SOCK_STREAM};

    /* IPv4 wildcard address (0.0.0.0) */
    net::ipv4::address addr4 {net::ipv4::address::ANY, 9998};
    /* IPv6 loopback */
    net::ipv6::address addr6 {"::1", 9999};

    /* Create some buffer of data (unique_ptr) and send
     * to the IPv4 address
     */
    auto buffer = net::make_buffer(512);
    sock4.sendto(*buffer.get(), addr4);

    /* Bind and listen */
    sock6.bind(addr6);
    sock6.listen();

    /* Wait for a client...
     * client.first == net::ipv6::socket
     * client.second == net::Address with AF_INET6
     */
    auto client = sock6.accept();
}
```

###  TODO
* Fill out CRTP base classes (socket, address)
* Raw sockets, DCCP, Multicast, Broadcast, TUN, TAP
* IP and UDP header construction.
* Linux-only optional header with `netlink` sockets and `netfilter` bindings
