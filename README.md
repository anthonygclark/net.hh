## net.hh

An attempt to simplify the Berkley Sockets API

* Removes boilerplate
* APIs return objects where applicable (instead of half-filled socket structures and error codes)
* Exceptions.
* Header only. Inclusion of `net_buffer.hh` is optional via `USE_NET_BUFFER` define.

### Example

```c++
#define USE_NET_BUFFER
#include "net.hh"

int main() 
{
    /* UDP Socket which will interact with IPv4 address */
	net::IPv4_Socket sock4 {SOCK_DGRAM};
    /* TCP Socket which will interact with IPv6 address */
	net::IPv6_Socket sock6 {SOCK_STREAM};
  
    /* IPv4 wildcard address (0.0.0.0) */
	net::Address addr4 {AF_INET, net::Address::ANY4, 9998};
    /* IPv6 loopback */
	net::Address addr6 {AF_INET6, "::1", 9999};
    
    /* Create some buffer of data (unique_ptr) and send 
     * to the IPv4 address
     */
    auto buffer = net::make_buffer(512);
    sock4.sendto(*buffer.get(), addr4);
  
    /* Bind and listen */
    sock6.bind(addr6);
    sock6.listen();
  
    /* Wait for a client...
     * client.first == net::IPv6_Socket
     * client.second == net::Address with AF_INET6
     */
    auto client = sock6.accept();
}
```

###  TODO

* Maybe segregate `Address` and `IPvX_Socket` into `net::ipv4` and `net::ipv6` like boost. This would remove the `AF_INETX` arg to `Address`.
* Raw sockets, DCCP, Multicast, Broadcast, TUN, TAP
* IP and UDP header construction.
* Linux-only optional header with `netlink` sockets and `netfilter` bindings