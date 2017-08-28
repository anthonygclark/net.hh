#ifndef _NET_HH_
#define _NET_HH_

extern "C" {
#include <arpa/inet.h>
#include <cstdint>
#include <netdb.h>
#include <netinet/ip.h>
#include <unistd.h>
}

#include <cassert>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#ifdef USE_NET_BUFFER
#include "net_buffer.hh"
#else
namespace net
{
    inline namespace v1
    {
        /**
         * @brief Very thin wrapper around a void* used for network I/O.
         * @details See net_buffer.hh for type-safe implementation
         */
        class Buffer final
        {
        private:
            void * m_ptr = nullptr;
            std::size_t m_size = 0;

        public:
            Buffer(void * ptr, std::size_t n) : m_ptr(ptr), m_size(n) { }
            void * get_data_void() { return m_ptr; }
            void const * get_data_void() const { return m_ptr; }
            std::size_t get_size() const { return m_size; }
        };

    } /* end namespace v1 */
} /* end namespace net */
#endif

namespace net
{
    inline namespace v1
    {
        namespace util
        {
            constexpr std::size_t max(std::size_t a, std::size_t b) {
                return a > b ? a : b;
            }

            template<typename... Ts>
                constexpr std::size_t max(std::size_t a, Ts ... t) {
                    return max(a, t...);
                }

        } /* end namespace util */

        using exception = std::system_error;

        namespace error
        {
            inline std::system_error make_syserr(int err, std::string const & msg)
            {
                return std::system_error(err, std::system_category(), msg);
            }

        } /* end namespace error */

        namespace sizes
        {
            /**< Largest address length used for size constraints. */
            constexpr static std::size_t max_address_length = INET6_ADDRSTRLEN;

        } /* end namespace sizes */

        /**
         * @brief Base socket type.
         * @todo This limits generic interfaces with the base Socket type.
         * @tparam D The devided socket implementation.
         */
        template<typename D>
            class socket
            {
            public:
                using handle_type = int;
                using flags_type = int;
                using domain_type = int;
                using socket_type = int;

            protected:
                handle_type m_fd;
                flags_type m_flags;
                domain_type m_domain;
                socket_type m_type;

                ~socket() {
                    if (m_fd) {
                        ::shutdown(m_fd, SHUT_RDWR);
                        ::close(m_fd);
                    }
                }
            };

        /**
         * @brief Address Base.
         * @details This remains as a CRTP base incase it's easier to implement CRTP dispatching
         *          later on.
         * @tparam D CRTP derived.
         */
        template<typename D>
            class address
            {
            public:
                /* Large enough to represent any internal address */
                using handle_type = struct sockaddr_storage;

            protected:
                std::uint16_t m_port = 0;
                std::string m_ip = "";
                handle_type m_address;

            public:
                /**
                 * @return Current IP Address (if applicable)
                 */
                decltype(m_ip) get_ip() const { return m_ip; }

                /**
                 * @return Current port (if applicable)
                 */
                decltype(m_port) get_port() const { return m_port; }

                /**
                 * @brief Sets IP Address
                 */
                void set_ip(decltype(m_ip) const & ip) { m_ip = ip; }

                /**
                 * @brief Sets IP Address
                 */
                void set_ip(char const * ip, std::size_t size) {
                    m_ip = std::move(std::string{ip, size});
                }

                /**
                 * @brief Sets port
                 */
                void set_port(decltype(m_port) const & port) { m_port = port; }

                struct sockaddr * cast_to_sockaddr() { return reinterpret_cast<struct sockaddr *>(&m_address); }
                struct sockaddr_in * cast_to_sockaddr_in() { return reinterpret_cast<struct sockaddr_in *>(&m_address); }
                struct sockaddr_in6 * cast_to_sockaddr_in6() { return reinterpret_cast<struct sockaddr_in6 *>(&m_address); }
                struct sockaddr_storage * cast_to_sockaddr_storage() { return &m_address; }

                struct sockaddr const * cast_to_sockaddr() const { return reinterpret_cast<struct sockaddr const *>(&m_address); }
                struct sockaddr_in const * cast_to_sockaddr_in() const { return reinterpret_cast<struct sockaddr_in const *>(&m_address); }
                struct sockaddr_in6 const * cast_to_sockaddr_in6() const { return reinterpret_cast<struct sockaddr_in6 const *>(&m_address); }
                struct sockaddr_storage const * cast_to_sockaddr_storage() const { return &m_address; }
            };

        namespace ipv4
        {
            namespace type_traits
            {
                template<typename T> struct is_ipv4_struct : std::false_type { };
                template<> struct is_ipv4_struct<struct sockaddr> : std::true_type { };
                template<> struct is_ipv4_struct<struct sockaddr_in> : std::true_type { };
                template<> struct is_ipv4_struct<struct sockaddr_storage> : std::true_type { };

            } /* end namespace type_traits */

            /**< Alias/Contraint for limiting socket API structs without
             * creating C++ base classes.
             */
            template<class T,
                     class Dummy = typename std::enable_if<
                                         ipv4::type_traits::is_ipv4_struct<
                                                 typename std::remove_cv<
                                                     typename std::remove_pointer<T>::type
                                                     >::type
                                                 >::value
                                         >::type>
            using ipv4_struct = T;

            /**
             * @brief Represents an ipv4 socket address
             * @details Some fields are only used with certain socket functions, ie - send.
             */
            class address final : public net::address<ipv4::address>
            {
            public:
                using net::address<ipv4::address>::handle_type;

            private:
                int m_family = AF_INET;

            public:
                /**< Represents ANY IPv4 address, aka wildcard */
                constexpr static const char * ANY = "0.0.0.0";

                /**
                 * @brief Default constructor
                 * @details Used typically when syscalls fill in an address structure but need
                 *          the socket family as a hint.
                 */
                address() {
                    std::memset(&m_address, 0, sizeof(handle_type));
                }

                /**
                 * @brief constructor
                 * @details Used typically when constructing a source or dest address
                 * @param ip The target The IP Address/Resource
                 * @param port The port
                 */
                address(std::string const & ip, std::uint16_t port)
                {
                    m_ip = ip;
                    m_port = port;

                    std::memset(&m_address, 0, sizeof(handle_type));

                    auto * in = cast_to_sockaddr_in();
                    in->sin_port = htons(m_port);
                    in->sin_family = m_family;

                    auto r = ::inet_pton(m_family, m_ip.c_str(), &(in->sin_addr.s_addr));

                    if (r == 0)
                        throw error::make_syserr(EINVAL, "Could not parse IP address");
                    else if (r == -1)
                        throw error::make_syserr(errno, "inet_pton");
                }

                /**
                 * @brief constructor
                 * @param addr Pre-filled address
                 */
                template<typename T>
                    explicit address(ipv4_struct<T> && s)
                    {
                        static_assert(std::is_pointer<T>::value, "T must be a pointer");

                        assert(s);
                        from_ipv4_struct(s, sizeof(typename std::remove_pointer<T>::type));
                    }

            private:
                /**
                 * @brief Constructs Address from src structure. src struct must be IPv4
                 *          structure (ie - sockaddr)
                 * @param src The IPv4 socket structure
                 * @param src_size The size of the src
                 */
                void from_ipv4_struct(void const * src, std::size_t src_size)
                {
                    std::memcpy(&m_address, src, src_size);
                    m_family = m_address.ss_family;

                    /* storage for the ascii ip */
                    char b[INET_ADDRSTRLEN] = {0};

                    auto * in = cast_to_sockaddr_in();

                    /* parse the IP from src */
                    auto r = ::inet_ntop(m_family, &(in->sin_addr),
                                         b, sizeof(b));

                    if (r == nullptr)
                        throw error::make_syserr(errno, "inet_ntop");

                    set_port(in->sin_port);
                    set_ip(b, INET_ADDRSTRLEN);
                }

            public:
                void from_sockaddr(struct sockaddr const * f)
                {
                    assert(f);
                    from_ipv4_struct(f, sizeof(*f));
                }

                void from_sockaddr_in(struct sockaddr_in const * f)
                {
                    assert(f);
                    from_ipv4_struct(f, sizeof(*f));
                }
            };

            /**
             * @brief Respresents an IPv4 socket
             */
            class socket final : net::socket<ipv4::socket>
            {
            public:
                using net::socket<ipv4::socket>::handle_type;
                using net::socket<ipv4::socket>::flags_type;
                using net::socket<ipv4::socket>::domain_type;
                using net::socket<ipv4::socket>::socket_type;

            private:
                /**
                 * @brief Private Constructor
                 * @param fd An existing socket
                 * @param type The existing socket's type
                 * @param flags The existing socket's flags
                 */
                socket(handle_type fd, socket_type type, flags_type flags)
                {
                    m_fd = fd;
                    m_type = type;
                    m_flags = flags;
                }

            public:
                /**
                 * @brief Constructor
                 * @param type The socket type
                 * @param flags The socket flags
                 */
                explicit socket(socket_type type, flags_type flags = 0)
                {
                    m_type = type;
                    m_flags = flags;

                    m_fd = ::socket(AF_INET, m_type, m_flags);

                    if (m_fd == -1)
                        throw error::make_syserr(errno, "socket");

                    if (type != SOCK_DGRAM && type != SOCK_STREAM && type != SOCK_RAW)
                        throw error::make_syserr(EINVAL, "Unknown socket type");
                }

                /**
                 * @brief Accepts a client (requires connected-mode socket)
                 * @return The client socket and the client address
                 */
                std::pair<std::unique_ptr<socket>, std::unique_ptr<ipv4::address>> accept()
                {
                    struct sockaddr_in accepted;
                    socklen_t accepted_size = sizeof(accepted);

                    std::memset(&accepted, 0, sizeof(accepted));

                    auto accepted_fd = ::accept(m_fd,
                                                (struct sockaddr *)(&accepted),
                                                &accepted_size);

                    if (accepted_fd == -1)
                        throw error::make_syserr(errno, "accept");

                    /* not make_unique here since we're calling a private ctor */
                    auto accepted_socket =
                        std::unique_ptr<socket>(new socket{accepted_fd, m_type, m_flags});

                    /* construct from the out param of ::accept */
                    auto accepted_address = std::make_unique<ipv4::address>(&accepted);

                    return std::make_pair(std::move(accepted_socket), std::move(accepted_address));
                }

                void bind(ipv4::address const & addr)
                {
                    static const int yes = 1;

                    if (m_type == SOCK_STREAM) {
                        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
                        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));
                    }

                    if(::bind(m_fd, addr.cast_to_sockaddr(),
                              sizeof(struct sockaddr_in)) == -1)
                    {
                        throw error::make_syserr(errno, "bind");
                    }
                }

                void listen(int backlog = 16) /* 16 is arbitrary */
                {
                    if (::listen(m_fd, backlog) == -1)
                        throw error::make_syserr(errno, "listen");
                }

                void connect(ipv4::address const & addr)
                {
                    if (::connect(m_fd, addr.cast_to_sockaddr(), sizeof(struct sockaddr_in)) == -1) {
                        throw error::make_syserr(errno, "connect");
                    }
                }

                void send(Buffer const & buffer, flags_type flags = 0)
                {
                    if (::send(m_fd, buffer.get_data_void(), buffer.get_size(), flags) == -1)
                        throw error::make_syserr(errno, "send");
                }

                void recv(Buffer & buffer, flags_type flags = 0)
                {
                    if (::recv(m_fd, buffer.get_data_void(), buffer.get_size(), flags) == -1)
                        throw error::make_syserr(errno, "recv");
                }

                void recvfrom(Buffer & buffer, ipv4::address * from, flags_type flags = 0)
                {
                    socklen_t from_size = sizeof(struct sockaddr);

                    auto r = ::recvfrom(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                        from == nullptr ? nullptr : from->cast_to_sockaddr(),
                                        from == nullptr ? nullptr : &from_size);

                    if (r == -1)
                        throw error::make_syserr(errno, "recvfrom");

                    if (from) {
                        from->from_sockaddr(from->cast_to_sockaddr());
                    }
                }

                void sendto(Buffer const & buffer, ipv4::address const & to, flags_type flags = 0)
                {
                    auto r = ::sendto(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                      to.cast_to_sockaddr(), sizeof(struct sockaddr));

                    if (r == -1)
                        throw error::make_syserr(errno, "sendto");
                }

                /**
                 * @brief Sends multiple buffers to an address
                 * @tparam T Buffer type (must be derived from net::Buffer)
                 * @tparam class Dummy type for detection of pointer-like objects. T can be T* or smart_pointer<T>.
                 *      Or, any pointer type that supplies std::pointer_traits
                 * @param buffers The list of buffers to send
                 * @param to The address to send to
                 * @param flags Implementation flags, see sendmsg(2)
                 */
                template<class T, class = typename std::pointer_traits<T>::pointer>
                    void send_multiple(std::vector<T> const & buffers, ipv4::address const & to, flags_type flags = 0)
                    {
                        static_assert(std::is_base_of<typename std::pointer_traits<T>::element_type, net::Buffer>::value, "T must be derived from net::Buffer");

                        struct msghdr msg = {};
                        std::memset(&msg, 0, sizeof(struct msghdr));

                        /* since sendmsg ultimately calls sendto, we have to send sockaddr
                         * as arg to msghdr.
                         *
                         * Note that we HOPE this cast is safe since sendto/sendmsg should not be
                         * modifying their dest address.
                         */
                        auto const * d = to.cast_to_sockaddr();
                        msg.msg_name = const_cast<sockaddr *>(d);
                        msg.msg_namelen = sizeof(struct sockaddr);
                        msg.msg_iovlen = buffers.size();

                        /* man page says "user allocated" */
                        msg.msg_iov = reinterpret_cast<struct iovec *>(std::calloc(buffers.size(), sizeof(struct iovec)));

                        for (std::size_t i = 0; i < buffers.size(); ++i)
                        {
                            msg.msg_iov[i].iov_base = buffers[i]->get_data_void();
                            msg.msg_iov[i].iov_len = static_cast<int>(buffers[i]->get_size());
                        }

                        auto r = ::sendmsg(m_fd, &msg, flags);

                        std::free(msg.msg_iov);

                        if (r == -1) {
                            throw error::make_syserr(errno, "sendmsg");
                        }
                    }

                /**
                 * @brief Received multiple buffers from a socket
                 * @tparam T Buffer type (must be derived from net::Buffer)
                 * @tparam class Dummy type for detection of pointer-like objects. T can be T* or smart_pointer<T>.
                 *      Or, any pointer type that supplies std::pointer_traits
                 * @param buffers The list of buffers to receive
                 * @param from Source address, optional, defaulted to nullptr
                 * @param flags Implementation flags, see recvmsg(2)
                 */
                template<class T, class = typename std::pointer_traits<T>::pointer>
                    void recv_multiple(std::vector<T> & buffers, ipv4::address * from = nullptr, flags_type flags = 0)
                    {
                        static_assert(std::is_base_of<typename std::pointer_traits<T>::element_type, net::Buffer>::value, "T must be derived from net::Buffer");

                        struct msghdr msg;

                        std::memset(&msg, 0, sizeof(struct msghdr));

                        msg.msg_name = from ? from->cast_to_sockaddr_storage() : nullptr;
                        msg.msg_namelen = from ? sizeof(struct sockaddr_storage) : 0;

                        msg.msg_iov = reinterpret_cast<struct iovec *>(std::calloc(buffers.size(), sizeof(struct iovec)));
                        msg.msg_iovlen = buffers.size();

                        for (decltype(msg.msg_iovlen) i = 0; i < msg.msg_iovlen; ++i)
                        {
                            msg.msg_iov[i].iov_base = buffers[i]->get_data_void();
                            msg.msg_iov[i].iov_len = static_cast<int>(buffers[i]->get_size());
                        }

                        auto r = ::recvmsg(m_fd, &msg, flags);

                        std::free(msg.msg_iov);

                        if (r == 1) {
                            throw error::make_syserr(errno, "recvmsg");
                        }

                        if (from) {
                            from->from_sockaddr(from->cast_to_sockaddr());
                        }
                    }
            };
        } /* end namespace ipv4 */

        namespace ipv6
        {
            namespace type_traits
            {
                template<typename T> struct is_ipv6_struct : std::false_type { };
                template<> struct is_ipv6_struct<struct sockaddr_in6> : std::true_type { };
                template<> struct is_ipv6_struct<struct sockaddr_storage> : std::true_type { };

            } /* end namespace type_traits */

            /**< Alias/Contraint for limiting socket API structs without
             * creating C++ base classes.
             */
            template<class T,
                     class Dummy = typename std::enable_if<
                                            ipv6::type_traits::is_ipv6_struct<
                                                    typename std::remove_cv<
                                                        typename std::remove_pointer<T>::type
                                                        >::type
                                                    >::value
                                            >::type>
            using ipv6_struct = T;

            /**
             * @brief Represents an ipv6 socket address
             */
            class address final : public net::address<ipv6::address>
            {
            public:
                using net::address<ipv6::address>::handle_type;

            private:
                int m_family = AF_INET6;

            public:
                /**< Represents ANY IPv6 address, aka wildcard.
                 * TODO This is a standin value for in6addr_any.
                 */
                constexpr static const char * ANY_6 = ":::";

                /**
                 * @brief Default constructor
                 * @details Used typically when syscalls fill in an address structure but need
                 *          the socket family as a hint.
                 */
                address()
                {
                    std::memset(&m_address, 0, sizeof(handle_type));
                }

                /**
                 * @brief Initializing constructor
                 * @details Used typically when constructing a source or dest address
                 * @param ip The target The IP Address/Resource
                 * @param port The port
                 */
                address(std::string const & ip, std::uint16_t port)
                {
                    m_ip = ip;
                    m_port = port;
                    std::memset(&m_address, 0, sizeof(handle_type));

                    auto * in = cast_to_sockaddr_in6();
                    in->sin6_port = htons(m_port);
                    in->sin6_family = m_family;

                    if (m_ip == ANY_6)
                    {
                        in->sin6_addr = in6addr_any;
                    }
                    else {
                        auto r = ::inet_pton(m_family, m_ip.c_str(), &(in->sin6_addr.s6_addr));

                        if (r == 0)
                            throw error::make_syserr(EINVAL, "Could not parse IP address");
                        else if (r == -1)
                            throw error::make_syserr(errno, "inet_pton");
                    }
                }

                /**
                 * @brief Constructor
                 * @param addr Pre-filled address
                 */
                template<typename T>
                    explicit address(ipv6_struct<T> && s)
                    {
                        static_assert(std::is_pointer<T>::value, "T must be a pointer");

                        assert(s);
                        from_ipv6_struct(s, sizeof(typename std::remove_pointer<T>::type));
                    }

            private:
                /**
                 * @brief Constructs Address from src structure. src struct must be IPv6
                 *          structure (ie - sockaddr_in6)
                 * @param src The IPv6 socket structure
                 * @param src_size The size of the src
                 */
                void from_ipv6_struct(void const * src, std::size_t src_size)
                {
                    std::memcpy(&m_address, src, src_size);
                    m_family = m_address.ss_family;

                    /* storage for the ascii ip */
                    char b[INET6_ADDRSTRLEN] = {0};

                    auto * in = cast_to_sockaddr_in6();

                    /* parse the IP from src */
                    auto r = ::inet_ntop(m_family, &(in->sin6_addr),
                                         b, sizeof(b));

                    if (r == nullptr)
                        throw error::make_syserr(errno, "inet_ntop");

                    set_port(in->sin6_port);
                    set_ip(b, INET_ADDRSTRLEN);
                }

            public:
                void from_sockaddr_in6(struct sockaddr_in6 const * f)
                {
                    assert(f);
                    from_ipv6_struct(f, sizeof(*f));
                }
            };

            /**
             * @brief Respresents an IPv6 socket
             */
            class socket final : net::socket<ipv6::socket>
            {
            public:
                using net::socket<ipv6::socket>::handle_type;
                using net::socket<ipv6::socket>::flags_type;
                using net::socket<ipv6::socket>::domain_type;
                using net::socket<ipv6::socket>::socket_type;

            private:
                /**
                 * @brief Private Constructor
                 * @param fd An existing socket
                 * @param type The existing socket's type
                 * @param flags The existing socket's flags
                 */
                socket(handle_type fd, socket_type type, flags_type flags)
                {
                    m_fd = fd;
                    m_type = type;
                    m_flags = flags;
                }

            public:
                /**
                 * @brief Constructor
                 * @param type The socket type
                 * @param flags The socket flags
                 */
                explicit socket(socket_type type, flags_type flags = 0)
                {
                    m_type = type;
                    m_flags = flags;

                    m_fd = ::socket(AF_INET6, m_type, m_flags);

                    if (m_fd == -1)
                        throw error::make_syserr(errno, "socket");

                    if (type != SOCK_DGRAM && type != SOCK_STREAM)
                        throw error::make_syserr(EINVAL, "Unknown socket type");
                }

                std::pair<std::unique_ptr<socket>, std::unique_ptr<ipv6::address>> accept()
                {
                    struct sockaddr_in6 accepted;
                    socklen_t accepted_size = sizeof(accepted);

                    std::memset(&accepted, 0, sizeof(accepted));

                    auto accepted_fd = ::accept(m_fd,
                                                (struct sockaddr *)(&accepted),
                                                &accepted_size);

                    if (accepted_fd == -1)
                        throw error::make_syserr(errno, "accept");

                    /* not make_unique here since we have a private ctor */
                    auto accepted_socket =
                        std::unique_ptr<socket>(new socket{accepted_fd, m_type, m_flags});

                    /* construct from the out param of ::accept */
                    auto accepted_address = std::make_unique<ipv6::address>(&accepted);

                    return std::make_pair(std::move(accepted_socket), std::move(accepted_address));
                }

                void bind(ipv6::address const & addr)
                {
                    static const int yes = 1;

                    if (m_type == SOCK_STREAM) {
                        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
                        (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));
                    }

                    if(::bind(m_fd, addr.cast_to_sockaddr(),
                              sizeof(struct sockaddr_in6)) == -1)
                    {
                        throw error::make_syserr(errno, "bind");
                    }
                }

                void listen(int backlog = 16) /* 16 is arbitrary */
                {
                    if (::listen(m_fd, backlog) == -1)
                        throw error::make_syserr(errno, "listen");
                }

                void connect(ipv6::address const & addr)
                {
                    if (::connect(m_fd, addr.cast_to_sockaddr(), sizeof(struct sockaddr_in6)) == -1) {
                        throw error::make_syserr(errno, "connect");
                    }
                }

                void send(Buffer const & buffer, flags_type flags = 0)
                {
                    if (::send(m_fd, buffer.get_data_void(), buffer.get_size(), flags) == -1)
                        throw error::make_syserr(errno, "send");
                }

                void recv(Buffer & buffer, flags_type flags = 0)
                {
                    if (::recv(m_fd, buffer.get_data_void(), buffer.get_size(), flags) == -1)
                        throw error::make_syserr(errno, "recv");
                }

                void recvfrom(Buffer & buffer, ipv6::address * from, flags_type flags = 0)
                {
                    socklen_t from_size = sizeof(struct sockaddr_in6);

                    auto r = ::recvfrom(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                        from == nullptr ? nullptr : from->cast_to_sockaddr(),
                                        from == nullptr ? nullptr : &from_size);

                    if (r == -1)
                        throw error::make_syserr(errno, "recvfrom");

                    if (from) {
                        from->from_sockaddr_in6(from->cast_to_sockaddr_in6());
                    }
                }

                void sendto(Buffer const & buffer, ipv6::address const & to, flags_type flags = 0)
                {
                    auto r = ::sendto(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                      to.cast_to_sockaddr(), sizeof(struct sockaddr_in6));

                    if (r == -1)
                        throw error::make_syserr(errno, "sendto");
                }

                template<class T, class = typename std::pointer_traits<T>::pointer>
                    void send_multiple(std::vector<T> const & buffers, ipv6::address const & to, flags_type flags = 0)
                    {
                        static_assert(std::is_base_of<typename std::pointer_traits<T>::element_type, net::Buffer>::value, "T must be derived from net::Buffer");

                        struct msghdr msg = {};
                        std::memset(&msg, 0, sizeof(struct msghdr));

                        /* since sendmsg ultimately calls sendto, we have to send sockaddr
                         * as arg to msghdr.
                         *
                         * Note that we HOPE this cast is safe since sendto/sendmsg should not be
                         * modifying their dest address.
                         */
                        auto const * d = to.cast_to_sockaddr();
                        msg.msg_name = const_cast<sockaddr *>(d);
                        msg.msg_namelen = sizeof(struct sockaddr_in6);
                        msg.msg_iovlen = buffers.size();

                        /* man page says "user allocated" */
                        msg.msg_iov = static_cast<struct iovec *>(std::calloc(buffers.size(), sizeof(struct iovec)));

                        for (std::size_t i = 0; i < buffers.size(); ++i)
                        {
                            msg.msg_iov[i].iov_base = buffers[i]->get_data_void();
                            msg.msg_iov[i].iov_len = static_cast<int>(buffers[i]->get_size());
                        }

                        auto r = ::sendmsg(m_fd, &msg, flags);

                        std::free(msg.msg_iov);

                        if (r == -1) {
                            throw error::make_syserr(errno, "sendmsg");
                        }
                    }

                template<class T, class = typename std::pointer_traits<T>::pointer>
                    void recv_multiple(std::vector<T> & buffers, ipv6::address * from = nullptr, flags_type flags = 0)
                    {
                        static_assert(std::is_base_of<typename std::pointer_traits<T>::element_type, net::Buffer>::value, "T must be derived from net::Buffer");

                        struct msghdr msg;

                        std::memset(&msg, 0, sizeof(struct msghdr));

                        msg.msg_name = from ? from->cast_to_sockaddr_storage() : nullptr;
                        msg.msg_namelen = from ? sizeof(struct sockaddr_storage) : 0;

                        msg.msg_iov = static_cast<struct iovec *>(std::calloc(buffers.size(), sizeof(struct iovec)));
                        msg.msg_iovlen = buffers.size();

                        for (decltype(msg.msg_iovlen) i = 0; i < msg.msg_iovlen; ++i)
                        {
                            msg.msg_iov[i].iov_base = buffers[i]->get_data_void();
                            msg.msg_iov[i].iov_len = static_cast<int>(buffers[i]->get_size());
                        }

                        auto r = ::recvmsg(m_fd, &msg, flags);

                        std::free(msg.msg_iov);

                        if (r == 1) {
                            throw error::make_syserr(errno, "recvmsg");
                        }

                        if (from) {
                            from->from_sockaddr_in6(from->cast_to_sockaddr_in6());
                        }
                    }
            };

        } /* end namespace ipv6 */

    } /* end namespace v1 */
} /* end namesace net */

#endif /* guard */
