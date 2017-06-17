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
        struct Buffer final
        {
            void * m_ptr = nullptr;
            std::size_t m_size = 0;

            Buffer(void * ptr, std::size_t n) :
                m_ptr(ptr), m_size(n)
            { }

            void * get_data_void() const { return m_ptr; }
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
            constexpr static int listen_backlog = 16;
            constexpr static std::size_t max_address_length = INET6_ADDRSTRLEN;

        } /* end namespace sizes */

        /**
         * @brief Represents a socket address
         * @details Some fields are only used with certain socket functions, ie - send.
         *          This distinction needs be explicit! TODO
         */
        class Address final
        {
        public:
            /* Large enough to hold any of the common
             * socket structures */
            using handle_type = sockaddr_storage;

        private:
            int m_family;
            std::uint16_t m_port;
            std::string m_ip;
            handle_type m_address;

        public:
            /**< Represents ANY IPv4 address, aka wildcard */
            constexpr static const char * ANY_4 = "0.0.0.0";
            /**< Represents ANY IPv6 address, aka wildcard */
            constexpr static const char * ANY_6 = ":::";

            /**
             * @brief Initializing constructor
             * @details Used typically when syscalls fill in an address structure but need
             *          the socket family as a hint.
             */
            explicit Address(int family) :
                m_family(family),
                m_port(0),
                m_ip("")
            {
                std::memset(&m_address, 0, sizeof(handle_type));
            }

            /**
             * @brief Initializing constructor
             * @details Used typically when constructing a source or dest address
             * @param family The socket family
             * @param ip The target The IP Address/Resource
             * @param port The port
             */
            Address(int family, std::string const & ip, std::uint16_t port) :
                m_family(family),
                m_port(port),
                m_ip(ip)
            {
                std::memset(&m_address, 0, sizeof(handle_type));

                switch(m_family)
                {
                case AF_INET:
                    {
                        auto * in = cast_to_sockaddr_in();
                        in->sin_port = htons(m_port);
                        in->sin_family = AF_INET;

                        auto r = ::inet_pton(family, m_ip.c_str(), &(in->sin_addr.s_addr));

                        if (r == 0)
                            throw error::make_syserr(EINVAL, "Could not parse IP address");
                        else if (r == -1)
                            throw error::make_syserr(errno, "inet_pton");

                        break;
                    }
                case AF_INET6:
                    {
                        auto * in = cast_to_sockaddr_in6();
                        in->sin6_port = htons(m_port);
                        in->sin6_family = AF_INET6;

                        if (m_ip == ANY_6)
                        {
                            in->sin6_addr = in6addr_any;
                        }
                        else {
                            auto r = ::inet_pton(family, m_ip.c_str(), &(in->sin6_addr.s6_addr));

                            if (r == 0)
                                throw error::make_syserr(EINVAL, "Could not parse IP address");
                            else if (r == -1)
                                throw error::make_syserr(errno, "inet_pton");
                        }
                        break;
                    }
                default:
                    assert(false && "Unsupported family");
                    break;
                }
            }

            /**
             * @return Current socket family
             */
            decltype(m_family) get_family() const { return m_family; }

            /**
             * @return Current IP Address (if applicable)
             */
            decltype(m_ip) get_ip() const { return m_ip; }

            /**
             * @brief Sets IP Address
             */
            void set_ip(decltype(m_ip) const & ip) { m_ip = ip; }

            /**
             * @return Current port (if applicable)
             */
            decltype(m_port) get_port() const { return m_port; }

            /**
             * @brief Sets port
             */
            void set_port(decltype(m_port) const & port) { m_port = port; }

#define CAST_TO_CONST(x) x const * cast_to_const_ ## x () const { return reinterpret_cast< x const *>(&m_address); }
            CAST_TO_CONST(sockaddr)
            CAST_TO_CONST(sockaddr_in)
            CAST_TO_CONST(sockaddr_in6)
            CAST_TO_CONST(sockaddr_storage)
#undef CAST_TO_CONST

#define CAST_TO(x) x * cast_to_ ## x () { return reinterpret_cast<x *>(&m_address); }
            CAST_TO(sockaddr)
            CAST_TO(sockaddr_in)
            CAST_TO(sockaddr_in6)
            CAST_TO(sockaddr_storage)
#undef CAST_TO

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
                char b[sizes::max_address_length] = {0};

                /* parse the IP from src */
                auto r = ::inet_ntop(m_family,
                                     &(cast_to_const_sockaddr_in()->sin_addr),
                                     b,
                                     sizeof(struct sockaddr_in));

                if (r == nullptr)
                    throw error::make_syserr(errno, "inet_ntop");

                set_port(ntohs(cast_to_const_sockaddr_in()->sin_port));
                set_ip(b);
            }

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
                char b[sizes::max_address_length] = {0};

                auto r = ::inet_ntop(m_family,
                                     &(cast_to_const_sockaddr_in6()->sin6_addr),
                                     b,
                                     sizeof(struct sockaddr_in6));

                if (r == nullptr)
                    throw error::make_syserr(errno, "inet_ntop");

                set_port(ntohs(cast_to_const_sockaddr_in6()->sin6_port));
                set_ip(b);
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

            void from_sockaddr_in6(struct sockaddr_in6 const * f)
            {
                assert(f);
                from_ipv6_struct(f, sizeof(*f));
            }

            void from_sockaddr_storage(struct sockaddr_storage const * f)
            {
                assert(f);
                std::memcpy(&m_address, f, sizeof(*f));
            }
        };

        /**
         * @brief Base socket type.
         * @todo This limits generic interfaces with the base Socket type.
         * @tparam D The devided socket implementation.
         */
        template<typename D>
            class Socket
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

            public:
                ~Socket() {
                    if (m_fd) {
                        ::shutdown(m_fd, SHUT_RDWR);
                        ::close(m_fd);
                    }
                }
            };

        /**
         * @brief Respresents an IPv4 socket
         */
        class IPv4_Socket final : Socket<IPv4_Socket>
        {
        public:
            using Socket<IPv4_Socket>::handle_type;
            using Socket<IPv4_Socket>::flags_type;
            using Socket<IPv4_Socket>::domain_type;
            using Socket<IPv4_Socket>::socket_type;

        private:
            /**
             * @brief Private Constructor
             * @param fd An existing socket
             * @param type The existing socket's type
             * @param flags The existing socket's flags
             */
            explicit IPv4_Socket(handle_type fd, socket_type type, flags_type flags)
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
            explicit IPv4_Socket(socket_type type, flags_type flags = 0)
            {
                m_type = type;
                m_flags = flags;

                m_fd = ::socket(AF_INET, m_type, m_flags);

                if (m_fd == -1)
                    throw error::make_syserr(errno, "socket");

                if (type != SOCK_DGRAM && type != SOCK_STREAM)
                    throw error::make_syserr(EINVAL, "Unknown socket type");
            }

            std::pair<std::unique_ptr<IPv4_Socket>, std::unique_ptr<Address>> accept()
            {
                struct sockaddr_in accepted;
                socklen_t accepted_size = sizeof(accepted);

                std::memset(&accepted, 0, sizeof(accepted));

                auto accepted_fd = ::accept(m_fd,
                                            (struct sockaddr *)(&accepted),
                                            &accepted_size);

                if (accepted_fd == -1)
                    throw error::make_syserr(errno, "accept");

                /* not make_unique here since we have a private ctor */
                auto accepted_socket =
                    std::unique_ptr<IPv4_Socket>(new IPv4_Socket{accepted_fd, m_type, m_flags});

                auto accepted_family = accepted.sin_family;

                auto accepted_address =
                    std::make_unique<Address>(accepted_family);

                accepted_address->from_sockaddr_in(&accepted);

                return std::make_pair(std::move(accepted_socket), std::move(accepted_address));
            }

            void bind(Address const & addr)
            {
                static const int yes = 1;

                if (m_type == SOCK_STREAM) {
                    (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
                    (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));
                }

                if(::bind(m_fd, addr.cast_to_const_sockaddr(),
                          sizeof(struct sockaddr_in)) == -1)
                {
                    throw error::make_syserr(errno, "bind");
                }
            }

            void listen(int backlog = sizes::listen_backlog)
            {
                if (::listen(m_fd, backlog) == -1)
                    throw error::make_syserr(errno, "listen");
            }

            void connect(Address const & addr)
            {
                if (::connect(m_fd, addr.cast_to_const_sockaddr(), sizeof(struct sockaddr_in)) == -1) {
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

            void recvfrom(Buffer & buffer, Address * from, flags_type flags = 0)
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

            void sendto(Buffer const & buffer, Address const & to, flags_type flags = 0)
            {
                auto r = ::sendto(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                  to.cast_to_const_sockaddr(), sizeof(struct sockaddr));

                if (r == -1)
                    throw error::make_syserr(errno, "sendto");
            }

            void send_multiple(std::vector<Buffer const *> & buffers, Address const & to, flags_type flags = 0)
            {
                struct msghdr msg = {};
                std::memset(&msg, 0, sizeof(struct msghdr));

                /* since sendmsg ultimately calls sendto, we have to send sockaddr
                 * as arg to msghdr.
                 *
                 * Note that we HOPE this cast is safe since sendto/sendmsg should not be
                 * modifying their dest address.
                 */
                msg.msg_name = (void *)to.cast_to_const_sockaddr();
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

            void recv_multiple(std::vector<Buffer *> & buffers, Address * from, flags_type flags = 0)
            {
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

        /**
         * @brief Respresents an IPv6 socket
         */
        class IPv6_Socket final : Socket<IPv6_Socket>
        {
        public:
            using Socket<IPv6_Socket>::handle_type;
            using Socket<IPv6_Socket>::flags_type;
            using Socket<IPv6_Socket>::domain_type;
            using Socket<IPv6_Socket>::socket_type;

        private:
            /**
             * @brief Private Constructor
             * @param fd An existing socket
             * @param type The existing socket's type
             * @param flags The existing socket's flags
             */
            explicit IPv6_Socket(handle_type fd, socket_type type, flags_type flags)
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
            explicit IPv6_Socket(socket_type type, flags_type flags = 0)
            {
                m_type = type;
                m_flags = flags;

                m_fd = ::socket(AF_INET6, m_type, m_flags);

                if (m_fd == -1)
                    throw error::make_syserr(errno, "socket");

                if (type != SOCK_DGRAM && type != SOCK_STREAM)
                    throw error::make_syserr(EINVAL, "Unknown socket type");
            }

            std::pair<std::unique_ptr<IPv6_Socket>, std::unique_ptr<Address>> accept()
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
                    std::unique_ptr<IPv6_Socket>(new IPv6_Socket{accepted_fd, m_type, m_flags});

                auto accepted_family = accepted.sin6_family;

                auto accepted_address =
                    std::make_unique<Address>(accepted_family);

                accepted_address->from_sockaddr_in6(&accepted);

                return std::make_pair(std::move(accepted_socket), std::move(accepted_address));
            }

            void bind(Address const & addr)
            {
                static const int yes = 1;

                if (m_type == SOCK_STREAM) {
                    (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
                    (void)::setsockopt(m_fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(int));
                }

                if(::bind(m_fd, addr.cast_to_const_sockaddr(),
                          sizeof(struct sockaddr_in6)) == -1)
                {
                    throw error::make_syserr(errno, "bind");
                }
            }

            void listen(int backlog = sizes::listen_backlog)
            {
                if (::listen(m_fd, backlog) == -1)
                    throw error::make_syserr(errno, "listen");
            }

            void connect(Address const & addr)
            {
                if (::connect(m_fd, addr.cast_to_const_sockaddr(), sizeof(struct sockaddr_in6)) == -1) {
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

            void recvfrom(Buffer & buffer, Address * from, flags_type flags = 0)
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

            void sendto(Buffer const & buffer, Address const & to, flags_type flags = 0)
            {
                auto r = ::sendto(m_fd, buffer.get_data_void(), buffer.get_size(), flags,
                                  to.cast_to_const_sockaddr(), sizeof(struct sockaddr_in6));

                if (r == -1)
                    throw error::make_syserr(errno, "sendto");
            }

            void send_multiple(std::vector<Buffer const *> & buffers, Address const & to, flags_type flags = 0)
            {
                struct msghdr msg = {};
                std::memset(&msg, 0, sizeof(struct msghdr));

                /* since sendmsg ultimately calls sendto, we have to send sockaddr
                 * as arg to msghdr.
                 *
                 * Note that we HOPE this cast is safe since sendto/sendmsg should not be
                 * modifying their dest address.
                 */
                msg.msg_name = (void *)to.cast_to_const_sockaddr();
                msg.msg_namelen = sizeof(struct sockaddr_in6);
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

            void recv_multiple(std::vector<Buffer *> & buffers, Address * from, flags_type flags = 0)
            {
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
                    from->from_sockaddr_in6(from->cast_to_sockaddr_in6());
                }
            }
        };

        /**
         * @brief Represents a RAW socket
         */
        class Raw_Socket final : Socket<Raw_Socket>
        {
        public:
            using Socket<Raw_Socket>::handle_type;
            using Socket<Raw_Socket>::flags_type;
            using Socket<Raw_Socket>::domain_type;
            using Socket<Raw_Socket>::socket_type;
        };

    } /* end namespace v1 */
} /* end namesace net */

#endif /* guard */
