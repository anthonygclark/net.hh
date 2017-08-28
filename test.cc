#include <iostream>
#include <chrono>
#include <thread>

#define USE_NET_BUFFER
#include "net.hh"

int main(void)
{
    std::cout << "-------------\n";

    std::thread udp_recvthread{[] {
        auto b = net::make_buffer<char>(188);
        auto s = net::ipv4::socket(SOCK_DGRAM);
        auto a = net::ipv4::address(net::ipv4::address::ANY, 9999);
        s.bind(a);

        net::ipv4::address who{};
        s.recvfrom(*b.get(), &who);

        std::cout << "UDP1: Received " << b->get_size() << " bytes\n";
        std::cout << "UDP1: WHO ADDR: " << who.get_ip() << std::endl;
    }};

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::thread udp_sendthread{[] {
        auto b = net::make_buffer<char>(188);
        auto p  = b.get();

        for (std::size_t i = 0; i < 188; i++) {
            reinterpret_cast<char*>(p->get_data_void())[i] = '1';
        }

        auto s = net::ipv4::socket(SOCK_DGRAM);
        auto a = net::ipv4::address(net::ipv4::address::ANY, 9999);

        std::cout << "UDP1: Sending " << b->get_size() << " bytes\n";
        s.sendto(*b.get(), a);
    }};

    udp_recvthread.join();
    udp_sendthread.join();

    std::cout << "-------------\n";

    std::thread tcp_recvthread{[] {
        auto b = net::make_buffer<char>(188);
        auto s = net::ipv4::socket{SOCK_STREAM};
        auto a = net::ipv4::address{net::ipv4::address::ANY, 8888};
        s.bind(a);
        s.listen();

        auto client = s.accept();

        std::get<0>(client)->send(*b.get());

        std::cout << "TCP1: Receiving " << b->get_size() << " bytes to "
                  << std::get<1>(client)->get_ip() << "\n";
    }};

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::thread tcp_sendthread{[] {
        auto b = net::make_buffer<char>(188);
        auto s = net::ipv4::socket{SOCK_STREAM};
        auto a = net::ipv4::address{net::ipv4::address::ANY, 8888};

        s.connect(a);
        s.recv(*b.get());

        std::cout << "TCP1: Sending " << b->get_size() << " bytes\n";
    }};

    tcp_recvthread.join();
    tcp_sendthread.join();

    std::cout << "----------------\n";

    std::thread recvmsg_thread{[] {
        auto s = net::ipv4::socket(SOCK_DGRAM);
        auto a = net::ipv4::address(net::ipv4::address::ANY, 9999);

        net::ipv4::address who{};

        std::vector<std::unique_ptr<net::Buffer>> buffers;

        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(1000));

        s.bind(a);

        s.recv_multiple(buffers, &who, MSG_WAITALL);

        std::size_t total_bytes = 0;

        for (auto & i : buffers) {
            total_bytes += i->get_size();
        }

        std::cout << "RECVMSG1: Recieved " << total_bytes
                  << " bytes via recv_multiple from ADDR: "
                  << who.get_ip() << std::endl;
    }};

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::thread sendmsg_thread{[] {
        auto s = net::ipv4::socket(SOCK_DGRAM);
        auto a = net::ipv4::address(net::ipv4::address::ANY, 9999);

        std::vector<std::unique_ptr<net::Buffer>> buffers;

        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(188));
        buffers.emplace_back(net::make_buffer(1000));

        s.send_multiple(buffers, a);

        std::cout << "SENDMSG1: Sending 1564 bytes via send_multiple...\n";
    }};

    recvmsg_thread.join();
    sendmsg_thread.join();
}
