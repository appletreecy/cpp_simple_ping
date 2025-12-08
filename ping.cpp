#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

// Compute Internet checksum (RFC 1071)
uint16_t checksum(void *data, int len) {
    uint16_t *buf = static_cast<uint16_t *>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *reinterpret_cast<uint8_t *>(buf);
    }

    // fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: sudo ./ping <hostname>\n";
        return 1;
    }

    // 1. Resolve hostname -> IPv4 address
    addrinfo hints{};
    addrinfo *res = nullptr;
    hints.ai_family = AF_INET;  // IPv4 only

    int ret = getaddrinfo(argv[1], nullptr, &hints, &res);
    if (ret != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(ret) << "\n";
        return 1;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr = (reinterpret_cast<sockaddr_in *>(res->ai_addr))->sin_addr;

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target.sin_addr, ipstr, sizeof(ipstr));

    std::cout << "PING " << argv[1] << " (" << ipstr << ")\n";

    freeaddrinfo(res);

    // 2. Create raw ICMP socket (needs sudo)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // 3. Build ICMP Echo Request
    char sendbuf[64];
    std::memset(sendbuf, 0, sizeof(sendbuf));

    // macOS/BSD uses 'struct icmp' (NOT icmphdr)
    struct icmp *icmp_hdr = reinterpret_cast<struct icmp *>(sendbuf);
    icmp_hdr->icmp_type = ICMP_ECHO;       // 8
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(getpid() & 0xFFFF);
    icmp_hdr->icmp_seq = htons(1);

    // You can also put some payload after the header if you want
    const char *payload = "hello from cpp ping";
    size_t payload_len = std::strlen(payload);
    std::memcpy(sendbuf + sizeof(struct icmp), payload, payload_len);

    size_t packet_len = sizeof(struct icmp) + payload_len;

    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum(sendbuf, static_cast<int>(packet_len));

    // 4. Send packet and measure time
    timeval start{}, end{};
    gettimeofday(&start, nullptr);

    ssize_t sent = sendto(sock,
                          sendbuf,
                          packet_len,
                          0,
                          reinterpret_cast<sockaddr *>(&target),
                          sizeof(target));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    // 5. Receive response
    char recvbuf[1024];
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);

    ssize_t n = recvfrom(sock,
                         recvbuf,
                         sizeof(recvbuf),
                         0,
                         reinterpret_cast<sockaddr *>(&from),
                         &fromlen);
    gettimeofday(&end, nullptr);

    if (n < 0) {
        perror("recvfrom");
        close(sock);
        return 1;
    }

    // 6. Parse IP + ICMP headers from the reply
    struct ip *ip_hdr = reinterpret_cast<struct ip *>(recvbuf);
    int ip_hdr_len = ip_hdr->ip_hl << 2;  // ip_hl is in 32-bit words

    struct icmp *icmp_reply =
        reinterpret_cast<struct icmp *>(recvbuf + ip_hdr_len);

    if (icmp_reply->icmp_type == ICMP_ECHOREPLY &&
        icmp_reply->icmp_id == icmp_hdr->icmp_id) {
        double rtt_ms =
            (end.tv_sec - start.tv_sec) * 1000.0 +
            (end.tv_usec - start.tv_usec) / 1000.0;

        char from_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));

        std::cout << "Reply from " << from_ip
                  << ": seq=" << ntohs(icmp_reply->icmp_seq)
                  << " time=" << rtt_ms << " ms\n";
    } else {
        std::cout << "Received non-echo-reply ICMP (type="
                  << static_cast<int>(icmp_reply->icmp_type)
                  << ", code=" << static_cast<int>(icmp_reply->icmp_code)
                  << ")\n";
    }

    close(sock);
    return 0;
}
