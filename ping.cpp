#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

// Internet checksum
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
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static double ms_since(const timeval &start, const timeval &end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_usec - start.tv_usec) / 1000.0;
}

int main(int argc, char *argv[]) {
    int count = 4;
    const char *host = nullptr;

    // Parse args: sudo ./ping [-c count] host
    if (argc == 2) {
        host = argv[1];
    } else if (argc == 4 && std::strcmp(argv[1], "-c") == 0) {
        count = std::atoi(argv[2]);
        host = argv[3];
        if (count <= 0) {
            std::cerr << "-c must be > 0\n";
            return 1;
        }
    } else {
        std::cerr << "Usage: sudo ./ping [-c count] <hostname>\n";
        return 1;
    }

    // Resolve host
    addrinfo hints{};
    addrinfo *res = nullptr;
    hints.ai_family = AF_INET;

    int gai = getaddrinfo(host, nullptr, &hints, &res);
    if (gai != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(gai) << "\n";
        return 1;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr = reinterpret_cast<sockaddr_in *>(res->ai_addr)->sin_addr;

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target.sin_addr, ipstr, sizeof(ipstr));
    freeaddrinfo(res);

    std::cout << "PING " << host << " (" << ipstr << ")\n";

    // Raw ICMP socket (needs sudo)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket (need sudo)");
        return 1;
    }

    // IMPORTANT: timeout so loss doesn't block forever
    // 1 second receive timeout
    timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(sock);
        return 1;
    }

    const uint16_t pid = static_cast<uint16_t>(getpid() & 0xFFFF);

    int sent = 0;
    int received = 0;
    std::vector<double> rtts_ms;

    double min_rtt = std::numeric_limits<double>::infinity();
    double max_rtt = 0.0;
    double sum_rtt = 0.0;

    timeval overall_start{};
    gettimeofday(&overall_start, nullptr);

    for (int seq = 1; seq <= count; ++seq) {
        char sendbuf[64]{};
        struct icmp *icmp_hdr = reinterpret_cast<struct icmp *>(sendbuf);

        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = htons(pid);
        icmp_hdr->icmp_seq = htons(seq);

        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = checksum(sendbuf, sizeof(sendbuf));

        ++sent;

        timeval start{}, end{};
        gettimeofday(&start, nullptr);

        ssize_t s = sendto(sock,
                           sendbuf,
                           sizeof(sendbuf),
                           0,
                           reinterpret_cast<sockaddr *>(&target),
                           sizeof(target));
        if (s < 0) {
            perror("sendto");
            break;
        }

        // Receive (with timeout)
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
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::cout << "Request timeout for icmp_seq " << seq << "\n";
            } else {
                perror("recvfrom");
            }
            sleep(1);
            continue;
        }

        // Parse reply: IP header + ICMP
        struct ip *ip_hdr = reinterpret_cast<struct ip *>(recvbuf);
        int ip_len = ip_hdr->ip_hl << 2;

        if (n < ip_len + (int)sizeof(struct icmp)) {
            std::cout << "Short packet\n";
            sleep(1);
            continue;
        }

        struct icmp *icmp_reply =
            reinterpret_cast<struct icmp *>(recvbuf + ip_len);

        // TTL from IP header
        int ttl = ip_hdr->ip_ttl;

        int icmp_bytes = n - ip_len;

        // Validate it's our echo reply
        if (icmp_reply->icmp_type == ICMP_ECHOREPLY &&
            ntohs(icmp_reply->icmp_id) == pid) {

            ++received;

            double rtt = ms_since(start, end);
            rtts_ms.push_back(rtt);

            min_rtt = std::min(min_rtt, rtt);
            max_rtt = std::max(max_rtt, rtt);
            sum_rtt += rtt;

            std::cout << icmp_bytes << " bytes from " << ipstr
                      << ": seq=" << ntohs(icmp_reply->icmp_seq)
                      << " ttl=" << ttl
                      << " time=" << rtt << " ms\n";
        }

        sleep(1);
    }

    timeval overall_end{};
    gettimeofday(&overall_end, nullptr);
    double elapsed_ms = ms_since(overall_start, overall_end);

    // Summary
    int lost = sent - received;
    double loss_pct = sent > 0 ? (lost * 100.0 / sent) : 0.0;

    std::cout << "\n--- " << host << " ping statistics ---\n";
    std::cout << sent << " packets transmitted, "
              << received << " packets received, "
              << loss_pct << "% packet loss, "
              << "time " << elapsed_ms << "ms\n";

    if (received > 0) {
        double avg = sum_rtt / received;

        // stddev (like ping)
        double variance = 0.0;
        for (double x : rtts_ms) variance += (x - avg) * (x - avg);
        variance /= received;
        double stddev = std::sqrt(variance);

        std::cout << "round-trip min/avg/max/stddev = "
                  << min_rtt << "/" << avg << "/" << max_rtt << "/"
                  << stddev << " ms\n";
    }

    close(sock);
    return 0;
}
