#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <relic.h>

#include "utils.hpp"

using namespace std;
using namespace chrono;
std::mutex mtx;

void Computation_Phase(std::vector<bn_t> &x, std::vector<gt_t> &mu, std::vector<uint8_t *> &R, g1_t chi, const int start, const int end)
{
    for (int i = start; i < end; i++)
    {
        g2_t temp;
        g2_null(temp);
        g2_new(temp);

        int dlen = Hash_F(x[i], temp);

        gt_null(mu[i]);
        gt_new(mu[i]);
        pc_map(mu[i], chi, temp);

        dlen = Hash_H(mu[i], R[i]);

        g2_free(temp);
    }
}

int main(int argc, char *argv[])
{
    int port = 0, n = 0, m = 0;
    int N = 0, M = 0, t = 0;
    int start = 0;

    if (parse_command_line(argc, argv, port, n, m, t) != EXIT_SUCCESS)
        port = 1234;

    N = (1 << n);
    M = (1 << m);

    if (t <= 1)
        t = 1;

    std::cout << "Semi-Honest Model - Sender:" << std::endl;
    std::cout << "N = " << N << ", M = " << M << ", t = " << t << std::endl;

    std::vector<std::thread> threads;
    int rangeSize = N / t;
    int remaining = N % t;

    // Init for TCP
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        std::cerr << "TCP/IP: Error creating socket\n";
        return 1;
    }

    int reuse = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "Error setting SO_REUSEADDR option" << std::endl;
        close(server_socket);
        return 1;
    }

    sockaddr_storage server_storage;
    socklen_t addr_size;

    sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_address.sin_port = htons(port);

    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));

    if (bind(server_socket, reinterpret_cast<sockaddr *>(&server_address), sizeof(server_address)) < 0)
    {
        std::cerr << "TCP/IP: Binding failed\n";
        return 1;
    }

    if (listen(server_socket, 50) == 0)
        std::cout << "TCP/IP: listening\n";
    else
        std::cerr << "TCP/IP: Error\n";

    int client_socket;
    struct sockaddr_in clientAddress;
    socklen_t clientAddrSize = sizeof(clientAddress);
    client_socket = accept(server_socket, reinterpret_cast<sockaddr *>(&clientAddress), &clientAddrSize);

    if (client_socket == -1)
    {
        std::cerr << "TCP/IP: Error accepting connection\n";
        close(server_socket);
        return 1;
    }

    // CRS Generation Phase
    if (core_init() != RLC_OK || pc_param_set_any() != RLC_OK)
    {
        printf("Relic initialization failed.\n");
        return 1;
    }

    g1_t g1;
    g1_null(g1);
    g1_new(g1);
    g1_get_gen(g1);

    g2_t g2;
    g2_null(g2);
    g2_new(g2);
    g2_get_gen(g2);

    bn_t p;
    bn_null(p);
    bn_new(p);
    pc_get_ord(p);

    bn_t s;
    bn_null(s);
    bn_new(s);
    bn_read_str(s, S, strlen(S), 16);

    g1_t Gamma;
    g1_null(Gamma);
    g1_new(Gamma);
    g1_mul(Gamma, g1, s);

    // Data Setup Phase
    std::vector<bn_t> x(N);
    for (int i = 0; i < N; ++i)
    {
        bn_null(x[i]);
        bn_new(x[i]);

        bn_rand_mod(x[i], p);
    }

    // Computation Phase
    bn_t r;
    bn_null(r);
    bn_new(r);
    bn_rand_mod(r, p);

    g1_t psi;
    g1_null(psi);
    g1_new(psi);
    g1_mul(psi, g1, r);

    g1_t chi;
    g1_null(chi);
    g1_new(chi);
    g1_mul(chi, Gamma, r);

    std::vector<gt_t> mu(N);
    std::vector<uint8_t *> R(N);

    start = 0;
    for (int i = 0; i < t; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
            end++;

        threads.emplace_back(Computation_Phase, std::ref(x), std::ref(mu), std::ref(R), chi, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    uint8_t PSI[2 * RLC_PC_BYTES + 1];

    if (recv(client_socket, PSI, strlen("Start"), 0) < 0)
        printf("Receive failed\n");
    else
        printf("Connection established\n");

    // Communication Phase
    memset(PSI, 0x00, 2 * RLC_PC_BYTES + 1);
    g1_write_bin(PSI, 2 * RLC_PC_BYTES + 1, psi, 0);

    if (send(client_socket, PSI, 2 * RLC_PC_BYTES + 1, 0) == -1)
        std::cerr << "Psi - TCP/IP: Send failed. Errno: " << strerror(errno) << std::endl;

    for (int i = 0; i < N; i++)
    {
        if (send(client_socket, R[i], SHA256_DIGEST_LENGTH, 0) == -1)
            std::cerr << "Data #" << i << " - TCP/IP: Send failed. Errno: " << strerror(errno) << std::endl;
    }
    close(client_socket);

    std::cout << "All data sent successfully" << std::endl;

    for (int i = 0; i < N; ++i)
    {
        gt_free(mu[i]);
        bn_free(x[i]);
        delete[] R[i];
    }

    g1_free(g1);
    g2_free(g2);
    bn_free(p);
    bn_free(s);
    g1_free(Gamma);
    bn_free(r);
    g1_free(psi);
    g1_free(chi);

    core_clean();

    return 0;
}