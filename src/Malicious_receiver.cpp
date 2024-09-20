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

void Receiver_set_registration_1(std::vector<bn_t> &y, std::vector<g2_t> &K, bn_t rho, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        int dlen = Hash_F(y[i], K[i]);
        g2_null(K[i]);
        g2_new(K[i]);
        g2_mul(K[i], K[i], rho);
    }
}

void Receiver_set_registration_2(std::vector<g2_t> &K, bn_t s, int start, int end)
{
    for (int i = start; i < end; i++)
        g2_mul(K[i], K[i], s);
}

void Receiver_set_registration_3(std::vector<g2_t> &K, bn_t inv_rho, int start, int end)
{
    for (int i = start; i < end; i++)
        g2_mul(K[i], K[i], inv_rho);
}

void Intersection_Extraction(std::vector<bn_t *> &Z, std::vector<bn_t> &y, std::vector<g2_t> &K, std::vector<uint8_t *> &R, g1_t psi, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        gt_t e;
        gt_null(e);
        gt_new(e);

        pc_map(e, psi, K[i]);

        uint8_t *temp;
        int dlen = Hash_H_hat(y[i], e, temp);

        if (binarySearch(R, temp))
        {
            std::lock_guard<std::mutex> lock(mtx);
            Z.push_back(&y[i]);
        }

        free(temp);
        gt_free(e);
    }
}

int main(int argc, char *argv[])
{
    int port = 0, n = 0, m = 0;
    int N = 0, M = 0, t = 0;
    int start = 0;

    if (parse_command_line(argc, argv, port, n, m, t) != EXIT_SUCCESS)
        port = 1234;

    N = (1 << n); // sender's data
    M = (1 << m); // receiver's data

    std::cout << "Malicious Model - Receiver:" << std::endl;
    std::cout << "N = " << N << ", M = " << M << ", t = " << t << std::endl;

    std::vector<std::thread> threads;
    int rangeSize = M / t;
    int remaining = M % t;

    // Init for TCP
    int client_socket;
    struct sockaddr_in server_address;
    socklen_t addr_size;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    // Configure settings of the server address
    // Address family is Internet
    server_address.sin_family = AF_INET;

    // Set port number, using htons function
    server_address.sin_port = htons(port);

    // Set IP address to localhost
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(server_address.sin_zero, '\0', sizeof(server_address.sin_zero));
    addr_size = sizeof(server_address);

    // Connect the socket to the server using the address
    if (connect(client_socket, reinterpret_cast<struct sockaddr *>(&server_address), addr_size) < 0)
    {
        std::cerr << "TCP/IP: Connection failed" << std::endl;
        return -1;
    }
    else
        std::cout << "TCP/IP: Connection established successfully" << std::endl;

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
    std::vector<bn_t> y(M);
    for (int i = 0; i < M; ++i)
    {
        bn_null(y[i]);
        bn_new(y[i]);

        bn_rand_mod(y[i], p);
    }

    // Receiver-set Registration Phase
    // K_i = F(y_i)^rho
    bn_t rho;
    bn_null(rho);
    bn_new(rho);
    bn_rand_mod(rho, p);

    std::vector<g2_t> K(M);

    start = 0;
    for (int i = 0; i < t; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
        {
            end += 1;
        }
        threads.emplace_back(Receiver_set_registration_1, std::ref(y), std::ref(K), rho, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
        {
            th.join();
        }
    }

    threads.clear();

    // K_i = F(y_i)^(rho * s)
    start = 0;
    for (int i = 0; i < t; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
        {
            end += 1;
        }
        threads.emplace_back(Receiver_set_registration_2, std::ref(K), s, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
        {
            th.join();
        }
    }
    threads.clear();

    // K_i = F(y_i)^(s)
    bn_t inv_rho;
    bn_null(inv_rho);
    bn_new(inv_rho);
    bn_mod_inv(inv_rho, rho, p);

    start = 0;
    for (int i = 0; i < t; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
            end++;

        threads.emplace_back(Receiver_set_registration_3, std::ref(K), inv_rho, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }

    threads.clear();

    send(client_socket, "Start", strlen("Start"), 0);

    // Communication Phase
    std::vector<uint8_t *> R(N);

    uint8_t PSI[2 * RLC_PC_BYTES + 1];
    memset(PSI, 0x00, 2 * RLC_PC_BYTES + 1);

    if (recv(client_socket, PSI, 2 * RLC_PC_BYTES + 1, 0) < 0)
    {
        std::cerr << "Receive failed: " << strerror(errno) << std::endl;
        return -1;
    }

    for (int i = 0; i < N; i++)
    {
        R[i] = new uint8_t[SHA256_DIGEST_LENGTH];
        if (recv(client_socket, R[i], SHA256_DIGEST_LENGTH, 0) < 0)
        {
            std::cerr << "Receive failed: " << strerror(errno) << std::endl;
            return -1;
        }
    }

    // Intersection Extraction Phase
    g1_t psi;
    g1_null(psi);
    g1_new(psi);
    g1_read_bin(psi, PSI, 2 * RLC_PC_BYTES + 1);

    std::sort(R.begin(), R.end(), compareArrays);

    std::vector<bn_t *> Z;

    start = 0;
    for (int i = 0; i < t; ++i)
    {
        int end = start + rangeSize;
        if (i < remaining)
            end++;

        threads.emplace_back(Intersection_Extraction, std::ref(Z), std::ref(y), std::ref(K), std::ref(R), psi, start, end);
        start = end;
    }

    for (auto &th : threads)
    {
        if (th.joinable())
            th.join();
    }
    threads.clear();

    std::cout << "# intersecion = " << Z.size() << std::endl;

    for (int i = 0; i < M; ++i)
    {
        g2_free(K[i]);
        bn_free(y[i]);
    }

    for (int i = 0; i < N; i++)
        delete[] R[i];

    g1_free(g1);
    g2_free(g2);
    bn_free(q);
    bn_free(s);
    g1_free(Gamma);
    bn_free(rho);
    bn_free(inv_rho);
    g1_free(psi);

    core_clean();

    return 0;
}