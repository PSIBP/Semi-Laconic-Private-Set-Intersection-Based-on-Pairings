#include "utils.hpp"

void handleErrors(const char *errorMessage)
{
    std::cerr << "Error: " << errorMessage << std::endl;
    std::cerr << "Aborting..." << std::endl;
    std::exit(EXIT_FAILURE);
}

uint32_t Hash_F(const bn_t src, g2_t &res)
{
    int size = bn_size_str(src, 16);
    uint8_t *buffer = new uint8_t[size];
    bn_write_str((char *)buffer, size, src, 16);

    uint8_t *dest;
    int dlen = SHA3_256(buffer, size, dest);

    g2_null(res);
    g2_new(res);

    g2_map(res, dest, dlen);

    free(dest);
    delete[] buffer;

    return dlen;
}
uint32_t Hash_H(const gt_t mu, uint8_t *&dest)
{
    uint8_t buffer[12 * RLC_PC_BYTES];
    gt_write_bin(buffer, 12 * RLC_PC_BYTES, mu, 0);

    int dlen = SHA3_256((uint8_t *)buffer, 12 * RLC_PC_BYTES, dest);

    return dlen;
}

uint32_t Hash_H_hat(const bn_t x, const gt_t mu, uint8_t *&dest)
{
    int size = bn_size_str(x, 16);

    uint8_t *buffer = new uint8_t[size + 12 * RLC_PC_BYTES];

    bn_write_str((char *)buffer, size, x, 16);
    gt_write_bin(buffer + size, 12 * RLC_PC_BYTES, mu, 0);

    int dlen = SHA3_256((uint8_t *)buffer, 12 * RLC_PC_BYTES + size, dest);

    delete[] buffer;
    return dlen;
}

uint32_t SHA3_256(const uint8_t *src, const uint slen, uint8_t *&dest)
{
    const EVP_MD *md = EVP_sha3_256();
    EVP_MD_CTX *mdctx;
    uint32_t dlen = SHA256_DIGEST_LENGTH;

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors("EVP_MD_CTX_create error occurred.");
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    { // returns 1 if successful
        handleErrors("EVP_DigestInit_ex error occurred.");
    }

    EVP_DigestUpdate(mdctx, src, slen);

    if ((dest = (uint8_t *)OPENSSL_malloc(dlen)) == NULL)
    {
        handleErrors("OPENSSL_malloc error occurred.");
    }
    memset(dest, 0x00, dlen);

    if (EVP_DigestFinal_ex(mdctx, dest, &dlen) != 1)
    { // returns 1 if successful
        OPENSSL_free(dest);
        handleErrors("EVP_DigestFinal_ex error occurred.");
    }

    EVP_MD_CTX_destroy(mdctx);

    return dlen;
}

bool compareArrays(const uint8_t *a, const uint8_t *b)
{
    return std::lexicographical_compare(a, a + SHA256_DIGEST_LENGTH, b, b + SHA256_DIGEST_LENGTH);
}

bool binarySearch(const std::vector<uint8_t *> &vectorR, const uint8_t *target)
{
    auto it = std::lower_bound(vectorR.begin(), vectorR.end(), target, compareArrays);
    return (it != vectorR.end() && !compareArrays(target, *it));
}

int parse_command_line(int argc, char *argv[], int &port, int &n, int &m, int &t)
{
    int opt;

    while ((opt = getopt(argc, argv, "p:n:m:t:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            port = std::atoi(optarg);
            break;
        case 'n':
            n = std::atoi(optarg);
            break;
        case 'm':
            m = std::atoi(optarg);
            break;
        case 't':
            t = std::atoi(optarg);
            break;
        default:
            std::cerr << "Usage: " << argv[0] << " -p port -n n -m m\n";
            return EXIT_FAILURE;
        }
    }

    // Check if port is specified
    if (port == 0)
    {
        std::cerr << "Port must be specified\n";
        return EXIT_FAILURE;
    }

    // default n = 2^10, m = 2^10
    if (n == 0)
        n = 10;

    if (m == 0)
        m = 10;
    if (t == 0)
        t = 1;

    return EXIT_SUCCESS;
}