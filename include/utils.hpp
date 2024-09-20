#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <relic.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define S "403E1F9BAAAF22CC51723F6F8DCCE8F46539FCC1A5C32C6F60776556913119A1"



void handleErrors(const char *errorMessage);

uint32_t Hash_F(const bn_t src, g2_t& res);

uint32_t SHA3_256(const uint8_t *src, const uint32_t slen, uint8_t *&dest);

uint32_t Hash_H(const gt_t mu, uint8_t *&dest);
uint32_t Hash_H_hat(const bn_t x, const gt_t mu, uint8_t *&dest);

bool compareArrays(const uint8_t* a, const uint8_t* b);
bool binarySearch(const std::vector<uint8_t*>& vectorR, const uint8_t* target);

// n: # sender's data, m: # receiver's data
int parse_command_line(int argc, char* argv[], int& port, int &n, int &m, int &t);