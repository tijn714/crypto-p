#include <stdio.h>
#include <stdint.h>

#include "sha256.h"

int main(void) {
    uint8_t data[] = "Hello, world!";
    uint8_t salt[] = "";
    uint8_t hash[SHA256_BLOCK_SIZE];

    sha256(data, sizeof(data), salt, sizeof(salt), hash);

    printf("SHA-256: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
