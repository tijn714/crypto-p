#include <stdint.h>
#include <stdio.h>

#include "sha256.h"

void test_two(void) {
  uint8_t data_two[] = "Hello, world!";
  uint8_t salt_two[] = "SALT";
  uint8_t hash_two[SHA256_BLOCK_SIZE];

  sha256(data_two, sizeof(data_two), salt_two, sizeof(salt_two), hash_two);

  printf("SHA-256 (salt): ");
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    printf("%02x", hash_two[i]);
  }
  printf("\n");


}

int main(void) {
  uint8_t data[] = "Hello, world!";
  uint8_t salt[] = "";
  uint8_t hash[SHA256_BLOCK_SIZE];

  sha256(data, sizeof(data), salt, sizeof(salt), hash);

  printf("SHA-256: ");
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
    printf("%02x", hash[i]);
  }
  printf("\n\n");

  test_two();

  return 0;
}
