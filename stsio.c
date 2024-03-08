#include "stsio.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  // Test data
  uint8_t originalData[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
  int dataLength = sizeof(originalData);

  // Encoding test
  char encodedData[20]; // Adjust the size accordingly
  base64_encode(originalData, dataLength, encodedData);

  // Decoding test
  uint8_t decodedData[20]; // Adjust the size accordingly
  base64_decode(encodedData, strlen(encodedData), decodedData);

  // Equality test
  bool isEqualResult = isEqual(originalData, decodedData, dataLength);

  // Display results
  printf("Original Data: ");
  for (int i = 0; i < dataLength; ++i) {
    printf("%c", originalData[i]);
  }
  printf("\n");

  printf("Encoded Data : %s\n", encodedData);

  printf("Decoded Data : ");
  for (int i = 0; i < dataLength; ++i) {
    printf("%c", decodedData[i]);
  }
  printf("\n");

  printf("Equality Test Result: %s\n", isEqualResult ? "Passed" : "Failed");

  return 0;
}
