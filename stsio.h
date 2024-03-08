#ifndef STSIO_H
#define STSIO_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int base64_index(char c);

// Function to transform data to base64
void base64_encode(uint8_t in[], int len, char out[]);
void base64_decode(char in[], int len, uint8_t out[]);
bool isEqual(uint8_t *a, uint8_t *b, int len);

void base64_encode(uint8_t in[], int len, char out[]) {
  const char *base64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i, j;

  for (i = 0, j = 0; i < len; i += 3, j += 4) {
    out[j] = base64[in[i] >> 2];
    out[j + 1] =
        base64[((in[i] & 0x03) << 4) | ((i + 1 < len) ? (in[i + 1] >> 4) : 0)];
    out[j + 2] = (i + 1 < len) ? base64[((in[i + 1] & 0x0F) << 2) |
                                        ((i + 2 < len) ? (in[i + 2] >> 6) : 0)]
                               : '=';
    out[j + 3] = (i + 2 < len) ? base64[in[i + 2] & 0x3F] : '=';
  }
  out[j] = '\0';
}

void base64_decode(char in[], int len, uint8_t out[]) {
  int i, j;

  for (i = 0, j = 0; i < len; i += 4, j += 3) {
    out[j] = (base64_index(in[i]) << 2) | (base64_index(in[i + 1]) >> 4);
    out[j + 1] =
        (base64_index(in[i + 1]) << 4) | (base64_index(in[i + 2]) >> 2);
    out[j + 2] = (base64_index(in[i + 2]) << 6) | base64_index(in[i + 3]);
  }
  out[j] = '\0';
}

// Helper function to get the index of a character in the base64 alphabet
int base64_index(char c) {
  const char *base64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (int i = 0; i < 64; ++i) {
    if (base64[i] == c) {
      return i;
    }
  }
  return -1;
}

bool isEqual(uint8_t *a, uint8_t *b, int len) {
  for (int i = 0; i < len; ++i) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

#endif // STSIO_H
