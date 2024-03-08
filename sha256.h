#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define SHA256_BLOCK_SIZE 32
#define SHA256_DIGEST_SIZE 32

static const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

};

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  unsigned long long bitlen;
  uint32_t state[8];
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]);

void sha256_init(SHA256_CTX *ctx) {
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
  uint32_t i;

  for (i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (ctx->datalen == 64) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
  uint32_t i;

  i = ctx->datalen;

  // Pad whatever data is left in the buffer.
  if (ctx->datalen < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56) {
      ctx->data[i++] = 0x00;
    }
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64) {
      ctx->data[i++] = 0x00;
    }
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 56; i++) {
      ctx->data[i] = 0x00;
    }
  }

  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);

  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
  }
  for (i = 0; i < 4; ++i) {
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
  }
  for (i = 0; i < 4; ++i) {
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
  }
  for (i = 0; i < 4; ++i) {
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
  }
  for (i = 0; i < 4; ++i) {
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
  }
  for (i = 0; i < 4; ++i) {
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
  }

  for (i = 0; i < 4; ++i) {
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
  }

  for (i = 0; i < 4; ++i) {
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
  }
}

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
  uint32_t a, b, c, d, e, f, g, h, i, j, m[64];
  uint32_t temp1, temp2, temp3, temp4, temp5;

  for (i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) |
           (data[j + 3]);
  }

  for (; i < 64; ++i) {
    m[i] = (m[i - 16] + m[i - 7] + ((m[i - 15] >> 7) | (m[i - 15] << 25)) +
            ((m[i - 15] >> 18) | (m[i - 15] << 14)) + (m[i - 15] >> 3) +
            ((m[i - 2] >> 17) | (m[i - 2] << 15)) +
            ((m[i - 2] >> 19) | (m[i - 2] << 13)) + (m[i - 2] >> 10)) &
           0xffffffff;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (i = 0; i < 64; ++i) {
    temp1 = h + ((e >> 6) | (e << 26)) + ((e >> 11) | (e << 21)) +
            ((e >> 25) | (e << 7)) + ((e & f) ^ (~e & g)) + k[i] + m[i];
    temp2 = ((a >> 2) | (a << 30)) + ((a >> 13) | (a << 19)) +
            ((a >> 22) | (a << 10)) + ((a & b) ^ (a & c) ^ (b & c));
    temp3 = temp1 + temp2;
    temp4 = ((d >> 2) | (d << 30)) + ((d >> 13) | (d << 19)) +
            ((d >> 22) | (d << 10)) + ((d & e) ^ (d & f) ^ (e & f));
    temp5 = temp3 + temp4;
  }

  ctx->state[0] = (temp5 + temp2) & 0xffffffff;
  ctx->state[1] = a;
  ctx->state[2] = b;
  ctx->state[3] = c;
  ctx->state[4] = (d + temp1) & 0xffffffff;
  ctx->state[5] = e;
  ctx->state[6] = f;
  ctx->state[7] = g;
}

void sha256(const uint8_t data[], size_t len, uint8_t salt[], size_t salt_len,
            uint8_t hash[]) {
  SHA256_CTX ctx;

  if (salt == NULL) {
    salt = (uint8_t *)"";
    salt_len = 0;
  }

  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_update(&ctx, salt, salt_len);
  sha256_final(&ctx, hash);
}
