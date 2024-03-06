#include <stdio.h>
#include <stdbool.h>

#include "aes.h"

bool isEqual(uint8_t *a, uint8_t *b, int len) {
    for (int i = 0; i < len; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

int main(void) {
	uint8_t key[32] = {
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c,
		0xa0, 0xfa, 0xfe, 0x17,
		0x88, 0x54, 0x2c, 0xb1,
		0x23, 0xa3, 0x39, 0x39,
		0x2a, 0x6c, 0x76, 0x05
	};

	uint8_t in[16] = {
		0x32, 0x43, 0xf6, 0xa8,
		0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2,
		0xe0, 0x37, 0x07, 0x34
	};
    printf("Input:      ");
	for (int i = 0; i < 16; ++i) {
		printf("%02x ", in[i]);
	}
	printf("\n");

	uint8_t out[16];
    uint8_t out2[16];
	uint8_t RoundKey[240];
	KeyExpansion(key, RoundKey);

    printf("RoundKey:   ");
    for (int i = 0; i < 240; ++i) {
        printf("%02x ", RoundKey[i]);
    }
    printf("\n");

	AES_Encrypt(in, out, RoundKey);

    printf("Encrypted:  ");
	for (int i = 0; i < 16; ++i) {
		printf("%02x ", out[i]);
	}
	printf("\n");
	
    printf("Decrypted:  ");
	AES_Decrypt(out, out2, RoundKey);
	for (int i = 0; i < 16; ++i) {
		printf("%02x ", out2[i]);
	}
	printf("\n");

    printf("Data is successfully recovered?   ");

    if (isEqual(in, out2, 16)) {
        printf("YES");
    } else {
        printf("NO");
    }

    printf("\n");
	return 0;
}
