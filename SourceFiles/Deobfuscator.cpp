#include "..\HeaderFiles\Deobfuscator.h"

// Deobfuscate a xor encryption
void deobfuscate_xor(unsigned char* data, SIZE_T data_len, unsigned char* key, SIZE_T key_len) {
    int i = 0;

    while (i < data_len) {
        int j = 0;
        while (j < key_len && i < data_len) {
            data[i] = data[i] ^ key[j];
            i++;
            j++;
        }
    }
}