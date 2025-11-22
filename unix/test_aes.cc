#include "aesgcm.cc"
#include <cstdio>
#include <cstring>

int main() {
    const char* text = "Sample text for encryption.";
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int ciphertext_len;
    int decrypted_len;

    // Generate key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    AESGCM aes(key);

    // Encryption
    bool ok = aes.encrypt((const unsigned char*)text, strlen(text),
                          ciphertext,
                          iv, sizeof(iv),
                          tag, sizeof(tag),
                          ciphertext_len);

    if (!ok) {
        printf("Encryption error\n");
        return 1;
    }

    printf("Ciphertext (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decryption
    bool dok = aes.decrypt(ciphertext, ciphertext_len,
                           iv, sizeof(iv),
                           tag, sizeof(tag),
                           decrypted, decrypted_len);

    if (!dok) {
        printf("Decryption error\n");
        return 1;
    }

    decrypted[decrypted_len] = '\0';
    printf("Decrypted text: %s\n", decrypted);
    return 0;
}
