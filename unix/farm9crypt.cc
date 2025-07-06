/*
 *  farm9crypt.cpp
 *
 *  C interface between netcat and AES-GCM.
 *
 *  Intended for direct replacement of system "read" and "write" calls.
 *
 *  Design is like a "C" version of an object.
 *
 *  Adapted by replacing Twofish with AES-GCM (OpenSSL)
 */

#ifndef WIN32
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <openssl/rand.h>
#else
#include <fcntl.h>
#include <io.h>
#include <conio.h>
#include <winsock.h>
#include <time.h>
#endif

extern "C"
{
#include "farm9crypt.h"
}

#include "aesgcm.h"

static int debug = false;
static int initialized = false;
static AESGCM* decryptor = NULL;
static AESGCM* encryptor = NULL;

extern "C" void farm9crypt_debug() {
    debug = true;
}

extern "C" int farm9crypt_initialized() {
    return initialized;
}

extern "C" void farm9crypt_init(char* keystr) {
    encryptor = new AESGCM(reinterpret_cast<const unsigned char*>(keystr), strlen(keystr));
    decryptor = new AESGCM(reinterpret_cast<const unsigned char*>(keystr), strlen(keystr));
    initialized = true;
    srand(1000);
}

extern "C" int farm9crypt_read(int sockfd, char* buf, int size) {
    unsigned char iv[12];
    unsigned char tag[16];
    int iv_len = 12;
    int tag_len = 16;

   
    int ret = recv(sockfd, iv, iv_len, MSG_WAITALL);
    if (ret != iv_len) return 0;

  
    ret = recv(sockfd, tag, tag_len, MSG_WAITALL);
    if (ret != tag_len) return 0;


    unsigned char ciphertext[8192];
    ret = recv(sockfd, ciphertext, size, MSG_WAITALL);
    if (ret <= 0) return 0;

    int plaintext_len;
    bool ok = decryptor->decrypt(
        ciphertext, ret,
        iv, iv_len,
        tag, tag_len,
        reinterpret_cast<unsigned char*>(buf),
        plaintext_len
    );

    if (!ok) {
        if (debug) fprintf(stderr, "Decryption failed\n");
        return 0;
    }

    buf[plaintext_len] = '\0'; 
    return plaintext_len;
}

extern "C" int farm9crypt_write(int sockfd, char* buf, int size) {
    unsigned char iv[12];
    unsigned char tag[16];
    int iv_len = 12;
    int tag_len = 16;

    
    if (RAND_bytes(iv, iv_len) != 1) {
        if (debug) fprintf(stderr, "IV generation failed\n");
        return 0;
    }

    unsigned char ciphertext[8192];
    int ciphertext_len;

    bool ok = encryptor->encrypt(
        reinterpret_cast<unsigned char*>(buf), size,
        ciphertext,
        iv, iv_len,
        tag, tag_len,
        ciphertext_len
    );

    if (!ok) {
        if (debug) fprintf(stderr, "Encryption failed\n");
        return 0;
    }


    int sent = send(sockfd, iv, iv_len, 0);
    if (sent != iv_len) return 0;


    sent = send(sockfd, tag, tag_len, 0);
    if (sent != tag_len) return 0;

  
    sent = send(sockfd, ciphertext, ciphertext_len, 0);
    if (sent != ciphertext_len) return 0;

    return size;
}
