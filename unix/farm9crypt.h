/*
 *  farm9crypt.h
 *
 *  C interface between netcat and AES-GCM encryption.
 *
 *  Modern cryptographic implementation with:
 *  - AES-256-GCM authenticated encryption
 *  - PBKDF2 key derivation from password
 *  - Secure random IV generation
 *  - Replay attack protection
 *
 *  NOTE: This file must be included within "extern C {...}" when included in C++
 */

/* Initialize encryption with password-based key derivation */
int farm9crypt_init_password(const char* password, size_t pass_len);

/* Initialize with raw 32-byte key (for advanced usage) */
void farm9crypt_init(char* inkey);

/* Enable debug output */
void farm9crypt_debug();

/* Check if encryption is initialized */
int farm9crypt_initialized();

/* Encrypted read - returns bytes read or -1 on error */
int farm9crypt_read(int sockfd, char* buf, int size);

/* Encrypted write - returns bytes written or -1 on error */
int farm9crypt_write(int sockfd, char* buf, int size);

/* Clean up and free resources */
void farm9crypt_cleanup();

/* Protocol constants */
#define FARM9_MAGIC 0x434C4157     /* "CLAW" */
#define FARM9_VERSION 0x0001       /* Protocol version 1 */
#define FARM9_IV_LEN 12            /* AES-GCM IV length */
#define FARM9_TAG_LEN 16           /* AES-GCM auth tag length */
#define FARM9_SALT_LEN 16          /* PBKDF2 salt length */
#define FARM9_MAX_MSG 8192         /* Maximum message size */

