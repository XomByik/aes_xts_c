#ifndef AES_XTS_H
#define AES_XTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#ifdef _WIN32
    #include <windows.h>
    #include <time.h>   
    #include <conio.h>  
    #include <winioctl.h>
#else
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <linux/fs.h>
    #include <termios.h>
    #include <sys/stat.h>
    #include <linux/hdreg.h>
    #include <dirent.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#define SALT_LENGTH 16
#define TWEAK_LENGTH 16
#define AES_KEY_LENGTH_128 16
#define AES_KEY_LENGTH_256 32

typedef enum {
    DEVICE_TYPE_UNKNOWN,
    DEVICE_TYPE_DISK,
    DEVICE_TYPE_VOLUME
} device_type_t;

#define BUFFER_SIZE (8 * 1024 * 1024)  

#define SECTOR_SIZE 4096
#define KEY_SIZE 32  
#define IV_SIZE 16   
#define SALT_SIZE 16  
#define HEADER_MAGIC "AES-XTS-HDR"
#define HEADER_VERSION 1
#define HEADER_SECTOR 62  
#define RESERVED_SECTORS 64  

#define KEY_SIZE_128 16  
#define KEY_SIZE_256 32  

#pragma pack(push, 1)  
typedef struct {
    char magic[6];
    uint8_t version;
    uint8_t encryption_type;
    uint32_t start_sector;
    uint32_t iterations;
    uint32_t memory_cost;
    uint32_t key_bits;
    uint8_t salt[SALT_SIZE];
    uint8_t verification_data[32];  
    uint8_t padding[0];  
} xts_header_t;
#pragma pack(pop)

typedef struct {
    #ifdef _WIN32
    HANDLE handle;
    LARGE_INTEGER size;
    device_type_t type;
    char path[MAX_PATH];
    #else
    int fd;
    uint64_t size;
    #endif
} device_context_t;

#ifndef _WIN32
#pragma pack(push, 1)
typedef struct {
    uint8_t magic[8];              
    uint8_t salt[SALT_LENGTH];     
    uint8_t initial_tweak[TWEAK_LENGTH]; 
    uint8_t verification_data[32];  
    uint64_t partition_size;        
    uint8_t reserved[64];           
} PartitionHeader;
#pragma pack(pop)
#endif

#define AES_XTS_SUCCESS 0
#define AES_XTS_ERROR_OPENSSL -1
#define AES_XTS_ERROR_IO -2
#define AES_XTS_ERROR_PARAM -3
#define AES_XTS_ERROR_MEMORY -4
#define AES_XTS_ERROR_PERMISSION -5
#define AES_XTS_ERROR_WRONG_PASSWORD -6

void aes_xts_init(void);
void aes_xts_cleanup(void);
int32_t aes_xts_encrypt_sector(const uint8_t *key1, const uint8_t *key2, uint64_t sector_num, uint8_t *data, size_t data_len, int key_bits);
int32_t aes_xts_decrypt_sector(const uint8_t *key1, const uint8_t *key2, uint64_t sector_num, uint8_t *data, size_t data_len, int key_bits);
int32_t aes_xts_crypt_sector(const uint8_t *key1, const uint8_t *key2, uint64_t sector_num, uint8_t *data, size_t data_len, int encrypt, int key_bits);
void print_openssl_error(void);
int derive_keys_from_password(
    const char *password, 
    const unsigned char *salt,
    size_t salt_len,
    unsigned char *key1, 
    unsigned char *key2,
    int key_bits,
    uint32_t iterations,
    uint32_t memory_cost
);
void read_password(char *password, size_t max_len, const char *prompt);
int process_user_confirmation(const char *device_path, int key_bits);
int process_password_input(char *password, size_t password_size, int verify);

int open_device(const char *path, device_context_t *ctx);
void close_device(device_context_t *ctx);

int process_sectors(
    device_context_t *ctx,
    uint8_t *key1,
    uint8_t *key2,
    uint64_t start_sector,
    int encrypt,
    int key_bits  
);

void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data);
int write_header(device_context_t *ctx, const xts_header_t *header);
int read_header(device_context_t *ctx, xts_header_t *header);

#ifndef _WIN32
int is_partition_mounted(const char *device_path);
uint64_t get_partition_size(int fd);
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, size_t in_len, uint8_t *out, int *out_len, uint8_t *tweak);
#endif

#ifdef _WIN32
BOOL is_admin(void);
void unlock_disk(HANDLE hDevice);
device_type_t get_device_type(const char *path);
int32_t prepare_device_for_encryption(const char *device_path, HANDLE *pDevice);
LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t deviceType);
void check_volume(const char *path);
#endif

int write_header_common(device_context_t *ctx, const xts_header_t *header);
int read_header_common(device_context_t *ctx, xts_header_t *header);

#endif