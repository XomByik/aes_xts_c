#ifndef AES_XTS_H
#define AES_XTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <stdbool.h>
#include <omp.h>

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

/* ========== Return Codes ========== */
#define AES_XTS_SUCCESS            0
#define AES_XTS_ERROR_OPENSSL     -1
#define AES_XTS_ERROR_IO          -2
#define AES_XTS_ERROR_PARAM       -3
#define AES_XTS_ERROR_MEMORY      -4
#define AES_XTS_ERROR_PERMISSION  -5
#define AES_XTS_ERROR_WRONG_PWD   -6

/* ========== Buffer Sizes ========== */
#define BUFFER_SIZE               (8 * 1024 * 1024)  /* 8 MB */
#define SECTOR_SIZE               4096
#define ERROR_BUFFER_SIZE         1024
#define PASSWORD_BUFFER_SIZE      128
#define RESERVED_SECTORS          64

/* ========== Cryptographic Constants ========== */
#define SALT_SIZE                 16
#define IV_SIZE                   16
#define VERIFICATION_DATA_SIZE    32
#define BITS_PER_BYTE             8
#define DEFAULT_KEY_BITS          256
#define ENCRYPT_MODE              1
#define DECRYPT_MODE              0

/* ========== Header Constants ========== */
#define HEADER_MAGIC              "AESXTS"
#define HEADER_MAGIC_SIZE         6
#define HEADER_VERSION            1
#define HEADER_SECTOR             62
#define HEADER_ENCRYPTION_TYPE    1

/* ========== KDF Parameters ========== */
#define DEFAULT_ITERATIONS        10
#define DEFAULT_MEMORY_COST       65536
#define DEFAULT_PARALLELISM       4
#define MIN_PASSWORD_LENGTH       8

/* ========== Progress Display ========== */
#define PROGRESS_UPDATE_INTERVAL  10000
#define BYTES_PER_MB              (1024 * 1024)
#define SLEEP_MS                  10

/* ========== Platform-specific Constants ========== */
#ifdef _WIN32
#define PROGRESS_FORMAT           "Priebeh: %.1f%% (%llu/%llu MB)\r"
#define SLEEP_FUNCTION            Sleep(SLEEP_MS)
#else
#define PROGRESS_FORMAT           "Priebeh: %.1f%% (%lu/%lu MB)\r"
#define SLEEP_FUNCTION            usleep(SLEEP_MS * 1000)
#endif

typedef enum {
    DEVICE_TYPE_UNKNOWN,
    DEVICE_TYPE_DISK,
    DEVICE_TYPE_VOLUME
} device_type_t;

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

void aes_xts_init(void);

void aes_xts_cleanup(void);

void print_openssl_error(void);

int32_t aes_xts_crypt_sector(
    const uint8_t *key,     // Jeden spojený kľúč namiesto key1 a key2
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int encrypt,
    int key_bits 
);

int derive_keys_from_password(
    const uint8_t *password, 
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key,          // Jeden spojený kľúč namiesto key1 a key2
    int key_bits,
    uint32_t iterations,
    uint32_t memory_cost
);

void read_password(uint8_t *password, size_t max_len, const char *prompt);

bool process_user_confirmation(const char *device_path, int key_bits);

bool process_password_input(uint8_t *password, size_t password_size, int verify);

bool open_device(const char *path, device_context_t *ctx);
void close_device(device_context_t *ctx);

int process_sectors(
    device_context_t *ctx,
    uint8_t *key,          // Jeden spojený kľúč namiesto key1 a key2
    uint64_t start_sector,
    int encrypt,
    int key_bits  
);

void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data);

uint8_t* allocate_aligned_buffer(size_t size);

void secure_clear_memory(void *buffer, size_t size, bool free_memory);

int header_io(device_context_t *ctx, xts_header_t *header, int isWrite); 

void report_error(const char *message, int error_code);

int encrypt_device(device_context_t *ctx, const char *device_path, int key_bits);

int decrypt_device(device_context_t *ctx);

bool parse_arguments(int argc, char *argv[], const char **operation, 
    const char **device_path, int *key_bits);

bool set_position(device_context_t *ctx, uint64_t position);

ssize_t read_data(device_context_t *ctx, void *buffer, size_t size);

ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size);

#ifdef _WIN32
BOOL is_admin(void);

BOOL set_file_position(HANDLE handle, LARGE_INTEGER position);

void unlock_disk(HANDLE hDevice);

device_type_t get_device_type(const char *path);

bool prepare_device_for_encryption(const char *path, HANDLE *handle);

LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t deviceType);
void check_volume(const char *path);

#else
bool is_partition_mounted(const char *device_path);

uint64_t get_partition_size(int fd);

#endif

#endif /* AES_XTS_H */