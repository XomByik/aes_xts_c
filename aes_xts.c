#include "aes_xts.h"

void aes_xts_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void aes_xts_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

void print_openssl_error(void) {
    uint8_t err_msg[ERROR_BUFFER_SIZE];
    uint32_t err = ERR_get_error();
    
    if(err != 0) {
        ERR_error_string_n(err, (char*)err_msg, sizeof(err_msg));
        fprintf(stderr, "OpenSSL Chyba: %s\n", err_msg);
    }
}

void show_progress(uint64_t current, uint64_t total, uint64_t sector_num) {
    if (sector_num % PROGRESS_UPDATE_INTERVAL == 0 || current >= total - SECTOR_SIZE) {
        float progress = (float)current * 100.0f / (float)total;
        if (progress > 100.0f) progress = 100.0f;
        
        printf(PROGRESS_FORMAT,
               progress,
               (current / BYTES_PER_MB),
               (total / BYTES_PER_MB));
        fflush(stdout);
        
        SLEEP_FUNCTION;
    }
}

int32_t aes_xts_crypt_sector(
    const uint8_t *key1,
    const uint8_t *key2,
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int encrypt,
    int key_bits 
) {
    EVP_CIPHER_CTX *ctx;
    uint8_t iv[IV_SIZE] = {0};
    int len;
    const EVP_CIPHER *cipher = (key_bits == 128) ? EVP_aes_128_xts() : EVP_aes_256_xts();
    size_t key_size = key_bits / BITS_PER_BYTE;
    
    *(uint64_t*)iv = sector_num + (
        #ifdef _WIN32
        RESERVED_SECTORS
        #else
        0
        #endif
    );
    
    uint8_t combined_key[KEY_SIZE * 2];
    memcpy(combined_key, key1, key_size);
    memcpy(combined_key + key_size, key2, key_size);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }

    int success;
    if (encrypt) {
        success = EVP_EncryptInit_ex(ctx, cipher, NULL, combined_key, iv);
        if (success) success = EVP_EncryptUpdate(ctx, data, &len, data, data_len);
        if (success) success = EVP_EncryptFinal_ex(ctx, data + len, &len);
    } else {
        success = EVP_DecryptInit_ex(ctx, cipher, NULL, combined_key, iv);
        if (success) success = EVP_DecryptUpdate(ctx, data, &len, data, data_len);
        if (success) success = EVP_DecryptFinal_ex(ctx, data + len, &len);
    }
    
    if (!success) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return AES_XTS_ERROR_OPENSSL;
    }

    EVP_CIPHER_CTX_free(ctx);
    return AES_XTS_SUCCESS;
}

int derive_keys_from_password(
    const uint8_t *password, 
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key1, 
    uint8_t *key2,
    int key_bits, 
    uint32_t iterations,
    uint32_t memory_cost
) {
    size_t key_len = key_bits / BITS_PER_BYTE;
    uint8_t combined_key[AES_KEY_LENGTH_256 * 2];
    uint32_t parallelism = DEFAULT_PARALLELISM;
    
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) {
        fprintf(stderr, "Chyba: Argon2id nie je dostupny v tejto verzii OpenSSL\n");
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }
    
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);  
    if (!kctx) {
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen((const char*)password)),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len),
        OSSL_PARAM_construct_uint32("iterations", &iterations),
        OSSL_PARAM_construct_uint32("m_cost", &memory_cost),
        OSSL_PARAM_construct_uint32("parallelism", &parallelism),
        OSSL_PARAM_construct_end()
    };
    
    if (EVP_KDF_derive(kctx, combined_key, key_len * 2, params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kctx);
        return AES_XTS_ERROR_OPENSSL;
    }
    
    EVP_KDF_CTX_free(kctx);
    
    memcpy(key1, combined_key, key_len);
    memcpy(key2, combined_key + key_len, key_len);
    
    return AES_XTS_SUCCESS;
}

void read_password(uint8_t *password, size_t max_len, const char *prompt) {
    printf("%s", prompt);
    fflush(stdout);
    
    size_t i = 0;
    int c;
    
    #ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    #else
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    #endif
    
    while (i < max_len - 1) {
        #ifdef _WIN32
        c = _getch();
        #else
        c = getchar();
        #endif
        
        if (c == '\r' || c == '\n' || c == EOF) 
            break;
        else if ((c == '\b' || c == 127) && i > 0) {
            i--;
            printf("\b \b");
            fflush(stdout);
        }
        else if (c >= 32 && c <= 255) {
            password[i++] = c;
            printf("*");
            fflush(stdout);
        }
    }
    
    #ifdef _WIN32
    SetConsoleMode(hStdin, mode);
    #else
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    #endif
    
    password[i] = '\0';
    printf("\n");
}

bool open_device(const char *path, device_context_t *ctx) {
    #ifdef _WIN32
    ctx->type = get_device_type(path);
    
    strncpy(ctx->path, path, MAX_PATH - 1);
    ctx->path[MAX_PATH - 1] = '\0';
    
    check_volume(path);
    
    if (!prepare_device_for_encryption(path, &ctx->handle)) {
        return false;
    }
    ctx->size = get_device_size(ctx->handle, ctx->type);
    return ctx->size.QuadPart != 0;
    #else
    if (is_partition_mounted(path)) {
        fprintf(stderr, "Chyba: Oddiel %s je pripojeny. Odpojte ho pred operaciou.\n", path);
        return false;
    }
    
    ctx->fd = open(path, O_RDWR);
    if (ctx->fd < 0) {
        perror("Chyba pri otvarani zariadenia");
        return false;
    }
    
    ctx->size = get_partition_size(ctx->fd);
    return ctx->size != 0;
    #endif
}

void close_device(device_context_t *ctx) {
    #ifdef _WIN32
    if (ctx->handle != INVALID_HANDLE_VALUE) {
        unlock_disk(ctx->handle);
        CloseHandle(ctx->handle);
        ctx->handle = INVALID_HANDLE_VALUE;
    }
    #else
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1;
    }
    #endif
}

uint8_t* allocate_aligned_buffer(size_t size) {
    uint8_t* buffer = NULL;
    #ifdef _WIN32
    buffer = (uint8_t *)_aligned_malloc(size, SECTOR_SIZE);
    #else
    if (posix_memalign((void**)&buffer, SECTOR_SIZE, size) != 0) {
        buffer = NULL;
    }
    #endif
    if (buffer) {
        memset(buffer, 0, size);
    }
    return buffer;
}

void secure_free_buffer(uint8_t* buffer, size_t size) {
    if (buffer) {
        #ifdef _WIN32
        SecureZeroMemory(buffer, size);
        _aligned_free(buffer);
        #else
        memset(buffer, 0, size);
        free(buffer);
        #endif
    }
}

static ssize_t read_sectors_block(device_context_t *ctx, uint8_t *buffer, size_t max_size, uint64_t currentOffset) {
    size_t bytesToRead = max_size;
    #ifdef _WIN32
    if (currentOffset + bytesToRead > (uint64_t)ctx->size.QuadPart)
        bytesToRead = ctx->size.QuadPart - currentOffset;
    #else
    if (currentOffset + bytesToRead > ctx->size)
        bytesToRead = ctx->size - currentOffset;
    #endif
    return read_data(ctx, buffer, bytesToRead);
}

static void process_block(
    uint8_t *buffer, 
    ssize_t bytesRead, 
    int encrypt, 
    int key_bits, 
    const uint8_t *key1, 
    const uint8_t *key2, 
    uint64_t sector_offset
) {
    const size_t completeSectors = bytesRead / SECTOR_SIZE;
    const size_t remainderBytes = bytesRead % SECTOR_SIZE;

    #pragma omp parallel for schedule(dynamic, 16)
    for (size_t i = 0; i < completeSectors; i++) {
        const uint64_t current_sector = sector_offset + i;
        uint8_t *sector_data = buffer + (i * SECTOR_SIZE);
        aes_xts_crypt_sector(key1, key2, current_sector, sector_data, SECTOR_SIZE, encrypt, key_bits);
    }

    if (remainderBytes > 0) {
        uint8_t lastSectorBuffer[SECTOR_SIZE] = {0};
        memcpy(lastSectorBuffer, buffer + completeSectors * SECTOR_SIZE, remainderBytes);
        
        const uint64_t last_sector = sector_offset + completeSectors;
        aes_xts_crypt_sector(key1, key2, last_sector, lastSectorBuffer, SECTOR_SIZE, encrypt, key_bits);
        
        memcpy(buffer + completeSectors * SECTOR_SIZE, lastSectorBuffer, remainderBytes);
    }
}

static ssize_t write_sectors_block(device_context_t *ctx, uint8_t *buffer, size_t bytesToWrite, uint64_t currentOffset) {
    if (!set_position(ctx, currentOffset)) {
        return -1;
    }
    return write_data(ctx, buffer, bytesToWrite);
}

int process_sectors(
    device_context_t *ctx,
    uint8_t *key1,
    uint8_t *key2,
    uint64_t start_sector,
    int encrypt,
    int key_bits
) {
    const uint64_t startOffset = start_sector * SECTOR_SIZE;
    const uint64_t total_size = 
        #ifdef _WIN32
        ctx->size.QuadPart - startOffset;
        #else
        ctx->size - startOffset;
        #endif
    
    const size_t buffer_size = BUFFER_SIZE + SECTOR_SIZE;
    uint8_t *buffer = allocate_aligned_buffer(buffer_size);
    if (!buffer) {
        fprintf(stderr, "Zlyhala alokacia pamate\n");
        return AES_XTS_ERROR_IO;
    }
    
    if (!set_position(ctx, startOffset)) {
        fprintf(stderr, "Chyba pri nastaveni pozicie v zariadeni\n");
        secure_free_buffer(buffer, buffer_size);
        return AES_XTS_ERROR_IO;
    }
    
    uint64_t currentOffset = startOffset;
    uint64_t sector_num = 0;
    
    printf("Zacinam %s...%s\n", 
           encrypt ? "sifrovanie" : "desifrovanie",
           encrypt ? " (toto moze trvat niekolko minut)" : "");
    
    while (currentOffset < startOffset + total_size) {
        ssize_t bytesRead = read_sectors_block(ctx, buffer, BUFFER_SIZE, currentOffset);
        if (bytesRead <= 0) {
            if (bytesRead < 0) {
                fprintf(stderr, "Chyba pri citani dat\n");
                secure_free_buffer(buffer, buffer_size);
                return AES_XTS_ERROR_IO;
            }
            break; 
        }
        
        process_block(buffer, bytesRead, encrypt, key_bits, key1, key2, sector_num);
        
        ssize_t bytesWritten = write_sectors_block(ctx, buffer, bytesRead, currentOffset);
        if (bytesWritten != bytesRead) {
            fprintf(stderr, "Chyba pri zapise dat\n");
            secure_free_buffer(buffer, buffer_size);
            return AES_XTS_ERROR_IO;
        }
        
        currentOffset += bytesWritten;
        sector_num += bytesRead / SECTOR_SIZE;
        
        uint64_t progress = currentOffset - startOffset;
        show_progress(progress, total_size, sector_num);
    }
    
    secure_free_buffer(buffer, buffer_size);
    return AES_XTS_SUCCESS;
}

int header_io(device_context_t *ctx, xts_header_t *header, int isWrite) {
    uint8_t *sector = allocate_aligned_buffer(SECTOR_SIZE);
    if (!sector) {
        fprintf(stderr, "Zlyhala alokacia pamate pre hlavicku\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    memset(sector, 0, SECTOR_SIZE);
    
    if (isWrite) {
        memcpy(sector, header, sizeof(xts_header_t));
        printf("Zapisujem hlavicku - magic: %.6s verzia: %u\n", header->magic, header->version);
    }
    
    const uint64_t headerPos = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;
    if (!set_position(ctx, headerPos)) {
        fprintf(stderr, "Zlyhalo nastavenie pozicie hlavicky\n");
        secure_free_buffer(sector, SECTOR_SIZE);
        return AES_XTS_ERROR_IO;
    }
    
    ssize_t bytesTransferred;
    if (isWrite) {
        bytesTransferred = write_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            fprintf(stderr, "Zlyhalo zapisanie hlavicky\n");
            secure_free_buffer(sector, SECTOR_SIZE);
            return AES_XTS_ERROR_IO;
        }
        
        #ifdef _WIN32
        FlushFileBuffers(ctx->handle);
        #else
        fsync(ctx->fd);
        #endif
    } else {
        bytesTransferred = read_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            fprintf(stderr, "Zlyhalo citanie hlavicky\n");
            secure_free_buffer(sector, SECTOR_SIZE);
            return AES_XTS_ERROR_IO;
        }
        
        memcpy(header, sector, sizeof(xts_header_t));
        
        if (memcmp(header->magic, HEADER_MAGIC, HEADER_MAGIC_SIZE) != 0) {
            fprintf(stderr, "Neplatna magicka hodnota v hlavicke\n");
            secure_free_buffer(sector, SECTOR_SIZE);
            return AES_XTS_ERROR_PARAM;
        }
    }
    
    secure_free_buffer(sector, SECTOR_SIZE);
    return AES_XTS_SUCCESS;
}

bool set_position(device_context_t *ctx, uint64_t position) {
    #ifdef _WIN32
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)position;
    if (!SetFilePointerEx(ctx->handle, pos, NULL, FILE_BEGIN)) {
        return false;
    }
    #else
    if (lseek(ctx->fd, (off_t)position, SEEK_SET) != (off_t)position) {
        return false;
    }
    #endif
    return true;
}

ssize_t read_data(device_context_t *ctx, void *buffer, size_t size) {
    #ifdef _WIN32
    DWORD bytesRead = 0;
    if (!ReadFile(ctx->handle, buffer, size, &bytesRead, NULL)) {
        return -1;
    }
    return bytesRead;
    #else
    return read(ctx->fd, buffer, size);
    #endif
}

ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size) {
    #ifdef _WIN32
    DWORD bytesWritten = 0;
    if (!WriteFile(ctx->handle, buffer, size, &bytesWritten, NULL)) {
        return -1;
    }
    return bytesWritten;
    #else
    return write(ctx->fd, buffer, size);
    #endif
}

#ifdef _WIN32

BOOL is_admin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        CheckTokenMembership(NULL, AdminGroup, &isAdmin);
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

device_type_t get_device_type(const char *path) {
    return (strncmp(path, "\\\\.\\PhysicalDrive", 17) == 0) ? DEVICE_TYPE_DISK : DEVICE_TYPE_VOLUME;
}

BOOL lock_and_dismount_volume(HANDLE hDevice) {
    DWORD bytesReturned;
    DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    return TRUE;
}

void unlock_disk(HANDLE hDevice) {
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    }
}

void check_volume(const char *path) {
    if (path[0] == '\\' && path[1] == '\\' && path[2] == '.' && path[3] == '\\' && isalpha(path[4])) {
        printf("Priprava jednotky %c: na pristup\n", path[4]);
    }
}

LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t type) {
    LARGE_INTEGER size = {0};
    DWORD bytesReturned;

    if (type == DEVICE_TYPE_VOLUME) {
        GET_LENGTH_INFORMATION lengthInfo;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &lengthInfo, sizeof(lengthInfo), &bytesReturned, NULL);
        size.QuadPart = lengthInfo.Length.QuadPart;
    } else {
        DISK_GEOMETRY_EX diskGeometry;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &diskGeometry, sizeof(diskGeometry), &bytesReturned, NULL);
        size.QuadPart = diskGeometry.DiskSize.QuadPart;
    }

    return size;
}

HANDLE open_device_with_retry(const char *path) {
    HANDLE handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    }

    return handle;
}

bool prepare_device_for_encryption(const char *path, HANDLE *handle) {
    if (!is_admin()) {
        fprintf(stderr, "Chyba: Vyzaduju sa administratorske opravnenia\n");
        return false;
    }

    check_volume(path);
    *handle = open_device_with_retry(path);

    if (*handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Zlyhalo otvorenie zariadenia: %lu\n", GetLastError());
        return false;
    }

    lock_and_dismount_volume(*handle);

    DWORD bytesReturned;
    DeviceIoControl(*handle, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &bytesReturned, NULL);

    return true;
}

BOOL set_file_position(HANDLE handle, LARGE_INTEGER position) {
    return SetFilePointerEx(handle, position, NULL, FILE_BEGIN);
}

void report_windows_error(const char *message) {
    char error_message[ERROR_BUFFER_SIZE] = {0};
    DWORD error_code = GetLastError();

    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error_message, ERROR_BUFFER_SIZE, NULL);
    fprintf(stderr, "%s: (%lu) %s\n", message, error_code, error_message);
}

#endif

void report_error(const char *message, int error_code) {
    #ifdef _WIN32
    (void)error_code; 
    fprintf(stderr, "%s: %lu\n", message, GetLastError());
    #else
    if (error_code) {
        fprintf(stderr, "%s: %s\n", message, strerror(error_code));
    } else {
        perror(message);
    }
    #endif
}

bool process_user_confirmation(const char *device_path, int key_bits) {
    printf("UPOZORNENIE: Vsetky data na zariadeni %s budu zasifrovane s %d-bitovym klucom!\n", 
           device_path, key_bits);
    
    printf("Chcete pokracovat? (a/n): ");
    
    char confirm;
    if (scanf(" %c", &confirm) != 1) {
        fprintf(stderr, "Chyba pri citani potvrdenia\n");
        return false;
    }
    
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    return (confirm == 'a' || confirm == 'A' || confirm == 'y' || confirm == 'Y');
}

bool process_password_input(uint8_t *password, size_t password_size, int verify) {
    read_password(password, password_size, "Zadajte heslo: ");
    
    if (strlen((char*)password) < MIN_PASSWORD_LENGTH) {
        fprintf(stderr, "Heslo musi mat aspon %d znakov\n", MIN_PASSWORD_LENGTH);
        return false;
    }
    
    if (verify) {
        uint8_t confirm_password[PASSWORD_BUFFER_SIZE];
        read_password(confirm_password, sizeof(confirm_password), "Potvrdte heslo: ");
        
        if (strcmp((char*)password, (char*)confirm_password) != 0) {
            fprintf(stderr, "Hesla sa nezhoduju\n");
            return false;
        }
    }
    
    return true;
}

void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data) {
    const char *verify_str = "AES-XTS-VERIFY";
    size_t hmac_key_len = key_bits / BITS_PER_BYTE;
    
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) {
        print_openssl_error();
        return;
    }
    
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    if (!hmac_ctx) {
        EVP_MAC_free(hmac);
        print_openssl_error();
        return;
    }
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    
    if (EVP_MAC_init(hmac_ctx, key, hmac_key_len, params) &&
        EVP_MAC_update(hmac_ctx, (uint8_t *)verify_str, strlen(verify_str)) &&
        EVP_MAC_update(hmac_ctx, salt, SALT_LENGTH)) {
        
        size_t out_len = VERIFICATION_DATA_SIZE;
        EVP_MAC_final(hmac_ctx, verification_data, &out_len, VERIFICATION_DATA_SIZE);
    } else {
        print_openssl_error();
    }
    
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
}

#ifndef _WIN32

bool is_partition_mounted(const char *device_path) {
    FILE *mtab = fopen("/proc/mounts", "r");
    if (!mtab) return false;

    char line[ERROR_BUFFER_SIZE];
    bool mounted = false;

    while (fgets(line, sizeof(line), mtab)) {
        if (strstr(line, device_path)) {
            mounted = true;
            break;
        }
    }

    fclose(mtab);
    return mounted;
}

uint64_t get_partition_size(int fd) {
    uint64_t size = 0;

    if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
        perror("Chyba pri zistovani velkosti oddielu");
        return 0;
    }

    return size;
}
#endif

bool parse_arguments(int argc, char *argv[], const char **operation, 
                    const char **device_path, int *key_bits) {
    if (argc < 3) {
        printf("AES-XTS Nastroj na sifrovanie diskov/oddielov\n");
        printf("=========================================\n\n");
        printf("Pouzitie:\n");
        printf("  %s encrypt [128|256] <zariadenie>\n", argv[0]);
        printf("  %s decrypt [128|256] <zariadenie>\n", argv[0]);
        printf("\nPriklady:\n");
        printf("  %s encrypt 128 /dev/sdb1     # Sifrovanie s 128-bitovym klucom\n", argv[0]);
        printf("  %s encrypt 256 /dev/sdb1     # Sifrovanie s 256-bitovym klucom\n", argv[0]);
        printf("  %s encrypt /dev/sdb1         # Sifrovanie s predvolenou velkostou kluca (256-bit)\n", argv[0]);
        printf("  %s decrypt /dev/sdb1         # Desifrovanie (velkost kluca je nacitana z hlavicky)\n", argv[0]);
        return false;
    }

    *operation = argv[1];
    
    if (argc >= 4 && (strcmp(argv[2], "128") == 0 || strcmp(argv[2], "256") == 0)) {
        *key_bits = atoi(argv[2]);
        *device_path = argv[3];
    } else if (argc >= 3) {
        *device_path = argv[2];
    }

    if (!*device_path) {
        fprintf(stderr, "Chyba: Nie je zadana cesta k zariadeniu\n");
        return false;
    }
    
    return true;
}

int encrypt_device(device_context_t *ctx, const char *device_path, int key_bits) {
    uint8_t password[PASSWORD_BUFFER_SIZE] = {0};
    uint8_t key1[KEY_SIZE] = {0}, key2[KEY_SIZE] = {0};
    xts_header_t header = {0};
    int result = 0;
    
    printf("Pouziva sa %d-bitove sifrovanie\n", key_bits);
    
    if (!process_user_confirmation(device_path, key_bits)) {
        printf("Sifrovanie zrusene.\n");
        return 0;
    }
    
    if (!process_password_input(password, sizeof(password), 1)) {
        return 0;
    }

    memcpy(header.magic, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    header.version = HEADER_VERSION;
    header.encryption_type = HEADER_ENCRYPTION_TYPE;
    header.start_sector = RESERVED_SECTORS;
    header.iterations = DEFAULT_ITERATIONS;
    header.memory_cost = DEFAULT_MEMORY_COST;
    header.key_bits = key_bits;

    if (!RAND_bytes(header.salt, SALT_LENGTH)) {
        print_openssl_error();
        return 0;
    }

    if (derive_keys_from_password(password, header.salt, SALT_LENGTH,
                                key1, key2, key_bits,
                                header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        return 0;
    }
    
    create_verification_data(key1, key_bits, header.salt, header.verification_data);
    printf("Verifikacne data vytvorene\n");

    if (header_io(ctx, &header, 1) != AES_XTS_SUCCESS) {
        fprintf(stderr, "Zlyhalo zapisanie hlavicky\n");
        return 0;
    }

    result = process_sectors(ctx, key1, key2, header.start_sector, ENCRYPT_MODE, key_bits);
    
    memset(password, 0, sizeof(password));
    memset(key1, 0, sizeof(key1));
    memset(key2, 0, sizeof(key2));
    
    return result;
}

int decrypt_device(device_context_t *ctx) {
    uint8_t password[PASSWORD_BUFFER_SIZE] = {0};
    uint8_t key1[KEY_SIZE] = {0}, key2[KEY_SIZE] = {0};
    xts_header_t header = {0};
    int result = 0;
    
    if (header_io(ctx, &header, 0) != AES_XTS_SUCCESS) {
        fprintf(stderr, "Zlyhalo nacitanie hlavicky alebo neplatna hlavicka\n");
        return 0;
    }
    
    if (!process_password_input(password, sizeof(password), 0)) {
        return 0;
    }

    printf("Pouziva sa %d-bitove sifrovanie (z hlavicky)\n", header.key_bits);

    if (derive_keys_from_password(password, header.salt, SALT_LENGTH,
                                key1, key2, header.key_bits, 
                                header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        return 0;
    }

    uint8_t verification_check[VERIFICATION_DATA_SIZE];
    create_verification_data(key1, header.key_bits, header.salt, verification_check);

    if (memcmp(verification_check, header.verification_data, VERIFICATION_DATA_SIZE) != 0) {
        fprintf(stderr, "Chyba: Neplatne heslo alebo poskodene data\n");
        
        memset(password, 0, sizeof(password));
        memset(key1, 0, sizeof(key1));
        memset(key2, 0, sizeof(key2));
        
        return AES_XTS_ERROR_WRONG_PWD;
    }

    printf("Overenie hesla uspesne\n");
    
    result = process_sectors(ctx, key1, key2, header.start_sector, DECRYPT_MODE, header.key_bits);
    
    memset(password, 0, sizeof(password));
    memset(key1, 0, sizeof(key1));
    memset(key2, 0, sizeof(key2));
    
    return result;
}

int main(int argc, char *argv[]) {
    const char *operation = NULL;
    const char *device_path = NULL;
    int key_bits = DEFAULT_KEY_BITS;
    int result = AES_XTS_ERROR_PARAM; 
    
    if (!parse_arguments(argc, argv, &operation, &device_path, &key_bits)) {
        return EXIT_FAILURE;
    }
    
    aes_xts_init();
    
    device_context_t ctx = {0};
    
    if (!open_device(device_path, &ctx)) {
        fprintf(stderr, "Chyba: Nepodarilo sa otvorit zariadenie %s\n", device_path);
        aes_xts_cleanup();
        return EXIT_FAILURE;
    }
    
    if (strcmp(operation, "encrypt") == 0) {
        result = encrypt_device(&ctx, device_path, key_bits);
    }
    else if (strcmp(operation, "decrypt") == 0) {
        result = decrypt_device(&ctx);
    }
    else {
        fprintf(stderr, "Neznamy prikaz: %s\n", operation);
        result = AES_XTS_ERROR_PARAM;
    }
    
    close_device(&ctx);
    aes_xts_cleanup();
    
    if (result == AES_XTS_SUCCESS) {
        printf("\nOperacia uspesne dokoncena.\n");
        return EXIT_SUCCESS;
    }
    else if (result == 0) {
        printf("\nOperacia zrusena pouzivatelom.\n");
        return EXIT_SUCCESS;
    }
    else {
        fprintf(stderr, "\nOperacia zlyhala s chybovym kodom %d.\n", result);
        return EXIT_FAILURE;
    }
}