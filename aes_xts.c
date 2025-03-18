#include "aes_xts.h"
#include <ctype.h>
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

void aes_xts_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void aes_xts_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

void print_openssl_error(void) {
    uint8_t err_msg[1024];
    uint32_t err = ERR_get_error();
    
    if(err != 0) {
        ERR_error_string_n(err, (char*)err_msg, sizeof(err_msg));
        fprintf(stderr, "OpenSSL Chyba: %s\n", err_msg);
    }
}

void show_progress(uint64_t current, uint64_t total, uint64_t sector_num) {
    if (sector_num % 10000 == 0 || current >= total - SECTOR_SIZE) {
        float progress = (float)current * 100.0f / (float)total;
        if (progress > 100.0f) progress = 100.0f;
        
        #ifdef _WIN32
        printf("Priebeh: %.1f%% (%llu/%llu MB)\r", 
        #else
        printf("Priebeh: %.1f%% (%lu/%lu MB)\r",
        #endif
               progress,
               (current / (1024*1024)),
               (total / (1024*1024)));
        fflush(stdout);
        
        #ifdef _WIN32
        Sleep(10);
        #else
        usleep(10000); 
        #endif
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
    size_t key_size = key_bits / 8;
    uint8_t combined_key[KEY_SIZE * 2]; 
    const EVP_CIPHER *cipher;
    
    #ifdef _WIN32
    uint64_t effective_sector = sector_num + RESERVED_SECTORS;
    #else
    uint64_t effective_sector = sector_num;
    #endif
    
    *(uint64_t*)iv = effective_sector;
    
    memcpy(combined_key, key1, key_size);
    memcpy(combined_key + key_size, key2, key_size);

    if (key_bits == 128) {
        cipher = EVP_aes_128_xts();
    } else {
        cipher = EVP_aes_256_xts(); 
    }
    
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }

    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, combined_key, iv) != 1 ||
            EVP_EncryptUpdate(ctx, data, &len, data, data_len) != 1 ||
            EVP_EncryptFinal_ex(ctx, data + len, &len) != 1) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            return AES_XTS_ERROR_OPENSSL;
        }
    } else {
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, combined_key, iv) != 1 ||
            EVP_DecryptUpdate(ctx, data, &len, data, data_len) != 1 ||
            EVP_DecryptFinal_ex(ctx, data + len, &len) != 1) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            return AES_XTS_ERROR_OPENSSL;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return AES_XTS_SUCCESS;
}

int32_t aes_xts_encrypt_sector(
    const uint8_t *key1,
    const uint8_t *key2,
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int key_bits  
) {
    return aes_xts_crypt_sector(key1, key2, sector_num, data, data_len, 1, key_bits);
}

int32_t aes_xts_decrypt_sector(
    const uint8_t *key1,
    const uint8_t *key2,
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int key_bits  
) {
    return aes_xts_crypt_sector(key1, key2, sector_num, data, data_len, 0, key_bits);
}

int derive_keys_from_password(
    const char *password, 
    const unsigned char *salt,
    size_t salt_len,
    unsigned char *key1, 
    unsigned char *key2,
    int key_bits, 
    uint32_t iterations,
    uint32_t memory_cost
) {
    size_t key_len = key_bits / 8;
    unsigned char combined_key[KEY_SIZE_256 * 2];
    
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
    
    OSSL_PARAM params[6];
    params[0] = OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen(password));
    params[1] = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
    params[2] = OSSL_PARAM_construct_uint32("iterations", &iterations);
    params[3] = OSSL_PARAM_construct_uint32("m_cost", &memory_cost);
    params[4] = OSSL_PARAM_construct_uint32("parallelism", &(uint32_t){4}); 
    params[5] = OSSL_PARAM_construct_end();
    
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

void read_password(char *password, size_t max_len, const char *prompt) {
    printf("%s", prompt);
    fflush(stdout);
    
    size_t i = 0;
    int c;
    
    #ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    
    while (i < max_len - 1) {
        c = _getch();
        
        if (c == '\r' || c == '\n') { 
            break;
        }
        else if (c == '\b' && i > 0) {
            i--;
            printf("\b \b"); 
            fflush(stdout);
        }
        else if (c >= 32 && c <= 126) {
            password[i++] = c;
            printf("*");
            fflush(stdout);
        }
    }
    
    SetConsoleMode(hStdin, mode);
    #else
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    
    while (i < max_len - 1) {
        c = getchar();
        
        if (c == '\n' || c == EOF) {
            break;
        }
        else if (c == 127 || c == '\b') { 
            if (i > 0) {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
        }
        else if (c >= 32 && c <= 126) { 
            password[i++] = c;
            printf("*");
            fflush(stdout);
        }
    }
    
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    #endif
    
    password[i] = '\0';
    printf("\n");
}

int open_device(const char *path, device_context_t *ctx) {
    #ifdef _WIN32
    ctx->type = get_device_type(path);
    
    strncpy(ctx->path, path, MAX_PATH - 1);
    ctx->path[MAX_PATH - 1] = '\0';
    
    check_volume(path);
    
    if (!prepare_device_for_encryption(path, &ctx->handle)) {
        return 0;
    }
    ctx->size = get_device_size(ctx->handle, ctx->type);
    return ctx->size.QuadPart != 0;
    #else
    if (is_partition_mounted(path)) {
        fprintf(stderr, "Chyba: Oddiel %s je pripojeny. Odpojte ho pred operaciou.\n", path);
        return 0;
    }
    
    ctx->fd = open(path, O_RDWR);
    if (ctx->fd < 0) {
        perror("Chyba pri otvarani zariadenia");
        return 0;
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

int process_sectors(
    device_context_t *ctx,
    uint8_t *key1,
    uint8_t *key2,
    uint64_t start_sector,
    int encrypt,
    int key_bits
) {
    unsigned char *buffer = NULL;
    uint64_t sector_num = 0;
    uint64_t total_size = 0;
    
    #ifdef _WIN32
    DWORD bytesRead, bytesWritten;
    LARGE_INTEGER currentOffset, startOffset;
    startOffset.QuadPart = (LONGLONG)start_sector * SECTOR_SIZE;
    currentOffset.QuadPart = startOffset.QuadPart;
    
    buffer = (unsigned char *)_aligned_malloc(BUFFER_SIZE + SECTOR_SIZE, SECTOR_SIZE);
    #else
    ssize_t bytesRead, bytesWritten;
    uint64_t currentOffset, startOffset;
    startOffset = start_sector * SECTOR_SIZE;
    currentOffset = startOffset;
    
    buffer = (unsigned char *)malloc(BUFFER_SIZE + SECTOR_SIZE);
    #endif
    
    if (!buffer) {
        fprintf(stderr, "Zlyhala alokacia pamate\n");
        return AES_XTS_ERROR_IO;
    }
    
    memset(buffer, 0, BUFFER_SIZE + SECTOR_SIZE);
    
    #ifdef _WIN32
    if (!SetFilePointerEx(ctx->handle, startOffset, NULL, FILE_BEGIN)) {
        fprintf(stderr, "Chyba pri nastaveni pozicie v subore: %lu\n", GetLastError());
        _aligned_free(buffer);
        return AES_XTS_ERROR_IO;
    }
    total_size = ctx->size.QuadPart - startOffset.QuadPart;
    #else
    if (lseek(ctx->fd, (off_t)startOffset, SEEK_SET) != (off_t)startOffset) {
        perror("Chyba pri vyhladavani v zariadeni");
        free(buffer);
        return AES_XTS_ERROR_IO;
    }
    total_size = ctx->size - startOffset;
    #endif

    while (1) {
        #ifdef _WIN32
        if (currentOffset.QuadPart >= (LONGLONG)(startOffset.QuadPart + total_size))
            break;
            
        DWORD bytesToProcess = min(BUFFER_SIZE, ctx->size.QuadPart - currentOffset.QuadPart);
        DWORD bytesToRead = ((bytesToProcess + SECTOR_SIZE - 1) / SECTOR_SIZE) * SECTOR_SIZE;
        bytesToRead = min(bytesToRead, BUFFER_SIZE);
        
        if (!ReadFile(ctx->handle, buffer, bytesToRead, &bytesRead, NULL)) {
            DWORD error = GetLastError();
            if (error == ERROR_HANDLE_EOF) break;
            fprintf(stderr, "Chyba pri citani dat: %lu\n", error);
            _aligned_free(buffer);
            return AES_XTS_ERROR_IO;
        }
        #else
        if (currentOffset >= total_size + startOffset)
            break;
            
        size_t bytesToRead = BUFFER_SIZE;
        if (currentOffset + bytesToRead > ctx->size) {
            bytesToRead = ctx->size - currentOffset;
        }
        
        bytesRead = read(ctx->fd, buffer, bytesToRead);
        #endif
        
        if (bytesRead <= 0) break;
        
        size_t completeSectors = bytesRead / SECTOR_SIZE;
        size_t remainderBytes = bytesRead % SECTOR_SIZE;
        
        #ifdef _OPENMP
        #pragma omp parallel for
        #endif
        for(size_t offset = 0; offset < completeSectors * SECTOR_SIZE; offset += SECTOR_SIZE) {
            uint64_t current_sector = sector_num + (offset / SECTOR_SIZE);
            if (encrypt)
                aes_xts_encrypt_sector(key1, key2, current_sector, buffer + offset, SECTOR_SIZE, key_bits);
            else
                aes_xts_decrypt_sector(key1, key2, current_sector, buffer + offset, SECTOR_SIZE, key_bits);
        }
        
        if (remainderBytes > 0) {
            #ifdef _WIN32
            uint8_t *lastSectorBuffer = (uint8_t*)_aligned_malloc(SECTOR_SIZE, SECTOR_SIZE);
            #else
            uint8_t *lastSectorBuffer = (uint8_t*)malloc(SECTOR_SIZE);
            #endif
            
            if (lastSectorBuffer) {
                memset(lastSectorBuffer, 0, SECTOR_SIZE);
                memcpy(lastSectorBuffer, buffer + completeSectors * SECTOR_SIZE, remainderBytes);
                
                uint64_t last_sector = sector_num + completeSectors;
                if (encrypt)
                    aes_xts_encrypt_sector(key1, key2, last_sector, lastSectorBuffer, SECTOR_SIZE, key_bits);
                else
                    aes_xts_decrypt_sector(key1, key2, last_sector, lastSectorBuffer, SECTOR_SIZE, key_bits);
                
                memcpy(buffer + completeSectors * SECTOR_SIZE, lastSectorBuffer, remainderBytes);
                
                #ifdef _WIN32
                _aligned_free(lastSectorBuffer);
                #else
                free(lastSectorBuffer);
                #endif
            }
        }
        
        #ifdef _WIN32
        if (!SetFilePointerEx(ctx->handle, currentOffset, NULL, FILE_BEGIN)) {
            fprintf(stderr, "Chyba pri nastaveni pozicie pre zapis: %lu\n", GetLastError());
            _aligned_free(buffer);
            return AES_XTS_ERROR_IO;
        }
        #else
        if (lseek(ctx->fd, (off_t)currentOffset, SEEK_SET) != (off_t)currentOffset) {
            perror("Chyba pri vyhladavani pre zapis");
            free(buffer);
            return AES_XTS_ERROR_IO;
        }
        #endif
        
        size_t bytesToWrite = completeSectors * SECTOR_SIZE;
        if (remainderBytes > 0) {
            bytesToWrite += remainderBytes;
        }
        
        #ifdef _WIN32
        if (!WriteFile(ctx->handle, buffer, bytesToWrite, &bytesWritten, NULL) || 
            bytesWritten != bytesToWrite) {
            fprintf(stderr, "Chyba pri zapise dat: %lu\n", GetLastError());
            _aligned_free(buffer);
            return AES_XTS_ERROR_IO;
        }
        #else
        bytesWritten = write(ctx->fd, buffer, bytesToWrite);
        if ((size_t)bytesWritten != bytesToWrite) {
            perror("Chyba pri zapise dat");
            free(buffer);
            return AES_XTS_ERROR_IO;
        }
        #endif
        
        #ifdef _WIN32
        currentOffset.QuadPart += bytesWritten;
        #else
        currentOffset += bytesWritten;
        #endif

        sector_num += completeSectors;

        #ifdef _WIN32
        uint64_t progress = currentOffset.QuadPart - startOffset.QuadPart;
        #else
        uint64_t progress = currentOffset - startOffset;
        #endif
        show_progress(progress, total_size, sector_num);
    }
    
    #ifdef _WIN32
    _aligned_free(buffer);
    #else
    free(buffer);
    #endif
    
    return AES_XTS_SUCCESS;
}

int write_header_common(device_context_t *ctx, const xts_header_t *header) {
    unsigned char *sector = NULL;
    int result = AES_XTS_ERROR_IO;
    
    #ifdef _WIN32
    sector = (unsigned char *)_aligned_malloc(SECTOR_SIZE, SECTOR_SIZE);
    #else
    sector = (unsigned char *)malloc(SECTOR_SIZE);
    #endif
    
    if (!sector) {
        fprintf(stderr, "Zlyhala alokacia vyrovanavacej pamate pre hlavicku\n");
        return AES_XTS_ERROR_IO;
    }

    memset(sector, 0, SECTOR_SIZE);
    memcpy(sector, header, sizeof(xts_header_t));
    
    uint64_t offset = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;

    #ifdef _WIN32
    LARGE_INTEGER li;
    li.QuadPart = 0;
    
    if (!SetFilePointerEx(ctx->handle, li, NULL, FILE_BEGIN)) {
        fprintf(stderr, "Zlyhalo nastavenie ukazatela suboru: %lu\n", GetLastError());
        goto cleanup;
    }
    
    li.QuadPart = offset;
    if (!SetFilePointerEx(ctx->handle, li, NULL, FILE_BEGIN)) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    DWORD bytesWritten;
    if (!WriteFile(ctx->handle, sector, SECTOR_SIZE, &bytesWritten, NULL)) {
        fprintf(stderr, "Zlyhalo zapisanie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (bytesWritten != SECTOR_SIZE) {
        fprintf(stderr, "Zlyhalo zapisanie kompletnej hlavicky: %lu bajtov zapisanych\n", bytesWritten);
        goto cleanup;
    }

    FlushFileBuffers(ctx->handle);
    #else
    if (lseek(ctx->fd, (off_t)offset, SEEK_SET) != (off_t)offset) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky\n");
        goto cleanup;
    }

    if (write(ctx->fd, sector, SECTOR_SIZE) != SECTOR_SIZE) {
        fprintf(stderr, "Zlyhalo zapisanie hlavicky\n");
        goto cleanup;
    }

    fsync(ctx->fd);
    #endif

    result = AES_XTS_SUCCESS;

cleanup:
    #ifdef _WIN32
    SecureZeroMemory(sector, SECTOR_SIZE);
    _aligned_free(sector);
    #else
    memset(sector, 0, SECTOR_SIZE);
    free(sector);
    #endif
    
    return result;
}

int read_header_common(device_context_t *ctx, xts_header_t *header) {
    unsigned char *sector = NULL;
    int result = AES_XTS_ERROR_IO;
    uint64_t offset = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;
    
    #ifdef _WIN32
    DWORD bytesRead;
    sector = (unsigned char *)_aligned_malloc(SECTOR_SIZE, SECTOR_SIZE);
    #else
    ssize_t bytesRead;
    sector = (unsigned char *)malloc(SECTOR_SIZE);
    #endif
    
    if (!sector) {
        fprintf(stderr, "Zlyhala alokacia vyrovanavacej pamate pre hlavicku\n");
        return AES_XTS_ERROR_IO;
    }
    
    memset(sector, 0, SECTOR_SIZE);
    
    #ifdef _WIN32
    LARGE_INTEGER zero = {0};
    if (!SetFilePointerEx(ctx->handle, zero, NULL, FILE_BEGIN)) {
        fprintf(stderr, "Zlyhalo nastavenie ukazatela suboru: %lu\n", GetLastError());
        goto cleanup;
    }
    
    LARGE_INTEGER li;
    li.QuadPart = offset;
    if (!SetFilePointerEx(ctx->handle, li, NULL, FILE_BEGIN)) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (!ReadFile(ctx->handle, sector, SECTOR_SIZE, &bytesRead, NULL)) {
        fprintf(stderr, "Zlyhalo citanie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    #else
    if (lseek(ctx->fd, (off_t)offset, SEEK_SET) != (off_t)offset) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky\n");
        goto cleanup;
    }

    bytesRead = read(ctx->fd, sector, SECTOR_SIZE);
    #endif
    
    if (bytesRead != SECTOR_SIZE) {
        fprintf(stderr, "Zlyhalo nacitanie kompletneho sektora hlavicky (%lu bajtov nacitanych)\n", 
                (unsigned long)bytesRead);
        goto cleanup;
    }
    
    memcpy(header, sector, sizeof(xts_header_t));
    
    if (memcmp(header->magic, "AESXTS", 6) != 0) {
        fprintf(stderr, "Neplatna magicka hodnota v hlavicke\n");
        result = AES_XTS_ERROR_PARAM;
        goto cleanup;
    }
    
    result = AES_XTS_SUCCESS;
    
cleanup:
    #ifdef _WIN32
    SecureZeroMemory(sector, SECTOR_SIZE);
    _aligned_free(sector);
    #else
    memset(sector, 0, SECTOR_SIZE);
    free(sector);
    #endif
    
    return result;
}


#ifdef _WIN32
int write_header(device_context_t *ctx, const xts_header_t *header) {
    unsigned char *sector = NULL;
    int result = AES_XTS_ERROR_IO;
    DWORD bytesWritten;
    
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)HEADER_SECTOR * SECTOR_SIZE;
    
    printf("Zapisovanie hlavicky do sektora %d\n", HEADER_SECTOR);
    
    sector = (unsigned char *)_aligned_malloc(SECTOR_SIZE, SECTOR_SIZE);
    if (!sector) {
        fprintf(stderr, "Zlyhala alokacia vyrovanavacej pamate pre hlavicku\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    memset(sector, 0, SECTOR_SIZE);
    memcpy(sector, header, sizeof(xts_header_t));
    printf("Zapisovanie hlavicky - magic: %.6s verzia: %u\n", 
           header->magic, header->version);
    
    DWORD bytesReturned;
    DeviceIoControl(ctx->handle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    
    if (SetFilePointer(ctx->handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Zlyhalo nastavenie ukazatela suboru\n");
        goto cleanup;
    }
    
    if (SetFilePointer(ctx->handle, (LONG)offset.QuadPart, 
                       (PLONG)(&offset.HighPart), FILE_BEGIN) == INVALID_SET_FILE_POINTER && 
        GetLastError() != NO_ERROR) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (!WriteFile(ctx->handle, sector, SECTOR_SIZE, &bytesWritten, NULL)) {
        fprintf(stderr, "Zlyhalo zapisanie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (bytesWritten != SECTOR_SIZE) {
        fprintf(stderr, "Zlyhalo zapisanie kompletnej hlavicky (zapisanych %lu bajtov)\n", bytesWritten);
        goto cleanup;
    }
    
    FlushFileBuffers(ctx->handle);
    result = AES_XTS_SUCCESS;
    
cleanup:
    if (sector) {
        SecureZeroMemory(sector, SECTOR_SIZE);
        _aligned_free(sector);
    }
    return result;
}

int read_header(device_context_t *ctx, xts_header_t *header) {
    unsigned char *sector = NULL;
    int result = AES_XTS_ERROR_IO;
    DWORD bytesRead;
    
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)HEADER_SECTOR * SECTOR_SIZE;
    
    printf("Citanie hlavicky zo sektora %d\n", HEADER_SECTOR);
    
    sector = (unsigned char *)_aligned_malloc(SECTOR_SIZE, SECTOR_SIZE);
    if (!sector) {
        fprintf(stderr, "Zlyhala alokacia vyrovanavacej pamate pre hlavicku\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    memset(sector, 0, SECTOR_SIZE);
    
    if (SetFilePointer(ctx->handle, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        fprintf(stderr, "Zlyhalo nastavenie ukazatela suboru\n");
        goto cleanup;
    }
    
    if (SetFilePointer(ctx->handle, (LONG)offset.QuadPart, 
                       (PLONG)(&offset.HighPart), FILE_BEGIN) == INVALID_SET_FILE_POINTER && 
        GetLastError() != NO_ERROR) {
        fprintf(stderr, "Zlyhalo vyhladavanie pozicie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (!ReadFile(ctx->handle, sector, SECTOR_SIZE, &bytesRead, NULL)) {
        fprintf(stderr, "Zlyhalo citanie hlavicky: %lu\n", GetLastError());
        goto cleanup;
    }
    
    if (bytesRead != SECTOR_SIZE) {
        fprintf(stderr, "Zlyhalo nacitanie kompletnej hlavicky (nacitanych %lu bajtov)\n", bytesRead);
        goto cleanup;
    }
    
    memcpy(header, sector, sizeof(xts_header_t));
    
    if (memcmp(header->magic, "AESXTS", 6) != 0) {
        fprintf(stderr, "Neplatna magicka hodnota v hlavicke\n");
        result = AES_XTS_ERROR_PARAM;
        goto cleanup;
    }
    
    result = AES_XTS_SUCCESS;
    
cleanup:
    if (sector) {
        SecureZeroMemory(sector, SECTOR_SIZE);
        _aligned_free(sector);
    }
    return result;
}

BOOL is_admin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2,
                               SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS,
                               0, 0, 0, 0, 0, 0,
                               &AdminGroup)) {
        CheckTokenMembership(NULL, AdminGroup, &isAdmin);
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

device_type_t get_device_type(const char *path) {
    return (strncmp(path, "\\\\.\\PhysicalDrive", 17) == 0) ? 
            DEVICE_TYPE_DISK : DEVICE_TYPE_VOLUME;
}

BOOL lock_and_dismount(HANDLE hDevice) {
    DWORD bytesReturned;
    
    DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    
    BOOL result = DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    
    if (!result)
        fprintf(stderr, "Upozornenie: Nepodarilo sa odpojit zvazok: %lu\n", GetLastError());
        
    return result;
}

void unlock_disk(HANDLE hDevice) {
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    }
}

void check_volume(const char *path) {
    if (path[0] == '\\' && path[1] == '\\' && path[2] == '.' && path[3] == '\\' && isalpha(path[4])) {
        char drive[3] = { path[4], ':', 0 };
        printf("Priprava jednotky %s na pristup\n", drive);
    }
}

LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t type) {
    LARGE_INTEGER size = {0};
    DWORD bytesReturned;
    
    if (type == DEVICE_TYPE_VOLUME) {
        GET_LENGTH_INFORMATION lengthInfo;
        if (DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
                          &lengthInfo, sizeof(lengthInfo), &bytesReturned, NULL)) {
            size.QuadPart = lengthInfo.Length.QuadPart;
            printf("Velkost zariadenia z IOCTL: %lld bajtov\n", size.QuadPart);
            return size;
        }
    } else {
        DISK_GEOMETRY_EX diskGeometry;
        if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
                          &diskGeometry, sizeof(diskGeometry), &bytesReturned, NULL)) {
            size.QuadPart = diskGeometry.DiskSize.QuadPart;
            printf("Velkost zariadenia z IOCTL: %lld bajtov\n", size.QuadPart);
            return size;
        }
    }

    LARGE_INTEGER zero = {0};
    if (SetFilePointerEx(hDevice, zero, &size, FILE_END)) {
        printf("Velkost zariadenia z vyhladavania: %lld bajtov\n", size.QuadPart);
        SetFilePointerEx(hDevice, zero, NULL, FILE_BEGIN);
        return size;
    }
    
    fprintf(stderr, "Zlyhalo zistenie velkosti zariadenia: %lu\n", GetLastError());
    return size;
}

int prepare_device_for_encryption(const char *path, HANDLE *handle) {
    if (!is_admin()) {
        fprintf(stderr, "Chyba: Vyzaduju sa administratorske opravnenia\n");
        return 0;
    }
    
    check_volume(path);
    
    *handle = CreateFileA(
        path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    printf("Pokus o otvorenie v standardnom rezime zdielania...\n");
    
    if (*handle == INVALID_HANDLE_VALUE) {
        printf("Pokus o otvorenie s exkluzivnym pristupom...\n");
        *handle = CreateFileA(
            path,
            GENERIC_READ | GENERIC_WRITE,
            0, 
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
            NULL
        );
    }
    
    if (*handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Zlyhalo otvorenie zariadenia: %lu\n", GetLastError());
        return 0;
    }
    
    printf("Zariadenie uspesne otvorene pomocou %s\n", 
           (*handle != INVALID_HANDLE_VALUE) ? "standardneho rezimu zdielania" : "exkluzivneho pristupu");
    
    printf("Pokus o odpojenie zvazku...\n");
    if (lock_and_dismount(*handle)) {
        printf("Zvazok uspesne odpojeny\n");
    }
    
    DWORD bytesReturned;
    DeviceIoControl(*handle, FSCTL_ALLOW_EXTENDED_DASD_IO, 
                  NULL, 0, NULL, 0, &bytesReturned, NULL);
    
    BYTE testBuffer[SECTOR_SIZE];
    DWORD bytesRead;
    if (ReadFile(*handle, testBuffer, SECTOR_SIZE, &bytesRead, NULL)) {
        printf("Uspesne nacitanych %lu bajtov zo zariadenia\n", bytesRead);
        SetFilePointer(*handle, 0, NULL, FILE_BEGIN);
    }
    
    return (*handle != INVALID_HANDLE_VALUE);
}
#else
int write_header(device_context_t *ctx, const xts_header_t *header) {
    return write_header_common(ctx, header);
}

int read_header(device_context_t *ctx, xts_header_t *header) {
    return read_header_common(ctx, header);
}
#endif

int process_user_confirmation(const char *device_path, int key_bits) {
    printf("UPOZORNENIE: Vsetky data na zariadeni %s budu zasifrovane s %d-bitovym klucom!\n", 
           device_path, key_bits);
    
    printf("Chcete pokracovat? (a/n): ");
    
    char confirm;
    if (scanf(" %c", &confirm) != 1) {
        fprintf(stderr, "Chyba pri citani potvrdenia\n");
        return 0;
    }
    
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    return (confirm == 'a' || confirm == 'A' || confirm == 'y' || confirm == 'Y');
}

int process_password_input(char *password, size_t password_size, int verify) {
    read_password(password, password_size, "Zadajte heslo: ");
    
    if (strlen(password) < 8) {
        fprintf(stderr, "Heslo musi mat aspon 8 znakov\n");
        return 0;
    }
    
    if (verify) {
        char confirm_password[128];
        read_password(confirm_password, sizeof(confirm_password), "Potvrdte heslo: ");
        
        if (strcmp(password, confirm_password) != 0) {
            fprintf(stderr, "Hesla sa nezhoduju\n");
            return 0;
        }
    }
    
    return 1;
}

void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data) {
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);

    OSSL_PARAM params[2];
    char md_name[] = "SHA256";
    params[0] = OSSL_PARAM_construct_utf8_string("digest", md_name, strlen(md_name));
    params[1] = OSSL_PARAM_construct_end();

    size_t hmac_key_len = key_bits == 256 ? 32 : 16;
    EVP_MAC_init(hmac_ctx, key, hmac_key_len, params);

    const char *verify_str = "AES-XTS-VERIFY";
    EVP_MAC_update(hmac_ctx, (uint8_t *)verify_str, strlen(verify_str));
    EVP_MAC_update(hmac_ctx, salt, SALT_LENGTH);

    size_t out_len = 32;
    EVP_MAC_final(hmac_ctx, verification_data, &out_len, 32);

    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
}

#ifndef _WIN32

int is_partition_mounted(const char *device_path) {
    FILE *mtab = fopen("/proc/mounts", "r");
    if (!mtab) return 0;

    char line[1024];
    int mounted = 0;

    while (fgets(line, sizeof(line), mtab)) {
        if (strstr(line, device_path)) {
            mounted = 1;
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

int main(int argc, char *argv[]) {
    int result = 0;
    char password[128];
    device_context_t ctx = {0};
    int key_bits = 256; 
    
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
        return 1;
    }

    aes_xts_init();
    
    const char *operation = argv[1];
    const char *device_path = NULL;
    
    if (argc >= 4 && (strcmp(argv[2], "128") == 0 || strcmp(argv[2], "256") == 0)) {
        key_bits = atoi(argv[2]);
        device_path = argv[3];
    } else if (argc >= 3) {
        device_path = argv[2];
    }

    if (!device_path) {
        fprintf(stderr, "Chyba: Nie je zadana cesta k zariadeniu\n");
        printf("Pouzite %s pre napovedu\n", argv[0]);
        aes_xts_cleanup();
        return 1;
    }

    if (strcmp(operation, "encrypt") == 0) {
        printf("Pouziva sa %d-bitove sifrovanie\n", key_bits);
    }
    
    uint8_t key1[KEY_SIZE], key2[KEY_SIZE];
    xts_header_t header;

    if (!open_device(device_path, &ctx)) {
        fprintf(stderr, "Zlyhalo otvorenie zariadenia\n");
        aes_xts_cleanup();
        return 1;
    }

    if (strcmp(operation, "encrypt") == 0) {
        if (!process_user_confirmation(device_path, key_bits)) {
            printf("Sifrovanie zrusene.\n");
            close_device(&ctx);
            aes_xts_cleanup();
            return 0;
        }
        
        if (!process_password_input(password, sizeof(password), 1)) {
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        memset(&header, 0, sizeof(header));
        memcpy(header.magic, "AESXTS", 6);
        header.version = 1;
        header.encryption_type = 1;
        header.start_sector = RESERVED_SECTORS;
        header.iterations = 10;
        header.memory_cost = 65536;
        header.key_bits = key_bits; 

        if (!RAND_bytes(header.salt, SALT_SIZE)) {
            print_openssl_error();
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                                    key1, key2, key_bits,
                                    header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }
        
        create_verification_data(key1, key_bits, header.salt, header.verification_data);
        printf("Verifikacne data vytvorene\n");

        if (write_header(&ctx, &header) != AES_XTS_SUCCESS) {
            fprintf(stderr, "Zlyhalo zapisanie hlavicky\n");
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        result = process_sectors(&ctx, key1, key2, header.start_sector, 1, key_bits);
    } 
    else if (strcmp(operation, "decrypt") == 0) {
        if (read_header(&ctx, &header) != AES_XTS_SUCCESS) {
            fprintf(stderr, "Zlyhalo nacitanie hlavicky alebo neplatna hlavicka\n");
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }
        
        if (!process_password_input(password, sizeof(password), 0)) {
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        printf("Pouziva sa %d-bitove sifrovanie (z hlavicky)\n", header.key_bits);

        if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                                    key1, key2, header.key_bits, 
                                    header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        uint8_t verification_check[32];
        create_verification_data(key1, header.key_bits, header.salt, verification_check);

        if (memcmp(verification_check, header.verification_data, 32) != 0) {
            fprintf(stderr, "Chyba: Neplatne heslo alebo poskodene data\n");
            close_device(&ctx);
            aes_xts_cleanup();
            return 1;
        }

        printf("Overenie hesla uspesne\n");
        
        result = process_sectors(&ctx, key1, key2, header.start_sector, 0, header.key_bits);
    }
    else {
        fprintf(stderr, "Neznamy prikaz: %s\n", operation);
        close_device(&ctx);
        aes_xts_cleanup();
        return 1;
    }

    close_device(&ctx);
    aes_xts_cleanup();
    
    if (result == AES_XTS_SUCCESS) {
        printf("\nOperacia uspesne dokoncena.\n");
    }
    return result;
}