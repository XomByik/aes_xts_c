#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/thread.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// Konštanty pre nastavenie šifrovania
#define BUFFER_SIZE 4096            // Veľkosť bufferu na šifrovanie a dešifrovanie
#define AES_KEY_LENGTH 32           // Dĺžka kľúča pre 128-bitový AES-XTS (2 x 128-bitové kľúče)
#define SALT_LENGTH 16              // Dĺžka salt hodnoty pre odvodenie kľúča
#define MAX_LINE_LENGTH 2048        // Maximálna dĺžka riadku pri načítaní testovacích vektorov

// Štruktúra na ukladanie testovacích vektorov (klúčov, tweak hodnôt a plaintext/ciphertext dvojíc)
typedef struct {
    unsigned char key1[16];         // Prvý 128-bitový kľúč
    unsigned char key2[16];         // Druhý 128-bitový kľúč
    unsigned char ducn[16];         // 128-bitová tweak hodnota (DUCN) pre AES-XTS
    unsigned char *plaintext;       // Pole bajtov pre plaintext
    int plaintext_len;              // Dĺžka plaintextu
    unsigned char *ciphertext;      // Pole bajtov pre ciphertext
    int ciphertext_len;             // Dĺžka ciphertextu
} TestVector;

// Funkcia na výpis chýb v OpenSSL
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Funkcia na konverziu hexadecimálneho reťazca na bajty
// Prevodí hex reťazec na bajty a ukladá ich do poľa `bytes`
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len) {
    int len = strlen(hex_str);
    if (len != expected_len * 2) {
        return -1;
    }
    for (int i = 0; i < expected_len; i++) {
        if (sscanf(&hex_str[i * 2], "%2hhx", &bytes[i]) != 1) {
            return -1;
        }
    }
    return expected_len;
}

// Funkcia na odvodenie kľúča z hesla pomocou Argon2id
// Používa KDF funkciu Argon2id na generovanie kľúča z hesla a salt hodnoty
int derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[8];
    size_t out_len = AES_KEY_LENGTH;

    // Nastavenie parametrov pre Argon2id (počet iterácií, pamäť, lanes, vlákna)
    uint32_t iteracie = 3;
    uint32_t pamet_kost = 65536; 
    uint32_t lanes = 4;
    uint32_t threads = 2;

    if (OSSL_set_max_threads(NULL, threads) != 1) {
        fprintf(stderr, "Chyba pri nastavovaní maximálneho počtu vlákien\n");
        return -1;
    }

    // Konfigurácia parametrov pre KDF
    OSSL_PARAM *p = params;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)password, strlen(password));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, SALT_LENGTH);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iteracie);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &pamet_kost);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &out_len);
    *p++ = OSSL_PARAM_construct_end();

    // Inicializácia KDF pre Argon2id
    kdf = EVP_KDF_fetch(NULL, "Argon2id", NULL);
    if (kdf == NULL) {
        fprintf(stderr, "Chyba pri získavaní KDF Argon2id\n");
        return -1;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "Chyba pri vytváraní KDF kontextu\n");
        EVP_KDF_free(kdf);
        return -1;
    }

    // Derivácia kľúča na základe parametrov
    if (EVP_KDF_derive(kctx, key, out_len, params) != 1) {
        fprintf(stderr, "Chyba pri odvodení kľúča\n");
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return -1;
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_set_max_threads(NULL, 0);

    return 0;
}

// Funkcia na načítanie testovacích vektorov zo súboru
// V každom riadku súboru sú uložené parametre ako `Key1`, `Key2`, `DUCN`, `PTX`, a `CTX`
int load_test_vectors(const char *filename, TestVector **vectors, int *count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Nemôžem otvoriť súbor s testovacími vektormi");
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    TestVector *temp_vectors = NULL;
    int temp_count = 0;
    TestVector current_vector;
    memset(&current_vector, 0, sizeof(TestVector));

    // Načítavanie každého riadku a ukladanie údajov do aktuálneho testovacieho vektora
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) { 
            if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
                temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
                if (!temp_vectors) {
                    perror("Chyba alokácie pamäte pre testovacie vektory");
                    fclose(file);
                    return -1;
                }
                temp_vectors[temp_count++] = current_vector;
                memset(&current_vector, 0, sizeof(TestVector));
                current_vector.plaintext = NULL;
                current_vector.ciphertext = NULL;
            }
            continue;
        }

        char *key = strtok(line, " ");
        char *value = strtok(NULL, " ");
        if (!key || !value) {
            fprintf(stderr, "Neplatný formát riadku: %s\n", line);
            fclose(file);
            return -1;
        }

        // Spracovanie kľúčov a dát na základe názvov
        if (strcmp(key, "Key1") == 0) {
            if (hex_to_bytes(value, current_vector.key1, 16) != 16) {
                fprintf(stderr, "Chyba pri konverzii Key1: %s\n", value);
                fclose(file);
                return -1;
            }
        } else if (strcmp(key, "Key2") == 0) {
            if (hex_to_bytes(value, current_vector.key2, 16) != 16) {
                fprintf(stderr, "Chyba pri konverzii Key2: %s\n", value);
                fclose(file);
                return -1;
            }
        } else if (strcmp(key, "DUCN") == 0) {
            if (hex_to_bytes(value, current_vector.ducn, 16) != 16) {
                fprintf(stderr, "Chyba pri konverzii DUCN: %s\n", value);
                fclose(file);
                return -1;
            }
        } else if (strcmp(key, "PTX") == 0) {
            int len = strlen(value) / 2;
            unsigned char *new_plaintext = realloc(current_vector.plaintext, current_vector.plaintext_len + len);
            if (!new_plaintext) {
                perror("Chyba alokácie pamäte pre PTX");
                fclose(file);
                return -1;
            }
            current_vector.plaintext = new_plaintext;
            if (hex_to_bytes(value, current_vector.plaintext + current_vector.plaintext_len, len) != len) {
                fprintf(stderr, "Chyba pri konverzii PTX: %s\n", value);
                fclose(file);
                return -1;
            }
            current_vector.plaintext_len += len;
        } else if (strcmp(key, "CTX") == 0) {
            int len = strlen(value) / 2;
            unsigned char *new_ciphertext = realloc(current_vector.ciphertext, current_vector.ciphertext_len + len);
            if (!new_ciphertext) {
                perror("Chyba alokácie pamäte pre CTX");
                fclose(file);
                return -1;
            }
            current_vector.ciphertext = new_ciphertext;
            if (hex_to_bytes(value, current_vector.ciphertext + current_vector.ciphertext_len, len) != len) {
                fprintf(stderr, "Chyba pri konverzii CTX: %s\n", value);
                fclose(file);
                return -1;
            }
            current_vector.ciphertext_len += len;
        } else {
            fprintf(stderr, "Neznámy parameter: %s\n", key);
            fclose(file);
            return -1;
        }
    }

    // Ukladanie posledného testovacieho vektora
    if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
        temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
        if (!temp_vectors) {
            perror("Chyba alokácie pamäte pre posledný testovací vektor");
            fclose(file);
            return -1;
        }
        temp_vectors[temp_count++] = current_vector;
    }

    fclose(file);
    *vectors = temp_vectors;
    *count = temp_count;
    return 0;
}

// Funkcia na šifrovanie alebo dešifrovanie AES-XTS s tweak hodnotou
// Používa tweak (napr. DUCN) a inicializuje šifrovací/dešifrovací kontext
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak) {
    int len;
    *out_len = 0;

    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tweak, -1) != 1) {
        handle_errors();
    }

    if (EVP_CipherUpdate(ctx, out, &len, in, in_len) != 1) {
        return -1;
    }
    *out_len += len;

    if (EVP_CipherFinal_ex(ctx, out + *out_len, &len) != 1) {
        return -1;
    }
    *out_len += len;

    return 0;
}

// Funkcia na formátovanie výstupu v hexadecimálnom tvare
void print_hex_output(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Funkcia na testovanie načítaných vektorov so zobrazením detailov a kontrolou zhody
void test_vectors(TestVector *vectors, int vector_count) {
    for (int i = 0; i < vector_count; i++) {
        printf("Testovací vektor %d:\n", i + 1);

        unsigned char *key1 = vectors[i].key1;
        unsigned char *key2 = vectors[i].key2;
        unsigned char *tweak = vectors[i].ducn;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handle_errors();
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors();
        }

        unsigned char enc_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int enc_out_len = 0;
        if (aes_xts_crypt(ctx, vectors[i].plaintext, vectors[i].plaintext_len, enc_out, &enc_out_len, tweak) != 0) {
            fprintf(stderr, "Chyba pri šifrovaní testovacieho vektora %d\n", i + 1);
            EVP_CIPHER_CTX_free(ctx);
            continue;
        }

        print_hex_output("Key1", key1, 16);
        print_hex_output("Key2", key2, 16);
        print_hex_output("DUCN (tweak)", tweak, 16);
        print_hex_output("PTX (Plaintext)", vectors[i].plaintext, vectors[i].plaintext_len);
        print_hex_output("CTX (očakávaný Ciphertext)", vectors[i].ciphertext, vectors[i].ciphertext_len);
        print_hex_output("Vygenerovaný CTX (Ciphertext)", enc_out, enc_out_len);

        if (enc_out_len != vectors[i].ciphertext_len || memcmp(enc_out, vectors[i].ciphertext, enc_out_len) != 0) {
            printf("Nesúlad v šifrovaní pri testovacom vektore %d\n", i + 1);
        } else {
            printf("Šifrovanie úspešné pre testovací vektor %d\n", i + 1);
        }

        EVP_CIPHER_CTX_free(ctx);
        printf("\n");
    }
}

// Funkcia na cross-platform získanie hesla od používateľa
void get_password(char *password, size_t len) {
    printf("Zadajte heslo: ");

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);

    int i = 0;
    char ch;
    while ((ch = _getch()) != '\r' && i < len - 1) {
        if (ch == '\b' && i > 0) {
            printf("\b \b");
            i--;
        } else if (ch != '\b') {
            password[i++] = ch;
            printf("*"); 
        }
    }
    password[i] = '\0';
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fgets(password, len, stdin);
    password[strcspn(password, "\n")] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    printf("\n");
}

// Hlavná funkcia pre šifrovanie, dešifrovanie a testovanie
int main(int argc, char *argv[]) {
    if (argc < 3 || (strcmp(argv[1], "encrypt") != 0 && strcmp(argv[1], "decrypt") != 0 && strcmp(argv[1], "test") != 0)) {
        fprintf(stderr, "Použitie: %s <encrypt|decrypt|test> <súbor alebo test_vectors_file>\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];

    if (strcmp(operation, "test") == 0) {
        const char *test_file = argv[2];
        TestVector *vectors = NULL;
        int vector_count = 0;

        if (load_test_vectors(test_file, &vectors, &vector_count) != 0) {
            fprintf(stderr, "Chyba pri načítaní testovacích vektorov\n");
            return 1;
        }

        printf("Načítané testovacie vektory: %d\n\n", vector_count);
        test_vectors(vectors, vector_count);

        for (int i = 0; i < vector_count; i++) {
            free(vectors[i].plaintext);
            free(vectors[i].ciphertext);
        }
        free(vectors);
        return 0;
    }

    const char *input_filename = argv[2];
    const char *output_filename = argv[3];

    char password[256];
    get_password(password, sizeof(password));

    unsigned char salt[SALT_LENGTH];
    unsigned char key[AES_KEY_LENGTH];
    FILE *infile = fopen(input_filename, "rb");
    if (!infile) {
        perror("Chyba pri otváraní vstupného súboru");
        return 1;
    }
    FILE *outfile = fopen(output_filename, "wb");
    if (!outfile) {
        perror("Chyba pri otváraní výstupného súboru");
        fclose(infile);
        return 1;
    }

    if (strcmp(operation, "encrypt") == 0) {
        if (!RAND_bytes(salt, SALT_LENGTH)) {
            fprintf(stderr, "Chyba pri generovaní salt\n");
            fclose(infile);
            fclose(outfile);
            return 1;
        }
        if (fwrite(salt, 1, SALT_LENGTH, outfile) != SALT_LENGTH) {
            fprintf(stderr, "Chyba pri zápise salt do výstupného súboru\n");
            fclose(infile);
            fclose(outfile);
            return 1;
        }
    } else {
        if (fread(salt, 1, SALT_LENGTH, infile) != SALT_LENGTH) {
            fprintf(stderr, "Chyba pri čítaní salt zo vstupného súboru\n");
            fclose(infile);
            fclose(outfile);
            return 1;
        }
    }

    if (derive_key_from_password(password, salt, key) != 0) {
        fprintf(stderr, "Chyba pri odvodení kľúča\n");
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    unsigned char *key1 = key;
    unsigned char *key2 = key + 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors();
    }

    if (strcmp(operation, "encrypt") == 0) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors();
        }
    } else {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors();
        }
    }

    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;

    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, infile)) > 0) {
        if (strcmp(operation, "encrypt") == 0) {
            if (aes_xts_crypt(ctx, in_buf, in_len, out_buf, &out_len, salt) != 0) {
                fprintf(stderr, "Chyba pri šifrovaní dát\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(infile);
                fclose(outfile);
                return 1;
            }
        } else {
            if (aes_xts_crypt(ctx, in_buf, in_len, out_buf, &out_len, salt) != 0) {
                fprintf(stderr, "Chyba pri dešifrovaní dát\n");
                EVP_CIPHER_CTX_free(ctx);
                fclose(infile);
                fclose(outfile);
                return 1;
            }
        }
        if (fwrite(out_buf, 1, out_len, outfile) != (size_t)out_len) {
            fprintf(stderr, "Chyba pri zápise dát do výstupného súboru\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return 1;
        }
    }

    if (strcmp(operation, "encrypt") == 0) {
        if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
            fprintf(stderr, "Chyba pri finalizácii šifrovania\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return 1;
        }
    } else {
        if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1) {
            fprintf(stderr, "Chyba pri finalizácii dešifrovania\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return 1;
        }
    }

    if (fwrite(out_buf, 1, out_len, outfile) != (size_t)out_len) {
        fprintf(stderr, "Chyba pri zápise finalizovaných dát do výstupného súboru\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);
    EVP_cleanup();
    ERR_free_strings();

    printf("Operácia '%s' bola úspešne dokončená.\n", operation);
    return 0;
}
