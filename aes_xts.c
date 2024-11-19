//aes_xts.c

#include "aes_xts.h"

#define CHECK_OPENSSL_CALL(call, error_action) \
    if (!(call)) { \
        fprintf(stderr, "Chyba: %s, riadok %d\n", __FILE__, __LINE__); \
        handle_errors(); \
        error_action; \
    }

// Handle_errors
void handle_errors(void) {
    ERR_print_errors_fp(stderr); // Vypíše detaily o chybe na stderr
    exit(EXIT_FAILURE);          // Ukončí program s chybovým kódom
}

// Funkcia na zobrazenie nápovedy pre používateľa
void print_help() {
    printf("Použitie: program [operácia] [súbory...]\n");
    printf("Operácie:\n");
    printf("  encrypt [súbory...]  - Šifrovanie zadaných súborov\n");
    printf("  decrypt [súbory...]  - Dešifrovanie zadaných súborov\n");
    printf("  test [súbor]         - Testovanie šifrovania s testovacími vektormi\n");
}

// Šifrovanie alebo dešifrovanie pomocou AES-XTS
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak) {
    int len;
    *out_len = 0;
    CHECK_OPENSSL_CALL(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tweak, -1), return -1);
    CHECK_OPENSSL_CALL(EVP_CipherUpdate(ctx, out, &len, in, in_len), return -1);
    *out_len += len;
    CHECK_OPENSSL_CALL(EVP_CipherFinal_ex(ctx, out + *out_len, &len), return -1);
    *out_len += len;
    return 0;
}

// Pomocná funkcia na pridanie údajov do poľa
unsigned char* append_data(unsigned char *current_data, int *current_len, const char *hex_str, int hex_len) {
    unsigned char *new_data = realloc(current_data, *current_len + hex_len);
    hex_to_bytes(hex_str, new_data + *current_len, hex_len);
    *current_len += hex_len;
    return new_data;
}

// Načítanie testovacích vektorov zo súboru
int load_test_vectors(const char *filename, TestVector **vectors, int *count) {
    FILE *file = fopen(filename, "r");
    TestVector *temp_vectors = NULL;
    int temp_count = 0;
    TestVector current_vector = {0};
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0; // Odstránenie nového riadku
        if (strlen(line) == 0) {
            // Ak je riadok prázdny, uložiť aktuálny vektor
            if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
                temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
                if (!temp_vectors) {
                    perror("Chyba pri alokácii pamäte");
                    fclose(file);
                    return -1;
                }
                temp_vectors[temp_count++] = current_vector;
                memset(&current_vector, 0, sizeof(TestVector));
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
        // Rozhodovanie podľa typu kľúča
        if (strcmp(key, "Key1") == 0) {
            hex_to_bytes(value, current_vector.key1, 16);
        } else if (strcmp(key, "Key2") == 0) {
            hex_to_bytes(value, current_vector.key2, 16);
        } else if (strcmp(key, "DUCN") == 0) {
            hex_to_bytes(value, current_vector.ducn, 16);
        } else if (strcmp(key, "PTX") == 0) {
            int len = strlen(value) / 2;
            current_vector.plaintext = append_data(current_vector.plaintext, &current_vector.plaintext_len, value, len);
            if (!current_vector.plaintext) {
                fclose(file);
                return -1;
            }
        } else if (strcmp(key, "CTX") == 0) {
            int len = strlen(value) / 2;
            current_vector.ciphertext = append_data(current_vector.ciphertext, &current_vector.ciphertext_len, value, len);
            if (!current_vector.ciphertext) {
                fclose(file);
                return -1;
            }
        } else {
            fprintf(stderr, "Neznámy parameter: %s\n", key);
            fclose(file);
            return -1;
        }
    }
    // Uloženie posledného vektora
    if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
        temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
        temp_vectors[temp_count++] = current_vector;
    }
    fclose(file);
    *vectors = temp_vectors;
    *count = temp_count;
    return 0;
}

// Testovanie načítaných vektorov
void test_vectors(TestVector *vectors, int vector_count) {
    for (int i = 0; i < vector_count; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handle_errors();
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, vectors[i].key1, vectors[i].key2) != 1) {
            handle_errors();
        }

        unsigned char enc_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int enc_out_len = 0;

        aes_xts_crypt(ctx, vectors[i].plaintext, vectors[i].plaintext_len, enc_out, &enc_out_len, vectors[i].ducn);

        if (enc_out_len != vectors[i].ciphertext_len || memcmp(enc_out, vectors[i].ciphertext, enc_out_len) != 0) {
            fprintf(stderr, "Nesúlad v šifrovaní pri vektore %d\n", i + 1);
        } else {
            printf("Šifrovanie úspešné pre vektor %d\n", i + 1);
        }

        EVP_CIPHER_CTX_free(ctx);
    }
}

// Odvodenie kľúča z hesla pomocou Argon2id
int derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[8];
    size_t out_len = AES_KEY_LENGTH;

    // Parametre pre Argon2id
    uint32_t iterations = 3;
    uint32_t memory_cost = 65536; 
    uint32_t lanes = 4;
    uint32_t threads = 2;

    // Nastavenie maximálneho počtu vlákien pre KDF
    OSSL_set_max_threads(NULL, threads);

    // Konfigurácia parametrov pre KDF
    OSSL_PARAM *p = params;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)password, strlen(password));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, SALT_LENGTH);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_cost);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &out_len);
    *p++ = OSSL_PARAM_construct_end();

    // Inicializácia KDF pre Argon2id
    kdf = EVP_KDF_fetch(NULL, "Argon2id", NULL);

    kctx = EVP_KDF_CTX_new(kdf);

    // Derivácia kľúča
    EVP_KDF_derive(kctx, key, out_len, params);

    // Uvoľnenie pamäte
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_set_max_threads(NULL, 0);

    return 0; // Úspešné odvodenie kľúča
}

// Konverzia hexadecimálneho reťazca na pole bajtov
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len) {
    int len = strlen(hex_str);
    if (len != expected_len * 2) {
        return -1; // Nesprávna dĺžka hex reťazca
    }
    for (int i = 0; i < expected_len; i++) {
        if (sscanf(&hex_str[i * 2], "%2hhx", &bytes[i]) != 1) {
            return -1; // Chyba pri konverzii
        }
    }
    return expected_len;
}

// Zabezpečené získanie hesla od používateľa
void get_password(char *password, size_t len) {
    printf("Zadajte heslo: ");

// Windows/Linux zadávanie hesla
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
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
    tcgetattr(STDIN_FILENO, &oldt);          // Získanie aktuálnych nastavení terminálu
    newt = oldt;
    newt.c_lflag &= ~ECHO;                   // Vypnutie echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Aplikácia nových nastavení

    fgets(password, len, stdin);
    password[strcspn(password, "\n")] = '\0'; // Odstránenie nového riadku

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Obnovenie pôvodných nastavení
#endif
    printf("\n");
}

// Pripojenie prípony k názvu súboru
char* append_extension(const char *filename, const char *extension) {
    size_t len = strlen(filename) + strlen(extension) + 1;
    char *new_name = malloc(len);
    snprintf(new_name, len, "%s%s", filename, extension);
    return new_name;
}

// Generovanie názvu dešifrovaného súboru s _dec
char* generate_decrypted_filename(const char *filename) {
    const char *enc_ext = ".enc";
    size_t filename_len = strlen(filename);
    size_t enc_ext_len = strlen(enc_ext);

    // Odstránenie .enc
    size_t base_len = filename_len - enc_ext_len;
    char *base_name = malloc(base_len + 1);
    strncpy(base_name, filename, base_len);
    base_name[base_len] = '\0';

    // Nájsť posledný bod v pôvodnom názve súboru
    char *dot = strrchr(base_name, '.');
    if (dot) {
        size_t name_before_dot_len = dot - base_name;
        size_t new_name_len = name_before_dot_len + strlen("_dec") + strlen(dot) + 1;
        char *new_name = malloc(new_name_len);

        strncpy(new_name, base_name, name_before_dot_len);
        new_name[name_before_dot_len] = '\0';
        strcat(new_name, "_dec");
        strcat(new_name, dot);
        free(base_name);
        return new_name;
    } else {
        // Ak súbor nemá pôvodnú príponu, pridať _dec
        size_t new_name_len = base_len + strlen("_dec") + 1;
        char *new_name = malloc(new_name_len);
        snprintf(new_name, new_name_len, "%s_dec", base_name);
        free(base_name);
        return new_name;
    }
}

// Funkcia na spracovanie šifrovania alebo dešifrovania súboru
void process_file(const char *operation, const char *input_filename, const char *password) {
    unsigned char salt[SALT_LENGTH]; // Buffer pre salt
    unsigned char key[AES_KEY_LENGTH]; // Buffer pre odvodený kľúč
    unsigned char *key1 = key; // Prvá polovica kľúča pre AES-XTS
    unsigned char *key2 = key + 16; // Druhá polovica kľúča pre AES-XTS
    unsigned char in_buf[BUFFER_SIZE]; // Vstupný buffer pre čítanie dát zo súboru
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH]; // Výstupný buffer pre zápis dát do súboru
    int in_len, out_len; // Dĺžky vstupných a výstupných dát
    char *output_filename = NULL;

    // Určenie názvu výstupného súboru na základe operácie
    if (strcmp(operation, "encrypt") == 0) {
        output_filename = append_extension(input_filename, ".enc");
    } else { // decrypt
        output_filename = generate_decrypted_filename(input_filename);
    }

    // Otvorenie vstupného a výstupného súboru
    FILE *infile = fopen(input_filename, "rb");
    if (!infile) {
        free(output_filename);
        printf("Chyba pri otváraní vstupného súboru: %s\n", input_filename);
        return;
    }
    FILE *outfile = fopen(output_filename, "wb");
    if (!outfile) {
        fclose(infile);
        free(output_filename);
        printf("Chyba pri otváraní výstupného súboru: %s\n", output_filename);
        return;
    }

    if (strcmp(operation, "encrypt") == 0) {
        // Generovanie a zápis salt pre šifrovanie
        if (!RAND_bytes(salt, SALT_LENGTH)) {
            fclose(infile);
            fclose(outfile);
            free(output_filename);
            printf("Chyba pri generovaní salt.\n");
            return;
        }
        if (fwrite(salt, 1, SALT_LENGTH, outfile) != SALT_LENGTH) {
            fclose(infile);
            fclose(outfile);
            free(output_filename);
            printf("Chyba pri zápise salt do súboru.\n");
            return;
        }
    } else { // decrypt
        // Čítanie salt zo vstupného súboru pre dešifrovanie
        if (fread(salt, 1, SALT_LENGTH, infile) != SALT_LENGTH) {
            fclose(infile);
            fclose(outfile);
            free(output_filename);
            printf("Chyba pri čítaní salt zo súboru.\n");
            return;
        }
    }

    // Odvodenie kľúča z hesla a salt
    if (derive_key_from_password(password, salt, key) != 0) {
        fclose(infile);
        fclose(outfile);
        free(output_filename);
        printf("Chyba pri odvodení kľúča z hesla.\n");
        return;
    }

    // Inicializácia šifrovania
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (strcmp(operation, "encrypt") == 0) {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors(); // Chyba pri inicializácii ciphertext
        }
    } else { // decrypt
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors(); // Chyba pri inicializácii ciphertext
        }
    }

    // Spracovanie súboru po častiach
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, infile)) > 0) {
        if (aes_xts_crypt(ctx, in_buf, in_len, out_buf, &out_len, salt) != 0) {
            printf("Chyba pri spracovaní dát.\n");
            break; // Chyba pri spracovaní dát, ukončenie spracovania súboru
        }
        if (fwrite(out_buf, 1, out_len, outfile) != (size_t)out_len) {
            printf("Chyba pri zápise dát do súboru.\n");
            break; // Chyba pri zápise dát do výstupného súboru, ukončenie spracovania súboru
        }
    }

    // Zápis dát šifrovania/dešifrovania
    if (strcmp(operation, "encrypt") == 0) {
        if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) == 1) {
            fwrite(out_buf, 1, out_len, outfile); // Zápis zašifrovaných dát do súboru
        }
    } else {
        if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) == 1) {
            fwrite(out_buf, 1, out_len, outfile); // Zápis rozšifrovaných dát do súboru
        }
    }

    // Uvoľnenie pamäte a zatvorenie súborov
    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);
    free(output_filename);

    printf("Operácia '%s' bola úspešne dokončená pre súbor: %s\n", operation, input_filename);
}

int main(int argc, char *argv[]) {

    int file_start = 2; // Index prvého súboru v argumentoch
    char password[256]; // Buffer pre uloženie hesla od používateľa

    // Načítanie argumentov od používateľa
    if (argc < 3 || 
        (strcmp(argv[1], "encrypt") != 0 && 
         strcmp(argv[1], "decrypt") != 0 && 
         strcmp(argv[1], "test") != 0)) {
        print_help();
        return 1;
    }

    const char *operation = argv[1];

    if (strcmp(operation, "test") == 0) {
        if (argc != 3) {
            print_help();
            return 1;
        }

        const char *test_file = argv[2];
        TestVector *vectors = NULL;
        int vector_count = 0;

        if (load_test_vectors(test_file, &vectors, &vector_count) != 0) {
            printf("Chyba pri načítaní testovacích vektorov zo súboru: %s\n", test_file);
            return 1; // Chyba pri načítaní testovacích vektorov
        }

        printf("Načítané testovacie vektory: %d\n\n", vector_count);
        test_vectors(vectors, vector_count);

        // Uvoľnenie alokovanej pamäte
        for (int i = 0; i < vector_count; i++) {
            free(vectors[i].plaintext);
            free(vectors[i].ciphertext);
        }
        free(vectors);
        return 0;
    }

    // Načítanie hesla od používateľa
    get_password(password, sizeof(password));

    // Šifrovanie každého súboru
    for (int i = file_start; i < argc; i++) {
        const char *input_filename = argv[i];
        process_file(operation, input_filename, password);
    }

    // Uvoľnenie OpenSSL pamäte
    EVP_cleanup();
    ERR_free_strings();

    return 0;
} 