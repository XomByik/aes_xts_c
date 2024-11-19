#include "aes_xts.h"

// Funkcia na výpis chýb a ukončenie programu
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
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
    if (OSSL_set_max_threads(NULL, threads) != 1) {
        return -1; // Chyba pri nastavovaní vlákien
    }

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
    if (kdf == NULL) {
        return -1; // Chyba pri získavaní KDF
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        EVP_KDF_free(kdf);
        return -1; // Chyba pri vytváraní KDF kontextu
    }

    // Derivácia kľúča
    if (EVP_KDF_derive(kctx, key, out_len, params) != 1) {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return -1; // Chyba pri derivácii kľúča
    }

    // Uvoľnenie zdrojov
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_set_max_threads(NULL, 0); // Resetovanie vlákien

    return 0; // Úspešné odvodenie kľúča
}

// Zabezpečené získanie hesla od používateľa
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
    if (!new_name) {
        exit(1); // Kritická chyba pri alokácii pamäte
    }
    snprintf(new_name, len, "%s%s", filename, extension);
    return new_name;
}

// Generovanie názvu dešifrovaného súboru s príponou _dec pred pôvodnou príponou
char* generate_decrypted_filename(const char *filename) {
    const char *enc_ext = ".enc";
    size_t filename_len = strlen(filename);
    size_t enc_ext_len = strlen(enc_ext);

    // Kontrola, či názov súboru končí na .enc
    if (filename_len < enc_ext_len || strcmp(filename + filename_len - enc_ext_len, enc_ext) != 0) {
        exit(1); // Nesprávna prípona súboru
    }

    // Odstránenie .enc
    size_t base_len = filename_len - enc_ext_len;
    char *base_name = malloc(base_len + 1);
    if (!base_name) {
        exit(1); // Kritická chyba pri alokácii pamäte
    }
    strncpy(base_name, filename, base_len);
    base_name[base_len] = '\0';

    // Nájsť posledný bod v pôvodnom názve súboru
    char *dot = strrchr(base_name, '.');
    if (dot) {
        size_t name_before_dot_len = dot - base_name;
        size_t new_name_len = name_before_dot_len + strlen("_dec") + strlen(dot) + 1;
        char *new_name = malloc(new_name_len);
        if (!new_name) {
            free(base_name);
            exit(1); // Kritická chyba pri alokácii pamäte
        }
        strncpy(new_name, base_name, name_before_dot_len);
        new_name[name_before_dot_len] = '\0';
        strcat(new_name, "_dec");
        strcat(new_name, dot);
        free(base_name);
        return new_name;
    } else {
        // Ak súbor nemá pôvodnú príponu, jednoducho pridať _dec
        size_t new_name_len = base_len + strlen("_dec") + 1;
        char *new_name = malloc(new_name_len);
        if (!new_name) {
            free(base_name);
            exit(1); // Kritická chyba pri alokácii pamäte
        }
        snprintf(new_name, new_name_len, "%s_dec", base_name);
        free(base_name);
        return new_name;
    }
}

// Šifrovanie alebo dešifrovanie pomocou AES-XTS
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak) {
    int len;
    *out_len = 0;

    // Nastavenie tweak hodnoty (iniciálne IV)
    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tweak, -1) != 1) {
        handle_errors(); // Kritická chyba pri nastavovaní tweak
    }

    // Spracovanie dát
    if (EVP_CipherUpdate(ctx, out, &len, in, in_len) != 1) {
        return -1; // Chyba pri spracovaní dát
    }
    *out_len += len;

    if (EVP_CipherFinal_ex(ctx, out + *out_len, &len) != 1) {
        return -1; // Chyba pri finalizácii
    }
    *out_len += len;

    return 0; // Úspešné spracovanie
}

// Formátovanie výstupu do hexadecimálneho formátu
void print_hex_output(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Načítanie testovacích vektorov zo súboru
int load_test_vectors(const char *filename, TestVector **vectors, int *count) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return -1; // Chyba pri otváraní súboru
    }

    char line[MAX_LINE_LENGTH];
    TestVector *temp_vectors = NULL;
    int temp_count = 0;
    TestVector current_vector;
    memset(&current_vector, 0, sizeof(TestVector));

    // Čítanie každého riadku a ukladanie údajov do aktuálneho testovacieho vektora
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0; // Odstránenie nových riadkov
        if (strlen(line) == 0) { 
            // Prázdny riadok označuje koniec aktuálneho testovacieho vektora
            if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
                temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
                if (!temp_vectors) {
                    fclose(file);
                    return -1; // Chyba pri alokácii pamäte
                }
                temp_vectors[temp_count++] = current_vector;
                memset(&current_vector, 0, sizeof(TestVector));
                current_vector.plaintext = NULL;
                current_vector.ciphertext = NULL;
            }
            continue;
        }

        // Rozdelenie riadku na kľúč a hodnotu
        char *key = strtok(line, " ");
        char *value = strtok(NULL, " ");
        if (!key || !value) {
            fclose(file);
            return -1; // Neplatný formát riadku
        }

        // Priradenie hodnôt na základe kľúča
        if (strcmp(key, "Key1") == 0) {
            if (hex_to_bytes(value, current_vector.key1, 16) != 16) {
                fclose(file);
                return -1; // Chyba pri konverzii Key1
            }
        } else if (strcmp(key, "Key2") == 0) {
            if (hex_to_bytes(value, current_vector.key2, 16) != 16) {
                fclose(file);
                return -1; // Chyba pri konverzii Key2
            }
        } else if (strcmp(key, "DUCN") == 0) {
            if (hex_to_bytes(value, current_vector.ducn, 16) != 16) {
                fclose(file);
                return -1; // Chyba pri konverzii DUCN
            }
        } else if (strcmp(key, "PTX") == 0) {
            int len = strlen(value) / 2;
            unsigned char *new_plaintext = realloc(current_vector.plaintext, current_vector.plaintext_len + len);
            if (!new_plaintext) {
                fclose(file);
                return -1; // Chyba pri alokácii pamäte pre PTX
            }
            current_vector.plaintext = new_plaintext;
            if (hex_to_bytes(value, current_vector.plaintext + current_vector.plaintext_len, len) != len) {
                fclose(file);
                return -1; // Chyba pri konverzii PTX
            }
            current_vector.plaintext_len += len;
        } else if (strcmp(key, "CTX") == 0) {
            int len = strlen(value) / 2;
            unsigned char *new_ciphertext = realloc(current_vector.ciphertext, current_vector.ciphertext_len + len);
            if (!new_ciphertext) {
                fclose(file);
                return -1; // Chyba pri alokácii pamäte pre CTX
            }
            current_vector.ciphertext = new_ciphertext;
            if (hex_to_bytes(value, current_vector.ciphertext + current_vector.ciphertext_len, len) != len) {
                fclose(file);
                return -1; // Chyba pri konverzii CTX
            }
            current_vector.ciphertext_len += len;
        } else {
            fclose(file);
            return -1; // Neznámy parameter
        }
    }

    // Uloženie posledného testovacieho vektora, ak existuje
    if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
        temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
        if (!temp_vectors) {
            fclose(file);
            return -1; // Chyba pri alokácii pamäte pre posledný testovací vektor
        }
        temp_vectors[temp_count++] = current_vector;
    }

    fclose(file);
    *vectors = temp_vectors;
    *count = temp_count;
    return 0; // Úspešné načítanie testovacích vektorov
}

// Testovanie načítaných testovacích vektorov
void test_vectors(TestVector *vectors, int vector_count) {
    for (int i = 0; i < vector_count; i++) {
        printf("Testovací vektor %d:\n", i + 1);

        unsigned char *key1 = vectors[i].key1;
        unsigned char *key2 = vectors[i].key2;
        unsigned char *tweak = vectors[i].ducn;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handle_errors(); // Kritická chyba pri vytváraní cipher kontextu
        }

        // Inicializácia šifrovacieho kontextu pre AES-128-XTS
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
            handle_errors(); // Kritická chyba pri inicializácii cipher
        }

        unsigned char enc_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int enc_out_len = 0;

        // Šifrovanie plaintextu
        if (aes_xts_crypt(ctx, vectors[i].plaintext, vectors[i].plaintext_len, enc_out, &enc_out_len, tweak) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            continue; // Chyba pri šifrovaní, pokračovanie na ďalší vektor
        }

        // Výpis všetkých relevantných dát
        print_hex_output("Key1", key1, 16);
        print_hex_output("Key2", key2, 16);
        print_hex_output("DUCN (tweak)", tweak, 16);
        print_hex_output("PTX (Plaintext)", vectors[i].plaintext, vectors[i].plaintext_len);
        print_hex_output("CTX (očakávaný Ciphertext)", vectors[i].ciphertext, vectors[i].ciphertext_len);
        print_hex_output("Vygenerovaný CTX (Ciphertext)", enc_out, enc_out_len);

        // Porovnanie vygenerovaného ciphertextu s očakávaným ciphertextom
        if (enc_out_len != vectors[i].ciphertext_len || memcmp(enc_out, vectors[i].ciphertext, enc_out_len) != 0) {
            printf("Nesúlad v šifrovaní pri testovacom vektore %d\n", i + 1);
        } else {
            printf("Šifrovanie úspešné pre testovací vektor %d\n", i + 1);
        }

        EVP_CIPHER_CTX_free(ctx);
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3 || 
        (strcmp(argv[1], "encrypt") != 0 && 
         strcmp(argv[1], "decrypt") != 0 && 
         strcmp(argv[1], "test") != 0)) {
        return 1; // Nesprávne použitie programu
    }

    const char *operation = argv[1];

    // Inicializácia OpenSSL
    OPENSSL_init();

    if (strcmp(operation, "test") == 0) {
        if (argc != 3) {
            return 1; // Nesprávne použitie pre testovanie
        }

        const char *test_file = argv[2];
        TestVector *vectors = NULL;
        int vector_count = 0;

        if (load_test_vectors(test_file, &vectors, &vector_count) != 0) {
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

    // Pre operácie šifrovania a dešifrovania
    int file_start = 2;
    int file_count = argc - 2;

    // Získanie hesla od používateľa
    char password[256];
    get_password(password, sizeof(password));

    for (int i = file_start; i < argc; i++) {
        const char *input_filename = argv[i];
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
            continue; // Chyba pri otváraní vstupného súboru, pokračovanie na ďalší
        }
        FILE *outfile = fopen(output_filename, "wb");
        if (!outfile) {
            fclose(infile);
            free(output_filename);
            continue; // Chyba pri otváraní výstupného súboru, pokračovanie na ďalší
        }

        unsigned char salt[SALT_LENGTH];
        unsigned char key[AES_KEY_LENGTH];

        if (strcmp(operation, "encrypt") == 0) {
            // Generovanie a zápis salt pre šifrovanie
            if (!RAND_bytes(salt, SALT_LENGTH)) {
                fclose(infile);
                fclose(outfile);
                free(output_filename);
                continue; // Chyba pri generovaní salt, pokračovanie na ďalší
            }
            if (fwrite(salt, 1, SALT_LENGTH, outfile) != SALT_LENGTH) {
                fclose(infile);
                fclose(outfile);
                free(output_filename);
                continue; // Chyba pri zápise salt, pokračovanie na ďalší
            }
        } else { // decrypt
            // Čítanie salt zo vstupného súboru pre dešifrovanie
            if (fread(salt, 1, SALT_LENGTH, infile) != SALT_LENGTH) {
                fclose(infile);
                fclose(outfile);
                free(output_filename);
                continue; // Chyba pri čítaní salt, pokračovanie na ďalší
            }
        }

        // Odvodenie kľúča z hesla a salt
        if (derive_key_from_password(password, salt, key) != 0) {
            fclose(infile);
            fclose(outfile);
            free(output_filename);
            continue; // Chyba pri odvodení kľúča, pokračovanie na ďalší
        }

        unsigned char *key1 = key;
        unsigned char *key2 = key + 16;

        // Inicializácia šifrovacieho kontextu
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handle_errors(); // Kritická chyba pri vytváraní cipher kontextu
        }

        if (strcmp(operation, "encrypt") == 0) {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
                handle_errors(); // Kritická chyba pri inicializácii cipher
            }
        } else { // decrypt
            if (EVP_DecryptInit_ex(ctx, EVP_aes_128_xts(), NULL, key1, key2) != 1) {
                handle_errors(); // Kritická chyba pri inicializácii cipher
            }
        }

        unsigned char in_buf[BUFFER_SIZE];
        unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int in_len, out_len;

        // Spracovanie súboru po častiach
        while ((in_len = fread(in_buf, 1, BUFFER_SIZE, infile)) > 0) {
            if (aes_xts_crypt(ctx, in_buf, in_len, out_buf, &out_len, salt) != 0) {
                break; // Chyba pri spracovaní dát, ukončenie spracovania súboru
            }
            if (fwrite(out_buf, 1, out_len, outfile) != (size_t)out_len) {
                break; // Chyba pri zápise dát do výstupného súboru, ukončenie spracovania súboru
            }
        }

        // Finalizácia šifrovania/dešifrovania
        if (strcmp(operation, "encrypt") == 0) {
            if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) == 1) {
                fwrite(out_buf, 1, out_len, outfile); // Zápis finalizovaných dát
            }
        } else { // decrypt
            if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) == 1) {
                fwrite(out_buf, 1, out_len, outfile); // Zápis finalizovaných dát
            }
        }

        // Uvoľnenie zdrojov
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        free(output_filename);

        printf("Operácia '%s' bola úspešne dokončená pre súbor: %s\n", operation, argv[i]);
    }

    // Čistenie OpenSSL zdrojov
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
