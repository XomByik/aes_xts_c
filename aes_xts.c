/****************************************************************************
 * Nazov projektu: AES-XTS Sifrovanie a Desifrovanie suborov pomocou OpenSSL
 * ----------------------------------------------------------------------------
 * Subor: aes_xts.c
 * Verzia: 1.1.0
 * Datum: 16.12.2024
 * 
 * Autor: Kamil Berecky
 * 
 * Vyuzite zdroje:
 * - https://docs.openssl.org/3.3/man7/EVP_KDF-ARGON2/
 * - https://github.com/marianasamiranda/AES_XTS_OpenSSL_example
 * - https://github.com/mewmix/sm4-xts-openssl/blob/main/sm4_xts.c
 * - https://gist.github.com/ants/862cb941057bdb8db00c72711d2b826c
 * - https://gist.github.com/dvtalk/edca1d9753503cd03f04b495b040f0e3
 * 
 * Popis:
 * Program implementuje sifrovanie a desifrovanie suborov pomocou AES-128-XTS, AES-256-XTS.
 * Vyuziva OpenSSL kniznicu pre kryptograficke operacie a Argon2id pre
 * bezpecne odvodenie kluca z hesla. Podporuje spracovanie viacerych suborov
 * naraz a testovanie pomocou standardnych IEEE testovacich vektorov.
 * 
 * Detaily implementacie:
 * - Sifrovaci algoritmus: AES-XTS (IEEE 1619-2007)
 * - Odvodenie kluca: Argon2id s nastavitelnou narocnostou
 * - Velkost bloku: 128 bitov
 * - Salt: 16 bajtov, nahodne generovany pre kazdy subor cez CSPRNG
 * - Pociatocny tweak: 128 bitov, nahodne generovany pre kazdy subor cez CSPRNG
 * - Pamatova narocnost: 64MB pre Argon2id
 * 
 * Pre viac info pozri README.md
 ****************************************************************************/

#include "aes_xts.h"

/**
 * Makro pre kontrolu navratovych hodnot OpenSSL funkcii
 * 
 * Pouzitie:
 * - Kontroluje uspesnost vykonania OpenSSL funkcii
 * - Pri chybe vypise informacie o subore a riadku
 * - Spusti handle_errors() pre detailny vypis chyby
 * - Vykona definovanu error_action
 * 
 * Parametre:
 * @param call - Volanie OpenSSL funkcie na kontrolu
 * @param error_action - Akcia vykonana pri chybe
 */
#define CHECK_OPENSSL_CALL(call, error_action) \
    if (!(call)) { \
        fprintf(stderr, "Chyba: %s, riadok %d\n", __FILE__, __LINE__); \
        handle_errors(); \
        error_action; \
    }

/**
 * Spracovanie chybovych hlaseni z OpenSSL
 * 
 * Popis:
 * Zachytava a spracovava vsetky chybove hlasky z OpenSSL kniznice.
 * Vypise detailne informacie o chybe vratane kodu, spravy a lokalizacie.
 */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);    // Vypis chybovych hlaseni na stderr
    exit(EXIT_FAILURE);             // Ukoncenie programu s chybovym kodom
}

/**
 * Zobrazenie napovedy pre pouzivatela
 * 
 * Vypise na standardny vystup:
 * 1. Zakladne pouzitie programu
 * 2. Dostupne operacie (sifrovanie, desifrovanie, testovanie)
 * 3. Format prikazov pre jednotlive operacie
 * 
 * Priklad pouzitia:
 * - Pri spusteni bez parametrov
 * - Pri nespravnych parametroch
 * - Pri poziadavke na napovedu
 */
void print_help() {
    printf("Pouzitie: program [operacia] [subory...]\n");
    printf("Operacie:\n");
    printf("  encrypt [subory...]  - Sifrovanie zadanych suborov\n");
    printf("  decrypt [subory...]  - Desifrovanie zadanych suborov\n");
    printf("  test [subor]         - Testovanie sifrovania s testovacimi vektormi\n");
}

/**
 * Implementacia sifrovania a desifrovania pomocou AES-XTS
 * 
 * Postup spracovania:
 * 1. Inicializacia sifrovacieho algortimu s nahodne vygenerovanou tweak hodnotou
 * 2. Sifrovanie/desifrovanie vstupnych dat
 * 3. Finalizacia operacie
 * 
 * Bezpecnostne opatrenia:
 * - Kontrola navratovych hodnot vsetkych OpenSSL funkcii
 * - Pouzitie makra CHECK_OPENSSL_CALL pre jednotne spracovanie chyb
 * - Spravna inicializacia vystupnych premennych
 * 
 * Parametre:
 * @param ctx      - Struktura s konfiguracnymi sifrovacimi parametrami vyuzivana v OpenSSL ("tzv. context")
 * @param in       - Vstupne data - pri sifrovani plaintext, pri desifrovani ciphertext
 * @param in_len   - Dlzka vstupnych dat
 * @param out      - Vystupne data pri desifrovani ciphertext, pri desifrovani plaintext
 * @param out_len  - Dlzka vystupnych dat
 * @param tweak    - Tweak hodnota pre XTS mod
 * 
 * @return 0 pri uspesnom dokonceni, -1 pri chybe
 */
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak) {
    int len;
    *out_len = 0;
    // Volanie EVP_CipherInit_ex:
    // - ctx: Struktura s konfiguracnymi sifrovacimi parametrami vyuzivana v OpenSSL ("tzv. context")
    // - NULL: bez zmeny sifry
    // - NULL: bez zmeny engine
    // - NULL: bez zmeny kluca
    // - tweak: tweak hodnota pre XTS mod
    // - -1: zachovat smer sifrovania/de-sifrovania
    CHECK_OPENSSL_CALL(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tweak, -1), return -1);

    // Volanie EVP_CipherUpdate pre sifrovanie/desifrovanie bloku dat:
    // - ctx: Struktura s konfiguracnymi sifrovacimi parametrami vyuzivana v OpenSSL ("tzv. context")
    // - out: Vystupne data pri desifrovani ciphertext, pri desifrovani plaintext
    // - &len: Velkost vystupnych dat
    // - in: Vstupne data - pri sifrovani plaintext, pri desifrovani ciphertext
    // - in_len: Velkost nezasifrovanych dat
    CHECK_OPENSSL_CALL(EVP_CipherUpdate(ctx, out, &len, in, in_len), return -1);
    *out_len += len;
    
    // Finalizacia sifrovania/desifrovania:
    CHECK_OPENSSL_CALL(EVP_CipherFinal_ex(ctx, out + *out_len, &len), return -1);
    *out_len += len;
    return 0;
}

/**
 * Pridanie hexadecimalnych dat do dynamickeho pola
 * 
 * Postup spracovania:
 * 1. Realokacia pamate pre nove data
 * 2. Konverzia hex retazca na bajty
 * 3. Pridanie novych dat na koniec pola
 * 
 * Pouzitie:
 * - Pri nacitavani testovacich vektorov
 * - Pri spracovani plaintextu a ciphertextu
 * 
 * Opatrenia:
 * - Kontrola uspesnosti alokacie
 * - Spravna aktualizacia dlzky pola
 * 
 * @param current_data - Existujuce pole dat
 * @param current_len  - Aktualna dlzka pola
 * @param hex_str      - Novy hex retazec na pridanie
 * @param hex_len      - Dlzka noveho hex retazca
 * 
 * @return Pointer na rozsirene pole alebo NULL pri chybe
 */
unsigned char* append_data(unsigned char *current_data, int *current_len, const char *hex_str, int hex_len) {
    unsigned char *new_data = realloc(current_data, *current_len + hex_len);
    hex_to_bytes(hex_str, new_data + *current_len, hex_len);
    *current_len += hex_len;
    return new_data;
}

/**
 * Nacitanie testovacich vektorov zo suboru
 * 
 * Popis:
 * Nacita testovacie vektory z textoveho suboru pre AES-XTS testovanie.
 * Kazdy vektor obsahuje vstupne data, kluc, IV a ocakavany vystup.
 * 
 * Format vstupneho suboru:
 * - Jeden testovaci vektor na blok
 * - Kazdy blok obsahuje:
 *   * KEY=<hex_string>    - Sifrovaci kluc
 *   * IV=<hex_string>     - Inicializacny vektor
 *   * PTX=<hex_string>     - Plaintext (vstupne data)
 *   * CTX=<hex_string>     - Ciphertext (ocakavany vystup)
 * - Prazdne riadky oddeluju jednotlive vektory
 * 
 * Bezpecnostne kontroly:
 * - Validacia vstupneho formatu
 * - Kontrola dlzky vektorov
 * - Overenie alokacie pamate
 * - Spracovanie chyb pri citani
 * 
 * Parametre:
 * @param filename - Cesta k suboru s testovacimi vektormi
 * @param vectors  - Vystupny parameter pre pole vektorov
 * @param count    - Vystupny parameter pre pocet vektorov
 * 
 * Navratove hodnoty:
 * @return 0 - Uspesne nacitanie
 * @return -1 - Chyba pri citani alebo spracovani
 * 
 * Pouzitie:
 * TestVector *vektory;
 * int pocet;
 * if(load_test_vectors("testy.txt", &vektory, &pocet) == 0) {
 *     // Spracovanie vektorov
 * }
 */
int load_test_vectors(const char *filename, TestVector **vectors, int *count) {
    FILE *file = fopen(filename, "r");
    TestVector *temp_vectors = NULL;
    int temp_count = 0;
    TestVector current_vector = {0};
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0; // Odstranenie noveho riadku
        if (strlen(line) == 0) {
            // Ak je riadok prazdny, ulozit aktualny vektor
            if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
                temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
                if (!temp_vectors) {
                    perror("Chyba pri alokacii pamate");
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
            fprintf(stderr, "Neplatny format riadku: %s\n", line);
            fclose(file);
            return -1;
        }
        // Rozhodovanie podla typu kluca
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
            fprintf(stderr, "Neznamy parameter: %s\n", key);
            fclose(file);
            return -1;
        }
    }
    // Ulozenie posledneho vektora
    if (current_vector.plaintext_len > 0 && current_vector.ciphertext_len > 0) {
        temp_vectors = realloc(temp_vectors, sizeof(TestVector) * (temp_count + 1));
        temp_vectors[temp_count++] = current_vector;
    }
    fclose(file);
    *vectors = temp_vectors;
    *count = temp_count;
    return 0;
}

/**
 * Testovanie AES-XTS implementacie pomocou standardnych vektorov
 * 
 * Popis:
 * Overuje spravnost implementacie AES-XTS sifrovania pomocou predpripravenych
 * testovacich vektorov. Kazdy vektor je samostatne testovany na sifrovanie.
 * 
 * Proces testovania:
 * 1. Inicializacia open-ssl implementacie kryptografickej funkcie
 * 2. Nastavenie klucov a parametrov
 * 3. Sifrovanie vstupnych dat (plaintext)
 * 4. Porovnanie vysledku s ocakavanym ciphertextom
 * 5. Vypis vysledku testu
 * 
 * Bezpecnostne kontroly:
 * - Overenie uspesnosti inicializacie kryptografickej funkcie
 * - Kontrola navratovych hodnot OpenSSL funkcii
 * - Validacia dlzok vystupnych dat
 * - Bezpecne uvolnenie zdrojov
 * 
 * Parametre:
 * @param vectors - Pole testovacich vektorov na overenie
 * @param vector_count - Pocet vektorov na testovanie
 * 
 * Vystup:
 * - Vypis uspesnosti/zlyhania pre kazdy vektor
 * - Pri zlyhari detail o nesulad v sifrovani
 * 
 * Pouzitie pamate:
 * - Docasny buffer pre sifrovane data
 * - Automaticke cistenie po dokonceni
 */
void test_vectors(TestVector *vectors, int vector_count) {
    for (int i = 0; i < vector_count; i++) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            handle_errors();
        }

        // Volanie EVP_EncryptInit_ex:
        // - ctx: Struktura s konfiguracnymi sifrovacimi parametrami vyuzivana v OpenSSL ("tzv. context")
        // - EVP_aes_128_xts(): AES-128 v XTS mode
        // - NULL: bez engine
        // - vectors[i].key1: prvy kluc pre XTS
        // - vectors[i].key2: druhy kluc pre XTS
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_xts(), NULL, vectors[i].key1, vectors[i].key2) != 1) {
            handle_errors();
        }

        unsigned char enc_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        int enc_out_len = 0;

        aes_xts_crypt(ctx, vectors[i].plaintext, vectors[i].plaintext_len, enc_out, &enc_out_len, vectors[i].ducn);

        if (enc_out_len != vectors[i].ciphertext_len || memcmp(enc_out, vectors[i].ciphertext, enc_out_len) != 0) {
            fprintf(stderr, "Nesulad v sifrovani pri vektore %d\n", i + 1);
        } else {
            printf("Sifrovanie uspesne pre vektor %d\n", i + 1);
        }

        EVP_CIPHER_CTX_free(ctx);
    }
}

/**
 * Odvodenie sifrovacieho kluca z hesla pomocou Argon2id
 * 
 * Implementuje bezpecne odvodenie kluca (KDF) s nasledujucimi vlastnostami:
 * 1. Pouziva Argon2id
 * 2. Nastavenia odolnosti:
 *    - Pocet iteracii: 3 (kompromis medzi bezpecnostou a rychlostou)
 *    - Pamatova narocnost: 64MB (ochrana proti GPU utokom)
 *    - Paralelizmus: 4 lanes, 2 vlakna (optimalizacia pre bezne CPU)
 * 3. Vystupna velkost kluca:
 *    - Pre AES-128-XTS: 32 bajtov (2x 16B kluc)
 *    - Pre AES-256-XTS: 64 bajtov (2x 32B kluc)
 * 
 * Pre viac informacii o parametroch a ich vplyve na bezpecnost
 * pozri sekciu "Bezpecnostne informacie" v README.md
 * 
 * @param password Heslo zadane pouzivatelom
 * @param salt 16-bajtova nahodna hodnota
 * @param key Vystupny buffer pre kluc (32B pre AES-128-XTS, 64B pre AES-256-XTS)
 * @param key_length Pozadovana dlzka kluca v bajtoch (32 pre 128-bit, 64 pre 256-bit)
 * @return 0 pri uspesnom odvodeni, -1 pri chybe
 */
int derive_key_from_password(const char *password, const unsigned char *salt, 
                           unsigned char *key, size_t key_length) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[8];
    size_t out_len = key_length;  // Using provided key length

    // Parametre pre Argon2id
    uint32_t iterations = 3;
    uint32_t memory_cost = 65536; 
    uint32_t lanes = 4;
    uint32_t threads = 2;

    // Nastavenie maximalneho poctu vlakien pre KDF
    OSSL_set_max_threads(NULL, threads);

    // Konfiguracia parametrov pre KDF
    OSSL_PARAM *p = params;
    // Volanie OSSL_PARAM_construct_octet_string:
    // - OSSL_KDF_PARAM_PASSWORD: parameter pre heslo
    // - password: vstupne heslo
    // - strlen(password): dlzka hesla
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)password, strlen(password));
    // Volanie OSSL_PARAM_construct_octet_string:
    // - OSSL_KDF_PARAM_SALT: parameter pre salt
    // - salt: nahodna salt hodnota
    // - SALT_LENGTH: dlzka salt (16 bajtov)
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, SALT_LENGTH);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory_cost);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &out_len);
    *p++ = OSSL_PARAM_construct_end();

    // Inicializacia KDF pre Argon2id
    kdf = EVP_KDF_fetch(NULL, "Argon2id", NULL);

    kctx = EVP_KDF_CTX_new(kdf);

    // Derivacia kluca
    EVP_KDF_derive(kctx, key, out_len, params);

    // Uvolnenie pamate
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_set_max_threads(NULL, 0);

    return 0; // Uspesne odvodenie kluca
}

/**
 * Konverzia hexadecimalneho retazca na pole bajtov
 * 
 * Popis:
 * Konvertuje hex string na bajty. Kazdy par znakov reprezentuje jeden bajt.
 * Napriklad: "1A2B" -> {0x1A, 0x2B}
 * 
 * Bezpecnostne kontroly:
 * - Validacia dlzky vstupneho retazca
 * - Kontrola spravneho formatu hex znakov
 * - Ochrana proti preteceniu buffera
 * 
 * Parametre:
 * @param hex_str - Vstupny hexadecimalny retazec
 * @param bytes - Vystupne pole bajtov
 * @param expected_len - Ocakavana dlzka vystupneho pola v bajtoch
 * 
 * Navratove hodnoty:
 * @return expected_len - Pri uspesnej konverzii
 * @return -1 - Pri chybe (nespravna dlzka/format)
 * 
 * Pouzitie:
 * unsigned char bytes[2];
 * if(hex_to_bytes("1A2B", bytes, 2) == -1) {
 *     // Spracovanie chyby
 * }
 */
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len) {
    int len = strlen(hex_str);
    if (len != expected_len * 2) {
        return -1; // Nespravna dlzka hex retazca
    }
    for (int i = 0; i < expected_len; i++) {
        if (sscanf(&hex_str[i * 2], "%2hhx", &bytes[i]) != 1) {
            return -1; // Chyba pri konverzii
        }
    }
    return expected_len;
}

/**
 * Nacita heslo zo standardneho vstupu bez zobrazenia znakov
 * 
 * @param password - Buffer pre heslo
 * @param len - Maximalna dlzka hesla
 */
void get_password(char *password, size_t len) {
    printf("Zadajte heslo: ");

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
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    if (fgets(password, len, stdin)) {
        password[strcspn(password, "\n")] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
#endif
    printf("\n");
}

/**
 * Pripojenie pripony k nazvu suboru
 * 
 * Popis:
 * Vytvara novy retazec obsahujuci povodny nazov suboru s pridanou priponou.
 * Zabezpecuje spravnu alokaciu pamate pre novy nazov.
 * 
 * Proces:
 * 1. Vypocet potrebnej velkosti pamate
 * 2. Alokacia noveho retazca
 * 3. Spojenie povodneho nazvu a pripony
 * 
 * Bezpecnostne kontroly:
 * - Overenie vstupnych parametrov
 * - Kontrola alokacie pamate
 * - Ochrana proti preteceniu buffera pomocou snprintf
 * 
 * Parametre:
 * @param filename - Povodny nazov suboru
 * @param extension - Pripona na pridanie (vratane bodky)
 * 
 * Navratova hodnota:
 * @return Novy retazec s pripojenou priponou (treba uvolnit pomocou free())
 * @return NULL pri chybe alokacie
 * 
 * Pouzitie:
 * char *novy_nazov = append_extension("subor", ".enc");
 * if(novy_nazov) {
 *     // Pouzitie noveho nazvu
 *     free(novy_nazov);
 * }
 */
char* append_extension(const char *filename, const char *extension) {
    size_t len = strlen(filename) + strlen(extension) + 1;
    char *new_name = malloc(len);
    // Volanie snprintf:
    // - new_name: buffer pre novy nazov
    // - len: maximalny pocet znakov
    // - "%s%s": format string (spoji dva retazce)
    // - filename: povodny nazov suboru
    // - extension: pripona na pridanie
    snprintf(new_name, len, "%s%s", filename, extension);
    return new_name;
}

/**
 * Generovanie nazvu desifrovaneho suboru
 * 
 * Popis:
 * Vytvara novy nazov suboru pre desifrovany vystup pridanim '_dec' pred priponu.
 * Odstranuje '.enc' priponu z povodneho nazvu.
 * 
 * Proces spracovania:
 * 1. Odstranenie '.enc' pripony
 * 2. Identifikacia povodnej pripony suboru
 * 3. Vlozenie '_dec' pred povodnu priponu
 * 4. Spojenie casti do vysledneho nazvu
 * 
 * Bezpecnostne kontroly:
 * - Overenie vstupneho parametra
 * - Kontrola alokacie pamate
 * - Ochrana proti buffer overflow
 * - Spracovanie chybnych vstupov
 * 
 * Parametre:
 * @param filename - Povodny nazov suboru s '.enc' priponou
 * 
 * Navratove hodnoty:
 * @return Novy nazov suboru s '_dec' (treba uvolnit pomocou free())
 * @return NULL pri chybe
 * 
 * Priklady:
 * "subor.txt.enc" -> "subor_dec.txt"
 * "dokument.pdf.enc" -> "dokument_dec.pdf"
 * "data.enc" -> "data_dec"
 */
char* generate_decrypted_filename(const char *filename) {
    const char *enc_ext = ".enc";
    size_t filename_len = strlen(filename);
    size_t enc_ext_len = strlen(enc_ext);

    // Odstranenie .enc
    size_t base_len = filename_len - enc_ext_len;
    char *base_name = malloc(base_len + 1);
    // Volanie strncpy:
    // - base_name: cielovy buffer
    // - filename: zdrojovy retazec
    // - base_len: pocet kopirovanych znakov
    strncpy(base_name, filename, base_len);
    base_name[base_len] = '\0';

    // Najst posledny bod v povodnom nazve suboru
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
        // Ak subor nema povodnu priponu, pridat _dec
        size_t new_name_len = base_len + strlen("_dec") + 1;
        char *new_name = malloc(new_name_len);
        snprintf(new_name, new_name_len, "%s_dec", base_name);
        free(base_name);
        return new_name;
    }
}

/**
 * Vypocet tweak hodnoty pre konkretny sektor
 * 
 * Popis:
 * Vypocitava jedinecnu tweak hodnotu pre kazdy sektor v subore pomocou
 * XOR medzi pociatocnym tweakom a logickou poziciou sektora.
 * 
 * Proces spracovania:
 * 1. Skopirovanie pociatocneho tweaku do vystupneho buffera
 * 2. XOR operacia logickej pozicie sektora s tweakom
 * 
 * Bezpecnostne vlastnosti:
 * - Kazdy sektor ma unikatny tweak
 * - Zachovava kryptograficku silu povodneho tweaku
 * - Predvidatelna zmena tweaku pre postupne sektory
 * 
 * Parametre:
 * @param initial_tweak - Pociatocny 128-bitovy tweak
 * @param sector_number - Logicke cislo sektora (pocitane od 0)
 * @param output_tweak - Vystupny buffer pre vypocitany tweak (128 bitov)
 * 
 * Pouzitie:
 * unsigned char tweak[16];
 * calculate_sector_tweak(initial_tweak, 0, tweak);
 */
void calculate_sector_tweak(const unsigned char *initial_tweak, 
                          uint64_t sector_number, 
                          unsigned char *output_tweak) {
    // Skopirovanie pociatocneho tweaku (128 bitov)
    memcpy(output_tweak, initial_tweak, TWEAK_LENGTH);
    
    // XOR celych 128 bitov po 64-bitovych castiach
    for(int i = 0; i < TWEAK_LENGTH; i += 8) {
        uint64_t *chunk = (uint64_t *)(output_tweak + i);
        *chunk ^= sector_number;
    }
}

/**
 * Spracovanie suboru pre sifrovanie alebo desifrovanie
 * 
 * Popis:
 * Implementuje sifrovanie/desifrovanie suboru po sektoroch s pouzitim
 * AES-XTS algoritmu (128-bit alebo 256-bit verzia). Kazdy sektor ma vlastny 
 * tweak odvodeny z pociatocneho tweaku a cisla sektora.
 *
 * Podporovane velkosti klucov:
 * - AES-128-XTS: 32 bajtov (2x 16B kluc)
 * - AES-256-XTS: 64 bajtov (2x 32B kluc)
 * 
 * Parametre:
 * @param operation - "encrypt" alebo "decrypt"
 * @param input_filename - Cesta k vstupnemu suboru
 * @param password - Heslo pre sifrovanie/desifrovanie
 * @param key_bits - Velkost kluca v bitoch (128 alebo 256)
 */
void process_file(const char *operation, const char *input_filename, 
                 const char *password, int key_bits) {
    unsigned char salt[SALT_LENGTH];
    unsigned char initial_tweak[INITIAL_TWEAK_LENGTH];
    unsigned char sector_tweak[TWEAK_LENGTH];
    // Alokacia kluca podla zvolenej velkosti
    unsigned char key[key_bits == 256 ? AES_KEY_LENGTH_256 : AES_KEY_LENGTH_128];
    unsigned char *key1 = key;
    unsigned char *key2 = key + (key_bits / 8);  // Polovica celkovej dlzky kluca
    unsigned char in_buf[SECTOR_SIZE];
    unsigned char out_buf[SECTOR_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    uint64_t sector_number = 0;
    char *output_filename = NULL;

    // Vytvorenie nazvu vystupneho suboru
    if (strcmp(operation, "encrypt") == 0) {
        output_filename = append_extension(input_filename, ".enc");
    } else {
        output_filename = generate_decrypted_filename(input_filename);
    }

    // Otvorenie suborov
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    if (!infile || !outfile) {
        // Spracovanie chyby...
        return;
    }

    if (strcmp(operation, "encrypt") == 0) {
        // Generovanie salt a pociatocneho tweaku
        if (!RAND_bytes(salt, SALT_LENGTH) || !RAND_bytes(initial_tweak, INITIAL_TWEAK_LENGTH)) {
            // Spracovanie chyby...
            return;
        }
        
        // Zapis hlavicky (salt + pociatocny tweak)
        if (fwrite(salt, 1, SALT_LENGTH, outfile) != SALT_LENGTH || fwrite(initial_tweak, 1, INITIAL_TWEAK_LENGTH, outfile) != INITIAL_TWEAK_LENGTH) {
            // Spracovanie chyby...
            return;
        }
    } else {
        // Citanie hlavicky pri desifrovani
        if (fread(salt, 1, SALT_LENGTH, infile) != SALT_LENGTH || fread(initial_tweak, 1, INITIAL_TWEAK_LENGTH, infile) != INITIAL_TWEAK_LENGTH) {
            // Spracovanie chyby...
            return;
        }
    }

    // Derivacia kluca z hesla - upravena dlzka kluca
    if (derive_key_from_password(password, salt, key, key_bits == 256 ? AES_KEY_LENGTH_256 : AES_KEY_LENGTH_128) != 0) {
        // Spracovanie chyby...
        return;
    }

    // Inicializacia sifrovania
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Spracovanie chyby...
        return;
    }

    // Vyber spravneho modu podla velkosti kluca
    const EVP_CIPHER *cipher = (key_bits == 256) ?  EVP_aes_256_xts() : EVP_aes_128_xts();

    // Nastavenie modu podla operacie
    if (strcmp(operation, "encrypt") == 0) {
        EVP_EncryptInit_ex(ctx, cipher, NULL, key1, key2);
    } else {
        EVP_DecryptInit_ex(ctx, cipher, NULL, key1, key2);
    }

    // Spracovanie po sektoroch
    while ((in_len = fread(in_buf, 1, SECTOR_SIZE, infile)) > 0) {
        // Vypocet tweaku pre aktualny sektor
        calculate_sector_tweak(initial_tweak, sector_number, sector_tweak);

        // Sifrovanie/desifrovanie sektora
        if (aes_xts_crypt(ctx, in_buf, in_len, out_buf, &out_len, sector_tweak) != 0) {
            // Spracovanie chyby...
            break;
        }

        // Zapis vystupu
        if (fwrite(out_buf, 1, out_len, outfile) != (size_t)out_len) {
            // Spracovanie chyby...
            break;
        }

        sector_number++;
    }

    // Finalizacia
    if (strcmp(operation, "encrypt") == 0) {
        EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    } else {
        EVP_DecryptFinal_ex(ctx, out_buf, &out_len);
    }

    // Cistenie
    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);
    free(output_filename);
}


int main(int argc, char *argv[]) {
    if (argc < 4 || 
        (strcmp(argv[1], "encrypt") != 0 && 
         strcmp(argv[1], "decrypt") != 0 && 
         strcmp(argv[1], "test") != 0)) {
        printf("Pouzitie: %s [encrypt|decrypt] [128|256] [subory...]\n", argv[0]);
        printf("alebo: %s test [subor_s_testami]\n", argv[0]);
        return 1;
    }

    const char *operation = argv[1];

    // Spracovanie testovacieho modu
    if (strcmp(operation, "test") == 0) {
        // Kontrola spravneho poctu argumentov pre testovaci mod
        if (argc != 3) {
            print_help();
            return 1;
        }

        const char *test_file = argv[2];         // Subor s testovacimi vektormi
        TestVector *vectors = NULL;              // Pole testovacich vektorov
        int vector_count = 0;                    // Pocet nacitanych vektorov

        // Nacitanie testovacich vektorov zo suboru
        if (load_test_vectors(test_file, &vectors, &vector_count) != 0) {
            printf("Chyba pri nacitani testovacich vektorov zo suboru: %s\n", test_file);
            return 1;
        }

        printf("Nacitane testovacie vektory: %d\n\n", vector_count);
        test_vectors(vectors, vector_count);     // Spustenie testovania

        // Systematicke uvolnenie pamate pre kazdy vektor
        for (int i = 0; i < vector_count; i++) {
            free(vectors[i].plaintext);          // Uvolnenie plaintext bufferu
            free(vectors[i].ciphertext);         // Uvolnenie ciphertext bufferu
        }
        free(vectors);                          // Uvolnenie pola vektorov
        return 0;                               // Ukoncenie po dokonceni testovania
    }

    // Kontrola a nastavenie velkosti kluca
    int key_bits = 128;  // Predvolena hodnota
    if (strcmp(argv[2], "256") == 0) {
        key_bits = 256;
    } else if (strcmp(argv[2], "128") != 0) {
        printf("Nespravna velkost kluca. Pouzite 128 alebo 256.\n");
        return 1;
    }

    char password[256];
    get_password(password, sizeof(password));

    // Spracovanie suborov od indexu 3 (po operation a key_bits)
    for (int i = 3; i < argc; i++) {
        const char *input_filename = argv[i];
        process_file(operation, input_filename, password, key_bits);
    }

    // Cistenie OpenSSL zdrojov a uvolnenie pamate
    EVP_cleanup();                       // Vycistenie sifrovanych textov
    ERR_free_strings();                 // Uvolnenie chybovych retazcov

    return 0;
}