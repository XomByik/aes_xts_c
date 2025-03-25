/************************************************************************
 * Nazov projektu: AES-XTS sifrovanie a desifrovanie diskov pomocou OpenSSL
 * ----------------------------------------------------------------------------
 * Subor: aes_xts.c 
 * Verzia: 2.1 
 * Datum: 25.3.2025
 *
 * Autor: Kamil Berecky
 *
 * Vyuzite zdroje:
 * - OpenSSL dokumentacia (EVP, HMAC, KDF): 
 *  https://www.openssl.org/docs/man3.0/
 * - OpenSSL ARGON2 KDF: 
 *  https://docs.openssl.org/3.3/man7/EVP_KDF-ARGON2/ 
 * - IEEE 1619-2018: 
 *  https://doi.org/10.1109/IEEESTD.2019.8637988
 * - NIST SP 800-38E: 
 *  https://doi.org/10.6028/NIST.SP.800-38E
 * - Microsoft DeviceIoControl API: 
 *  https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
 * - Linux ioctl() pre blokove zariadenia: 
 *  https://www.kernel.org/doc/html/latest/driver-api/
 * - Argon2id KDF: 
 *  https://github.com/P-H-C/phc-winner-argon2
 * - AES-XTS paralelizacia: 
 *  https://sciresol.s3.us-east-2.amazonaws.com/IJST/Articles/2014/Issue-11/Article13.pdf
 * - OpenMP: 
 * https://www.openmp.org/
 *
 * 
 * Popis: Program implementuje sifrovanie a desifrovanie diskov 
 * diskovych particii pomocou AES-XTS algoritmu s podporou 128 aj
 * 256-bitovych klucov. Vyuziva OpenSSL kniznicu pre kryptograficke
 * operacie a Argon2id na derivaciu kluca z hesla. Podporuje viacero
 * operacnych systemov (Windows, Linux) a rozne typy diskovych
 * zariadeni (fyzicke disky, logicke oddiely). Implementacia respektuje
 * bezpecnostne standardy a vyuziva aj paralelizaciu pomocou kniznice
 * OpenMP pre zrychlenie sifrovania a desifrovania dat.
 *
 * Pre viac info pozri README.md
 **********************************************************************/
#include "aes_xts.h"

/**
 * Inicializacia kryptografickeho prostredia OpenSSL
 *
 * Popis: Inicializuje OpenSSL kniznicu pre pouzitie kryptografickych
 * algoritmov potrebnych v aplikacii. Tato funkcia musi byt volana pred
 * akymkolvek pouzitim OpenSSL funkcii.
 *
 * Proces:
 * 1. Registruje vsetky dostupne kryptograficke algoritmy
 * 2. Nacita chybove retazce pre diagnostiku
 *
 * Pouzitie: Vola sa na zaciatku hlavneho programu
 */
void aes_xts_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

/**
 * Uvolnenie kryptografickeho prostredia OpenSSL
 *
 * Popis: Uvolnuje zdroje alokovane OpenSSL kniznicou. Tato funkcia by
 * mala byt volana pred ukoncenim programu na zabranenie unikov pamate.
 *
 * Proces:
 * 1. Uvolnuje/vycisti pamat vsetkych kryptografickych algoritmov
 * 2. Uvolnuje pamat pouzitu na chybove retazce
 *
 * Pouzitie: Vola sa na konci hlavneho programu
 */
void aes_xts_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

/**
 * Vypis detailov OpenSSL chyby na standardny chybovy vystup
 *
 * Popis: Ziskava a zobrazuje poslednu chybu, ktora nastala v OpenSSL kniznici.
 * Pouziva sa na diagnostiku problemov pri volani OpenSSL funkcii.
 *
 * Proces:
 * 1. Ziska kod poslednej chyby z OpenSSL
 * 2. Konvertuje kod chyby na citatelny retazec
 * 3. Zobrazi chybovu spravu na chybovy vystup
 *
 * Pouzitie: Vola sa po neuspesnom volani OpenSSL funkcii na zistenie
 * presneho dovodu zlyhania
 */
void print_openssl_error(void) {
    uint8_t err_msg[ERROR_BUFFER_SIZE];
    uint32_t err = ERR_get_error();
    
    if(err != 0) {
        ERR_error_string_n(err, (char*)err_msg, sizeof(err_msg));
        fprintf(stderr, "OpenSSL Chyba: %s\n", err_msg);
    }
}

/**
 * Zobrazenie priebehu sifrovania/desifovania 
 *
 * Popis: Zobrazuje aktualny stav spracovania sifrovania/desifrovania
 * disku/particie v percentach a megabajtoch. Optimalizuje frekvenciu
 * aktualizacie zobrazenia na konzolu pomocou obmedzovania na casovy
 * interval a urcity pocet spracovanych sektorov.
 *
 * Proces:
 * 1. Kontrola ci sa ma aktualizovat zobrazenie (interval, pocet
 * sektorov, alebo koniec operacie)
 * 2. Vypocet percentualneho stavu a prevedie bajty na megabajty
 * 3. Formatovany vypis s roznymi formatmi pre Windows/Linux
 * 4. Vynutenie vypisu bufferu na konzolu
 * 5. Ulozenie casu poslednej aktualizacie
 *
 * Parametre:
 * @param current - Aktualne spracovane bajty
 * @param total - Celkovy pocet bajtov na spracovanie
 * @param sector_num - Aktualny spracovavany sektor (pre kontrolu intervalu)
 *
 * Pouzitie: Vola sa v cykle spracovania dat pre zobrazenie postupu
 * sifrovania
 */

void show_progress(uint64_t current, uint64_t total, uint64_t sector_num) {
    static uint64_t last_update_time = 0;
    uint64_t current_time = time(NULL);
    
    if (sector_num % PROGRESS_UPDATE_INTERVAL == 0 || 
        current >= total - SECTOR_SIZE || 
        current_time - last_update_time >= 1) {
        
        float percent = (float)current * 100.0f / (float)total;
        if (percent > 100.0f) percent = 100.0f;
        
        uint64_t current_mb = current / BYTES_PER_MB;
        uint64_t total_mb = total / BYTES_PER_MB;
        #ifdef _WIN32
            printf("Priebeh: %.1f%% (%llu/%llu MB)\r", percent, current_mb, total_mb);
        #else
            printf("Priebeh: %.1f%% (%lu/%lu MB)\r", percent, current_mb, total_mb);
        #endif
        fflush(stdout);
        
        last_update_time = current_time;
    }
}

/**
 * Sifrovanie alebo desifrovanie jedneho sektora disku pomocou AES-XTS
 *
 * Popis: Implementuje AES-XTS algoritmus pre sifrovanie alebo
 * desifrovanie jedneho sektora disku. AES-XTS je optimalizovany pre
 * bloky dat, ktorych poradie je zname, ako su napriklad sektory disku.
 * Poskytuje silnu ochranu proti utoku na podobnost vzorov (pattern
 * analysis).
 *
 * Proces:
 * 1. Vytvorenie inicializacneho vektora z cisla sektora
 * 2. Vyberie spravny rezim sifrovania podla velkosti kluca (128/256 bitov)
 * 3. Inicializacia kryptografickeho kontextu
 * 4. Sifrovanie alebo desifrovanie dat podla zadaneho rezimu
 * 5. Uvolnenie kryptografickeho kontextu
 *
 * Parametre:
 * @param key - Kluc pre sifrovanie/desifrovanie dat
 * @param sector_num - Cislo spracovavaneho sektora (pouzite v IV)
 * @param data - Buffer obsahujuci data na sifrovanie/desifrovanie
 * @param data_len - Dlzka dat v bufferi
 * @param encrypt - Priznak urcujuci operaciu (1 = sifrovanie, 0 = desifrovanie)
 * @param key_bits - Velkost kluca v bitoch (128 alebo 256)
 *
 * Navratova hodnota:
 * @return AES_XTS_SUCCESS v pripade uspesneho dokoncenia,
 *         alebo kod chyby v pripade zlyhania
 * 
 * XTS rezim:
 * - Pouziva dva nezavisle kluce: jeden pre AES a druhy pre "tweak"
 * - Cislo sektora sa pouziva ako "tweak", co zabezpecuje ze kazdy
 *   sektor je sifrovany odlisnym sposobom, aj ked obsahuje rovnake data
 */
int32_t aes_xts_crypt_sector(
    const uint8_t *key,     
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int encrypt,
    int key_bits 
) {
    EVP_CIPHER_CTX *ctx;
    uint8_t iv[IV_SIZE] = {0};
    int len;
    // Vyber spravneho rezimu na zaklade velkosti kluca (128 alebo 256 bitov)
    const EVP_CIPHER *cipher = (key_bits == 128) ? EVP_aes_128_xts() : EVP_aes_256_xts();
    
    // Cislo sektora sa pouziva ako inicializacny vektor
    *(uint64_t*)iv = sector_num;

    // Vytvorenie noveho kryptografickeho OpenSSL kontextu
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }

    int success = 0;
    if (encrypt) {
        // Sifrujeme data - spojenie operacii do jedneho volania s kontrolou uspesnosti
        success = EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) &&
                  EVP_EncryptUpdate(ctx, data, &len, data, data_len) &&
                  EVP_EncryptFinal_ex(ctx, data + len, &len);
    } else {
        // Desifrujeme data - spojenie operacii do jedneho volania s kontrolou uspesnosti
        success = EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) &&
                  EVP_DecryptUpdate(ctx, data, &len, data, data_len) &&
                  EVP_DecryptFinal_ex(ctx, data + len, &len);
    }
    
    // Kontrola ci vsetky operacie prebehli uspesne
    if (!success) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return AES_XTS_ERROR_OPENSSL;
    }

    // Uvolnenie kryptografickeho OpenSSL kontextu
    EVP_CIPHER_CTX_free(ctx);
    return AES_XTS_SUCCESS;
}

/**
 * Derivacia kluca z hesla pomocou Argon2id KDF
 *
 * Popis: Odvodzuje sifrovaci kluc pre AES-XTS z pouzivatelskeho hesla
 * a vygenrovanej nahodnej soli pomocou Argon2id funkcie pre derivaciu
 * klucov (KDF). Argon2id je odolna voci utokom hrubou silou,
 * hardverovym utokom a side-channel utokom. Vytvoreny kluc ma
 * dvojnasobnu velkost pre XTS rezim, kde prva polovica sluzi na
 * sifrovanie a druha ako "tweak" kluc.
 *
 * Proces:
 * 1. Vypocet potrebnej dlzky vysledneho kluca (pre XTS potrebujeme dvojnasobnu velkost)
 * 2. Inicializacia kontextu pre KDF algoritmus Argon2id
 * 3. Nastavenie parametrov: heslo, sol, iteracie, pouzita pamat a paralelizacia
 * 4. Derivacia kluca podla parametrov
 * 5. Uvolnenie zdrojov
 *
 * Parametre:
 * @param password - Pouzivatelske heslo ako vstup pre KDF
 * @param salt - Nahodna sol pre zabranenie slovnikovym utokom
 * @param salt_len - Dlzka soli v bajtoch
 * @param key - Buffer pre vystupny kluc (double-size pre XTS)
 * @param key_bits - Velkost pozadovaneho kluca v bitoch (128 alebo 256)
 * @param iterations - Pocet iteracii Argon2id algoritmu (vyrazne ovplyvnuje bezpecnost)
 * @param memory_cost - Pamatova narocnost v KB (spomaluje utoky na specializovanom hardveri)
 *
 * Navratove hodnoty:
 * @return AES_XTS_SUCCESS pri uspesnej derivacii kluca
 * @return AES_XTS_ERROR_OPENSSL pri chybe OpenSSL kniznice
 *
 * Bezpecnostne poznamky:
 * - Argon2id kombinuje odolnost proti side-channel utokom aj utokom hrubou silou
 * - Vysoke hodnoty memory_cost a iterations zvysuju bezpecnost, ale spomaluju program
 * - Tato funkcia generuje cely spojeny kluc potrebny pre XTS v jednom volani
 */
int derive_keys_from_password(
    const uint8_t *password, 
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key,
    int key_bits, 
    uint32_t iterations,
    uint32_t memory_cost
) {
    // Vypocet dlzky kluca - pre XTS rezim potrebujeme 2x dlzku standardneho kluca
    size_t key_len = (key_bits / BITS_PER_BYTE) * 2;
    uint32_t parallelism = DEFAULT_PARALLELISM;
    
    // Inicializacia KDF algoritmu Argon2id
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
    if (!kdf) {
        fprintf(stderr, "Chyba: Argon2id nie je dostupny v tejto verzii OpenSSL\n");
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }
    
    // Vytvorenie kontextu pre KDF
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);  // KDF objekt mozno uvolnit po vytvoreni kontextu
    if (!kctx) {
        print_openssl_error();
        return AES_XTS_ERROR_OPENSSL;
    }
    
    // Nastavenie parametrov pre Argon2id
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string("pass", (void*)password, strlen((const char*)password)),
        OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len),
        OSSL_PARAM_construct_uint32("iterations", &iterations),
        OSSL_PARAM_construct_uint32("m_cost", &memory_cost),
        OSSL_PARAM_construct_uint32("parallelism", &parallelism),
        OSSL_PARAM_construct_end()
    };
    
    // Odvodenie kluca - vytvorenie kluca s dvojnasobnou velkostou pre XTS
    if (EVP_KDF_derive(kctx, key, key_len, params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kctx);
        return AES_XTS_ERROR_OPENSSL;
    }
    
    // Uvolnenie zdrojov a navrat uspesneho vysledku
    EVP_KDF_CTX_free(kctx);
    return AES_XTS_SUCCESS;
}

/**
 * Bezpecne nacitanie hesla od pouzivatela
 *
 * Popis: Umoznuje bezpecne nacitanie hesla zo standardneho vstupu
 * bez jeho zobrazovania na obrazovke. Na Windows namiesto znakov hesla
 * zobrazuje hviezdicky (*), na Linux pri zadavani nezobrazuje nic a
 * podporuje mazanie znakov klavesom backspace.
 *
 * Proces spracovania:
 * 1. Vypise vyzvu (prompt) na zadanie hesla
 * 2. Vypne echo vstupu v terminali (platformovo specificka implementacia)
 * 3. Nacitava znaky zo standardneho vstupu po jednom:
 *    - Enter (CR/LF) ukonci nacitavanie
 *    - Backspace (BS/DEL) vymaze posledny znak
 *    - Ostatne viditelne znaky sa ulozia do hesla a zobrazi sa *
 * 4. Obnovi povodne nastavenie terminalu
 * 5. Ukonci retazec nulovym znakom
 *
 * Platformova implementacia:
 * - Windows: Pouziva GetStdHandle a SetConsoleMode s ENABLE_ECHO_INPUT
 *   flagom, cita znaky pomocou _getch() funkcie
 * - Linux/Unix: Pouziva termios strukturu pre nastavenie terminaloveho
 *   modu s vypnutym ECHO flagom, cita znaky cez standardny getchar()
 *
 * Parametre:
 * @param password - Pointer na buffer, kam sa ulozia nacitane znaky hesla
 * @param max_len - Maximalna velkost buffra pre heslo (vratane nuloveho znaku)
 * @param prompt - Textova vyzva pre pouzivatela (napr. "Zadajte heslo: ")
 *
 * Bezpecnostne aspekty:
 * - Heslo nie je zobrazovane na obrazovke
 * - Heslo zostava v pamati aj po volani, musi byt bezpecne vymazane
 *   po pouziti volanim secure_clear_memory()
 */
void read_password(uint8_t *password, size_t max_len, const char *prompt) {
    printf("%s", prompt);  // Zobrazenie vyzvy
    fflush(stdout);        // Vynutenie okamziteho zobrazenia vyzvy
    
    size_t i = 0;          // Index pre ulozenie znakov hesla
    int c;                 // Nacitany znak
    
    #ifdef _WIN32
    // Windows-specificka implementacia pre vypnutie zobrazenia znakov
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);                        // Ulozenie povodneho nastavenia
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));  // Vypnutie echa
    #else
    // Linux/Unix implementacia pre vypnutie zobrazenia znakov
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);               // Ulozenie povodneho nastavenia
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);                      // Vypnutie echa
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);      // Aplikovanie novych nastaveni
    #endif
    
    // Hlavny cyklus citania znakov hesla
    while (i < max_len - 1 && (c = 
        #ifdef _WIN32
        _getch()                       // Windows-specificky sposob citania znakov
        #else
        getchar()                      // Linux/Unix sposob citania znakov
        #endif
    ) != EOF) {
        if (c == '\r' || c == '\n')    // Enter ukonci nacitavanie
            break;
        else if ((c == '\b' || c == 127) && i > 0) {  // Backspace vymaze predchadzajuci znak
            i--;
            printf("\b \b");      // Posun kurzora spat, vymaze znak a opat posun kurzora
            fflush(stdout);
        }
        else if (c >= 32 && c <= 255) {  // Bezne znaky sa ulozia do hesla
            password[i++] = c;
            printf("*");                 // Zobrazenie hviezdicky namiesto skutocneho znaku
            fflush(stdout);
        }
    }
    
    #ifdef _WIN32
    // Obnovenie povodneho nastavenia konzoly vo Windows
    SetConsoleMode(hStdin, mode);
    #else
    // Obnovenie povodneho nastavenia terminalu v Linux/Unix
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    #endif
    
    password[i] = '\0';    // Ukoncenie retazca hesla
    printf("\n");          // Prechod na novy riadok po dokonceni
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

void secure_clear_memory(void *buffer, size_t size, bool free_memory) {
    if (buffer) {
        OPENSSL_cleanse(buffer, size);
        
        if (free_memory) {
            #ifdef _WIN32
            _aligned_free(buffer);
            #else
            free(buffer);
            #endif
        }
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
    const uint8_t *key,   
    uint64_t sector_offset
) {
    const size_t completeSectors = bytesRead / SECTOR_SIZE;
    const size_t remainderBytes = bytesRead % SECTOR_SIZE;

    #pragma omp parallel for schedule(dynamic, 32)
    for (size_t i = 0; i < completeSectors; i++) {
        const uint64_t current_sector = sector_offset + i;
        uint8_t *sector_data = buffer + (i * SECTOR_SIZE);
        aes_xts_crypt_sector(key, current_sector, sector_data, SECTOR_SIZE, encrypt, key_bits);
    }

    if (remainderBytes > 0) {
        uint8_t lastSectorBuffer[SECTOR_SIZE] = {0};
        memcpy(lastSectorBuffer, buffer + completeSectors * SECTOR_SIZE, remainderBytes);
        
        aes_xts_crypt_sector(key, sector_offset + completeSectors, 
                            lastSectorBuffer, SECTOR_SIZE, encrypt, key_bits);
        
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
    uint8_t *key,      
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
    
    const size_t buffer_size = BUFFER_SIZE;
    uint8_t *buffer = allocate_aligned_buffer(buffer_size);
    if (!buffer) {
        return AES_XTS_ERROR_MEMORY;
    }
    
    if (!set_position(ctx, startOffset)) {
        secure_clear_memory(buffer, buffer_size,true);
        return AES_XTS_ERROR_IO;
    }
    
    uint64_t currentOffset = startOffset;
    uint64_t sector_num = 0;
    uint64_t total_mb = total_size / BYTES_PER_MB;
    #ifdef _WIN32
        printf("Zacinam %s %llu MB dat...\n", encrypt ? "sifrovanie" : "desifrovanie", total_mb);
    #else
        printf("Zacinam %s %lu MB dat...\n", encrypt ? "sifrovanie" : "desifrovanie", (unsigned long)total_mb);
    #endif
    while (currentOffset < startOffset + total_size) {
        ssize_t bytesRead = read_sectors_block(ctx, buffer, buffer_size, currentOffset);
        if (bytesRead <= 0) {
            if (bytesRead < 0) {
                secure_clear_memory(buffer, buffer_size,true);
                return AES_XTS_ERROR_IO;
            }
            break; 
        }
        
        process_block(buffer, bytesRead, encrypt, key_bits, key, sector_num);
        
        ssize_t bytesWritten = write_sectors_block(ctx, buffer, bytesRead, currentOffset);
        if (bytesWritten != bytesRead) {
            secure_clear_memory(buffer, buffer_size,true);
            return AES_XTS_ERROR_IO;
        }
        
        currentOffset += bytesWritten;
        sector_num += bytesRead / SECTOR_SIZE;
        
        uint64_t progress = currentOffset - startOffset;
        show_progress(progress, total_size, sector_num);
    }
    
    printf("\n");
    secure_clear_memory(buffer, buffer_size,true);
    return AES_XTS_SUCCESS;
}

int header_io(device_context_t *ctx, xts_header_t *header, int isWrite) {
    uint8_t *sector = allocate_aligned_buffer(SECTOR_SIZE);
    if (!sector) {
        return AES_XTS_ERROR_MEMORY;
    }
    
    memset(sector, 0, SECTOR_SIZE);
    const uint64_t headerPos = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;
    ssize_t bytesTransferred;
    int result = AES_XTS_SUCCESS;
    
    if (!set_position(ctx, headerPos)) {
        result = AES_XTS_ERROR_IO;
        goto cleanup;
    }
    
    if (isWrite) {
        memcpy(sector, header, sizeof(xts_header_t));
        bytesTransferred = write_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            result = AES_XTS_ERROR_IO;
            goto cleanup;
        }
        
        #ifdef _WIN32
        FlushFileBuffers(ctx->handle);
        #else
        fsync(ctx->fd);
        #endif
    } else {
        bytesTransferred = read_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            result = AES_XTS_ERROR_IO;
            goto cleanup;
        }
        
        memcpy(header, sector, sizeof(xts_header_t));
        
        if (memcmp(header->magic, HEADER_MAGIC, HEADER_MAGIC_SIZE) != 0) {
            result = AES_XTS_ERROR_PARAM;
        }
    }
    
cleanup:
    secure_clear_memory(sector, SECTOR_SIZE,true);
    return result;
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

/**
 * Spracovanie zadania hesla od pouzivatela s bezpecnostnymi odporucaniami
 *
 * Popis: Zobrazi pouzivatelovi bezpecnostne odporucania pre volbu
 * kvalitneho hesla, nacita heslo zo vstupu a v pripade potreby vyziada
 * jeho potvrdenie. Poskytuje upozornenia na bezpecnostne rizika, ale
 * umoznuje pouzit lubovlne heslo podla rozhodnutia pouzivatela.
 *
 * Proces:
 * 1. Zobrazi bezpecnostne odporucania pre vytvorenie silneho hesla
 * 2. Vyzve uzivatela na zadanie hesla (bez zobrazenia na obrazovke)
 * 3. V pripade kratkeho hesla zobrazi varovanie, ale pokracuje
 * 4. V pripade potreby vyzada potvrdenie hesla a porovna obidve hesla
 *
 * Parametre:
 * @param password - Buffer pre ulozenie zadaneho hesla
 * @param password_size - Velkost buffera pre heslo
 * @param verify - Priznak, ci sa ma vyzadovat potvrdenie hesla (1 = ano, 0 = nie)
 *
 * Navratova hodnota:
 * @return true ak bolo heslo uspesne zadane a potvrdene (ak sa vyzadovalo),
 *         false ak zadanie zlyhalo alebo hesla sa nezhoduju
 *
 * Bezpecnostne poznamky:
 * - Heslo zostava v pamati po volani, potrebne vycistit secure_clear_memory()
 * - Upozornuje na rizika slabych hesiel, ale nespori vstup podla kriterii
 */
bool process_password_input(uint8_t *password, size_t password_size, int verify) {
    printf("\n--------------------------------------------------\n");
    printf("BEZPECNOSTNE ODPORUCANIA PRE HESLO:\n");
    printf("--------------------------------------------------\n");
    printf("- Pouzite aspon %d znakov (dlhsie heslo = lepsie)\n", MIN_PASSWORD_LENGTH);
    printf("- Kombinujte VELKE a male pismena\n");
    printf("- Pridajte cisla (0-9)\n");
    printf("- Pouzite specialne znaky (!@#$%%^&*)\n");
    printf("- Nepouzivajte mena, datumy narodenia a zname slova\n");
    printf("- Pouzite pre kazde zariadenie ine heslo\n");
    printf("--------------------------------------------------\n");
    printf("POZOR: Ak zabudnete heslo, data NEMOZU byt obnovene!\n");
    printf("--------------------------------------------------\n\n");
    
    read_password(password, password_size, "Zadajte heslo: ");
    
    // Upozornenie na kratke heslo, ale pokracujeme dalej
    if (strlen((char*)password) < MIN_PASSWORD_LENGTH) {
        printf("\n");
        printf("!!! VAROVANIE: Pouzivate kratke heslo (menej ako %d znakov) !!!\n", MIN_PASSWORD_LENGTH);
        printf("!!! Kratke hesla su lahsie prelomitelne a VYRAZNE znizuju bezpecnost !!!\n");
        printf("\n");
    }
    
    if (verify) {
        uint8_t confirm_password[PASSWORD_BUFFER_SIZE];
        read_password(confirm_password, sizeof(confirm_password), "Potvrdte heslo: ");
        
        if (strcmp((char*)password, (char*)confirm_password) != 0) {
            fprintf(stderr, "Chyba: Hesla sa nezhoduju\n");
            secure_clear_memory(confirm_password, sizeof(confirm_password), false);
            return false;
        }
        secure_clear_memory(confirm_password, sizeof(confirm_password), false);
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
        EVP_MAC_update(hmac_ctx, salt, SALT_SIZE)) {
        
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

    while (fgets(line, sizeof(line), mtab) && !mounted) {
        mounted = strstr(line, device_path) != NULL;
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
        printf("  %s encrypt 128 /dev/sdb1   # 128-bitovy kluc\n", argv[0]);
        printf("  %s encrypt 256 /dev/sdb1   # 256-bitovy kluc\n", argv[0]);
        printf("  %s encrypt /dev/sdb1       # Predvoleny 256-bitovy kluc\n", argv[0]);
        printf("  %s decrypt /dev/sdb1       # Kluc z hlavicky\n", argv[0]);
        return false;
    }

    *operation = argv[1];
    *device_path = NULL;
    
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
    xts_header_t header = {0};
    int result = 0;
    
    printf("Pouziva sa %d-bitove sifrovanie\n", key_bits);
    
    if (!process_user_confirmation(device_path, key_bits) ||
        !process_password_input(password, sizeof(password), 1)) {
        return 0;
    }

    // Alokacia spojeneho kluca
    uint8_t *key = (uint8_t*)malloc(key_bits / BITS_PER_BYTE * 2);
    if (!key) {
        fprintf(stderr, "Chyba: Nedostatok pamate pri alokacii kluca\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    // Inicializácia hlavičky
    memcpy(header.magic, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    header.version = HEADER_VERSION;
    header.encryption_type = HEADER_ENCRYPTION_TYPE;
    header.start_sector = RESERVED_SECTORS;
    header.iterations = DEFAULT_ITERATIONS;
    header.memory_cost = DEFAULT_MEMORY_COST;
    header.key_bits = key_bits;

    if (!RAND_bytes(header.salt, SALT_SIZE)) {
        print_openssl_error();
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }

    if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                               key, key_bits,
                               header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }
    
    create_verification_data(key, key_bits, header.salt, header.verification_data);
    
    if (header_io(ctx, &header, 1) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }
    
    result = process_sectors(ctx, key, header.start_sector, ENCRYPT_MODE, key_bits);
    
    secure_clear_memory(password, sizeof(password), false);
    secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
    
    return result;
}

int decrypt_device(device_context_t *ctx) {
    uint8_t password[PASSWORD_BUFFER_SIZE] = {0};
    xts_header_t header = {0};
    int result = 0;
    
    if (header_io(ctx, &header, 0) != AES_XTS_SUCCESS) {
        fprintf(stderr, "Neplatna alebo poskodena hlavicka\n");
        return 0;
    }
    
    if (!process_password_input(password, sizeof(password), 0)) {
        return 0;
    }

    printf("Pouziva sa %d-bitove sifrovanie\n", header.key_bits);

    // Alokacia spojeneho kluca s velkostou podla nacitanej hlavicky
    uint8_t *key = (uint8_t*)malloc(header.key_bits / BITS_PER_BYTE * 2);
    if (!key) {
        fprintf(stderr, "Chyba: Nedostatok pamate pri alokacii kluca\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                               key, header.key_bits, 
                               header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }

    uint8_t verification_check[VERIFICATION_DATA_SIZE];
    create_verification_data(key, header.key_bits, header.salt, verification_check);

    if (memcmp(verification_check, header.verification_data, VERIFICATION_DATA_SIZE) != 0) {
        fprintf(stderr, "Chyba: Neplatne heslo alebo poskodene data\n");
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
        return AES_XTS_ERROR_WRONG_PWD;
    }

    result = process_sectors(ctx, key, header.start_sector, DECRYPT_MODE, header.key_bits);
    
    secure_clear_memory(password, sizeof(password), false);
    secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
    
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
    } else if (strcmp(operation, "decrypt") == 0) {
        result = decrypt_device(&ctx);
    } else {
        fprintf(stderr, "Neznamy prikaz: %s\n", operation);
        result = AES_XTS_ERROR_PARAM;
    }
    
    close_device(&ctx);
    aes_xts_cleanup();
    
    if (result == AES_XTS_SUCCESS) {
        printf("Operacia uspesne dokoncena.\n");
        return EXIT_SUCCESS;
    } else if (result == 0) {
        printf("Operacia zrusena pouzivatelom.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Operacia zlyhala s chybovym kodom %d.\n", result);
        return EXIT_FAILURE;
    }
}