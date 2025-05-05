/************************************************************************
 * Nazov projektu: AES-XTS sifrovanie a desifrovanie diskov pomocou OpenSSL
 * ----------------------------------------------------------------------------
 * Subor: aes_xts.c 
 * Verzia: 2.1 
 * Datum: 25.3.2025
 *
 * Autor: Kamil Berecky
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

/**
 * Otvorenie diskovej particie alebo celeho disku pre sifrovanie
 *
 * Popis: Otvara zariadenie pre citanie a zapis a pripravuje ho na
 * sifrovanie/desifrovanie. Na roznych operacnych systemoch pouziva
 * odlisne techniky.
 *
 * Proces:
 * 1. Windows implementacia:
 *    - Urcenie typu zariadenia (disk/particiu)
 *    - Ukladanie cesty k zariadeniu do kontextu
 *    - Kontrola a priprava zvoleneho oddielu 
 *    - Ziskanie velkosti zariadenia
 * 2. Linux implementacia:
 *    - Kontrola ci oddiely nie su pripojene (zabranenie poskodeniu dat)
 *    - Otvorenie zariadenia v rezime citania/zapisu
 *    - Ziskanie velkosti zariadenia pomocou ioctl
 *
 * Parametre:
 * @param path - Cesta k zariadeniu (napr. "/dev/sda1" alebo "\\\\.\\PhysicalDrive0")
 * @param ctx - Kontext zariadenia pre ulozenie deskriptorov a informacii
 *
 * Navratova hodnota:
 * @return true ak sa zariadenie podarilo otvorit a pripravit,
 *         false v pripade zlyhania
 *
 * Bezpecnostne aspekty:
 * - Na Windows vyzaduje administratorske opravnenia
 * - Na Linuxe kontroluje ci je oddiel odpojeny
 * - Zariadenie je otvorene s vyhradnym pristupom pre zabranenie konfliktom
 */
bool open_device(const char *path, device_context_t *ctx) {
    #ifdef _WIN32
    // Zistenie typu zariadenia - fyzicky disk alebo logicky oddiel
    ctx->type = get_device_type(path);
    
    // Ulozenie cesty k zariadeniu do kontextu (bezpecne kopirovanie s osetrenim null-terminatora)
    strncpy(ctx->path, path, MAX_PATH - 1);
    ctx->path[MAX_PATH - 1] = '\0';
    
    // Kontrola ci je zariadenie pripojene ako Windows jednotka a zobrazenie informacie
    check_volume(path);
    
    // Priprava zariadenia na sifrovanie - vyzaduje administratorske prava, 
    // otvara zariadenie a uzamyka ho pred inym pristupom
    if (!prepare_device_for_encryption(path, &ctx->handle)) {
        return false;
    }
    
    // Zistenie velkosti zariadenia, rozny pristup k diskom a logickym oddielom
    ctx->size = get_device_size(ctx->handle, ctx->type);
    return ctx->size.QuadPart != 0;  // Uspech len ak sa podarilo ziskat velkost > 0
    
    #else
    // Linux implementacia
    
    // Kontrola ci oddiel nie je prave pripojeny (mounted) v systeme
    // Sifrovanie pripojeneho oddielu by sposobilo poskodenie dat
    if (is_partition_mounted(path)) {
        fprintf(stderr, "Chyba: Oddiel %s je pripojeny. Odpojte ho pred operaciou.\n", path);
        return false;
    }
    
    // Otvorenie zariadenia pre citanie a zapis
    ctx->fd = open(path, O_RDWR);
    if (ctx->fd < 0) {
        perror("Chyba pri otvarani zariadenia");
        return false;
    }
    
    // Zistenie celkovej velkosti zariadenia pomocou ioctl volania BLKGETSIZE64
    ctx->size = get_partition_size(ctx->fd);
    return ctx->size != 0;  // Uspech len ak sa podarilo ziskat velkost > 0
    #endif
}

/**
 * Zatvorenie zariadenia a uvolnenie zdrojov
 *
 * Popis: Bezpecne zatvara otvorene zariadenie a uvolnuje vsetky
 * alokovane zdroje. Na Windows najprv odomyka disk a potom
 * uzatvara handle, na Linuxe zatvara file descriptor.
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/file descriptor
 *
 * Platformove rozdiely:
 * - Windows: Odomyka disk pred zatvorenim a resetuje handle
 * - Linux: Zatvara file descriptor a oznacuje ho ako neplatny
 */
void close_device(device_context_t *ctx) {
    #ifdef _WIN32
    // Kontrola ci je handle platny, potom odomyka a zatvara zariadenie
    if (ctx->handle != INVALID_HANDLE_VALUE) {
        unlock_disk(ctx->handle);  // Odomknutie zamknuteho zariadenia
        CloseHandle(ctx->handle);  // Zatvorenie handle
        ctx->handle = INVALID_HANDLE_VALUE;  // Oznacenie handle ako neplatny
    }
    #else
    // Linux implementacia - zatvorenie file descriptora
    if (ctx->fd >= 0) {
        close(ctx->fd);  // Zatvorenie file descriptora
        ctx->fd = -1;    // Oznacenie file descriptora ako neplatny
    }
    #endif
}

/**
 * Alokacia zarovnaneho buffera pre diskove operacie
 *
 * Popis: Alokuje pamat s korektnym zarovnanim pre efektivne diskove
 * operacie. Spravne zarovnanie je dolezite pre priamy pristup k disku
 * a moze vyrazne zrychlit operacie citania/zapisu.
 *
 * Proces:
 * 1. Alokacia pamate so zarovnanim na velkost sektora (zvycajne 512 bajtov)
 * 2. Inicializacia alokovanej pamate na nuly
 * 3. Kontrola uspesnosti alokacie
 *
 * Parametre:
 * @param size - Velkost buffera v bajtoch, ktory ma byt alokovany
 *
 * Navratova hodnota:
 * @return ukazovatel na alokovany buffer, alebo NULL v pripade zlyhania
 *
 * Platformove rozdiely:
 * - Windows: Pouziva _aligned_malloc zo standardnej kniznice
 * - Linux: Pouziva posix_memalign pre zarovnanu alokaciu
 *
 * Poznamka: Pamat alokovana touto funkciou musi byt uvolnena pomocou
 * secure_clear_memory s parametrom free_memory nastavenym na true
 */
uint8_t* allocate_aligned_buffer(size_t size) {
    uint8_t* buffer = NULL;
    #ifdef _WIN32
    // Windows-specificka funkcia pre zarovnanu alokaciu
    buffer = (uint8_t *)_aligned_malloc(size, SECTOR_SIZE);
    #else
    // Linux/POSIX implementacia zarovnanej alokacie
    if (posix_memalign((void**)&buffer, SECTOR_SIZE, size) != 0) {
        buffer = NULL;  // V pripade zlyhania vratime NULL
    }
    #endif
    
    // Inicializacia alokovaneho buffera na nuly
    if (buffer) {
        memset(buffer, 0, size);
    }
    return buffer;
}

/**
 * Bezpecne vymazanie senzitivnych udajov z pamate
 *
 * Popis: Bezpecne vymaze senzitivne data z pamate a volitelne uvolni
 * alokovanu pamat. Pouziva OpenSSL funkciu OPENSSL_cleanse, ktora je
 * navrhuta tak, aby nemohla byt optimalizatorom odstranena a zabezpecuje
 * skutocne vymazanie dat.
 *
 * Proces:
 * 1. Kontrola ci buffer existuje
 * 2. Vymazanie dat pomocou kryptograficky bezpecnej funkcie
 * 3. Volitelne uvolnenie pamate podla parametru free_memory
 *
 * Parametre:
 * @param buffer - Ukazovatel na pamat, ktora ma byt vymazana
 * @param size - Velkost pamate na vymazanie v bajtoch
 * @param free_memory - Priznak ci sa ma pamat po vymazani uvolnit (true = ano)
 *
 * Bezpecnostne aspekty:
 * - Zabranuje ulozenam privlacnym bufferom (RAM/SWAP)
 * - Zabranuje optimalizaciam kompilatora, ktore by mohli odstranit mazanie
 * - Pouziva sa pre vsetky citlive data (hesla, kluce)
 *
 * Platformove rozdiely:
 * - Pri uvolnovani pamate pouziva na Windows _aligned_free, na Linuxe standardne free()
 */
void secure_clear_memory(void *buffer, size_t size, bool free_memory) {
    if (buffer) {
        // Bezpecne vycistenie pamate (nemozne optimalizovat prec)
        OPENSSL_cleanse(buffer, size);
        
        // Volitelne uvolnenie pamate
        if (free_memory) {
            #ifdef _WIN32
            _aligned_free(buffer);  // Pre zarovnanu pamat na Windows
            #else
            free(buffer);           // Standardne uvolnenie na Linuxe
            #endif
        }
    }
}

/**
 * Precitanie bloku sektorov zo zariadenia
 *
 * Popis: Citanie bloku dat zo zariadenia s kontrolou hranicnych podmienok.
 * Zabezpecuje, ze nedojde k pokusu o citanie za fyzicku hranicu zariadenia.
 *
 * Proces:
 * 1. Vypocet maximalnej velkosti dat, ktore je mozne precitat
 * 2. Kontrola ci pozadovana velkost nepresahuje hranice zariadenia
 * 3. Upravenie velkosti citania v pripade potreby
 * 4. Vykonanie citania pomocou nizkouronovej funkcie read_data()
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/fd a informacie o velkosti
 * @param buffer - Vystupny buffer pre nacitane data
 * @param max_size - Maximalna velkost dat na precitanie v bajtoch
 * @param currentOffset - Pozicia v zariadeni, odkial sa budu citat data
 *
 * Navratova hodnota:
 * @return pocet precitanych bajtov, alebo -1 v pripade chyby
 *
 * Platformove rozdiely:
 * - Windows: Pouziva velkost z ctx->size.QuadPart
 * - Linux: Pouziva velkost z ctx->size
 *
 * Privatna funkcia: Oznacena ako static, pretoze je pouzivana len v ramci modulu
 */
static ssize_t read_sectors_block(device_context_t *ctx, uint8_t *buffer, size_t max_size, uint64_t currentOffset) {
    size_t bytesToRead = max_size;
    
    // Kontrola ci sa nepokusame citat za koniec zariadenia
    #ifdef _WIN32
    if (currentOffset + bytesToRead > (uint64_t)ctx->size.QuadPart)
        bytesToRead = ctx->size.QuadPart - currentOffset;  // Uprava velkosti ak presahujeme
    #else
    if (currentOffset + bytesToRead > ctx->size)
        bytesToRead = ctx->size - currentOffset;  // Uprava velkosti ak presahujeme
    #endif
    
    // Vykonanie samotneho citania
    return read_data(ctx, buffer, bytesToRead);
}

/**
 * Paralelne spracovanie bloku dat (sifrovanie/desifrovanie)
 *
 * Popis: Spracovava blok dat po sektoroch pomocou AES-XTS algoritmu
 * s vyuzitim OpenMP pre paralelizaciu. Zabezpecuje efektivne spracovanie
 * velkych blokov dat rozdelenim na sektory, ktore su spracovane paralelne.
 *
 * Proces:
 * 1. Vypocet poctu sektorov v bloku
 * 2. Paralelne spracovanie sektorov pomocou OpenMP
 *
 * Parametre:
 * @param buffer - Buffer obsahujuci data na spracovanie
 * @param bytesRead - Velkost dat v bufferi v bajtoch
 * @param encrypt - Priznak rezimu (1 = sifrovanie, 0 = desifrovanie)
 * @param key_bits - Velkost kluca v bitoch (128 alebo 256)
 * @param key - Kluc pre sifrovanie/desifrovanie
 * @param sector_offset - Poradove cislo prveho sektora v bloku
 *
 * Technicke detaily:
 * - Paralelizacia pomocou OpenMP s dynamickym rozvrhovanim uloh
 * - OpenSSL implementacia XTS automaticky riesi vsetky velkosti dat
 */
static void process_block(
    uint8_t *buffer, 
    ssize_t bytesRead, 
    int encrypt, 
    int key_bits, 
    const uint8_t *key,   
    uint64_t sector_offset
) {
    // Vypocet poctu sektorov v bloku (zaokruhlenie nahor pre posledny neuplny sektor)
    const size_t num_sectors = (bytesRead + SECTOR_SIZE - 1) / SECTOR_SIZE;

    // Paralelne spracovanie vsetkych sektorov v bloku pomocou OpenMP
    #pragma omp parallel for schedule(dynamic, 32)
    for (size_t i = 0; i < num_sectors; i++) {
        // Vypocet aktualneho cisla sektora (globalny offset + lokalna pozicia)
        const uint64_t current_sector = sector_offset + i;
        // Pointer na data konkretneho sektora v ramci buffra
        uint8_t *sector_data = buffer + (i * SECTOR_SIZE);
        
        // Vypocet velkosti posledneho sektora (moze byt mensi ako SECTOR_SIZE)
        size_t sector_size = SECTOR_SIZE;
        if (i == num_sectors - 1 && bytesRead % SECTOR_SIZE != 0) {
            sector_size = bytesRead % SECTOR_SIZE;
        }
        
        // Volanie AES-XTS sifrovania/desifrovanis pre konkretny sektor
        aes_xts_crypt_sector(key, current_sector, sector_data, sector_size, encrypt, key_bits);
    }
}

/**
 * Zapis bloku sektorov na zariadenie
 *
 * Popis: Zapisuje blok dat do zariadenia s nastavenim pozicie pred zapisom.
 * Zabezpecuje spravne umiestnenie zapisovanych dat na zariadeni.
 *
 * Proces:
 * 1. Nastavenie pozicie v zariadeni pomocou set_position()
 * 2. Zapis dat pomocou nizkouronovej funkcie write_data()
 * 3. Vratenie poctu zapisanych bajtov alebo -1 pri chybe
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/fd
 * @param buffer - Vstupny buffer s datami na zapis
 * @param bytesToWrite - Velkost dat na zapis v bajtoch
 * @param currentOffset - Pozicia v zariadeni, kam sa budu zapisovat data
 *
 * Navratova hodnota:
 * @return pocet zapisanych bajtov, alebo -1 v pripade chyby
 *
 * Privatna funkcia: Oznacena ako static, pretoze je pouzivana len v ramci modulu
 */
static ssize_t write_sectors_block(device_context_t *ctx, uint8_t *buffer, size_t bytesToWrite, uint64_t currentOffset) {
    // Nastavenie spravnej pozicie v zariadeni pred zapisom
    if (!set_position(ctx, currentOffset)) {
        return -1;  // Chyba pri nastavovani pozicie
    }
    // Samotny zapis dat na zariadenie
    return write_data(ctx, buffer, bytesToWrite);
}

/**
 * Spracovanie sektorov zariadenia (sifrovanie/desifrovanie)
 *
 * Popis: Hlavna funkcia pre postupne spracovanie vsetkych sektorov zariadenia
 * od zadaneho pociatocneho sektora. Cita, spracovava a zapisuje data po blokoch
 * pre efektivnu pracu s velkymi diskmi/oddielmi.
 *
 * Proces:
 * 1. Vypocet pociatocnej pozicie a celkovej velkosti dat
 * 2. Alokacia pracovneho buffra pre bloky dat
 * 3. Nastavenie pociatocnej pozicie v zariadeni
 * 4. Cyklus spracovania: citanie bloku -> sifrovanie/desifrovanie -> zapis
 * 5. Zobrazenie priebehu spracovania
 * 6. Uvolnenie zdrojov
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/fd a informacie o velkosti
 * @param key - Kluc pre sifrovanie/desifrovanie dat
 * @param start_sector - Cislo sektora, od ktoreho sa zacne spracovanie
 * @param encrypt - Priznak rezimu (1 = sifrovanie, 0 = desifrovanie)
 * @param key_bits - Velkost kluca v bitoch (128 alebo 256)
 *
 * Navratova hodnota:
 * @return kod vysledku operacie (AES_XTS_SUCCESS pri uspesnom dokonceni)
 *
 * Bezpecnostne aspekty:
 * - Bezpecne uvolnuje vsetky zdroje aj pri chybe
 * - Podporuje zarovnane bufre pre optimalny pristup k disku
 */
int process_sectors(
    device_context_t *ctx,
    uint8_t *key,      
    uint64_t start_sector,
    int encrypt,
    int key_bits
) {
    // Vypocet oddelenia a celkovej velkosti dat na spracovanie
    const uint64_t startOffset = start_sector * SECTOR_SIZE;
    const uint64_t total_size = 
        #ifdef _WIN32
        ctx->size.QuadPart - startOffset;
        #else
        ctx->size - startOffset;
        #endif
    
    // Alokacia pracovneho buffera pre bloky dat
    const size_t buffer_size = BUFFER_SIZE;
    uint8_t *buffer = allocate_aligned_buffer(buffer_size);
    if (!buffer) {
        return AES_XTS_ERROR_MEMORY;  // Zlyhanie alokacie pamate
    }
    
    // Nastavenie pociatocnej pozicie v zariadeni
    if (!set_position(ctx, startOffset)) {
        secure_clear_memory(buffer, buffer_size, true);
        return AES_XTS_ERROR_IO;  // Chyba pri nastavovani pozicie
    }
    
    // Inicializacia premennych pre sledovanie priebehu
    uint64_t currentOffset = startOffset;
    uint64_t sector_num = 0;
    uint64_t total_mb = total_size / BYTES_PER_MB;
    
    // Zobrazenie informacie o zaciatku procesu s rozdielnymi formatmi pre Windows/Linux
    #ifdef _WIN32
        printf("Zacinam %s %llu MB dat...\n", encrypt ? "sifrovanie" : "desifrovanie", total_mb);
    #else
        printf("Zacinam %s %lu MB dat...\n", encrypt ? "sifrovanie" : "desifrovanie", (unsigned long)total_mb);
    #endif
    
    // Hlavny cyklus spracovania blokov dat
    while (currentOffset < startOffset + total_size) {
        // Citanie bloku dat zo zariadenia
        ssize_t bytesRead = read_sectors_block(ctx, buffer, buffer_size, currentOffset);
        if (bytesRead <= 0) {
            if (bytesRead < 0) {
                secure_clear_memory(buffer, buffer_size, true);
                return AES_XTS_ERROR_IO;  // Chyba pri citani
            }
            break;  // Koniec citania (EOF)
        }
        
        // Sifrovanie/desifrovanie nacitanych dat
        process_block(buffer, bytesRead, encrypt, key_bits, key, sector_num);
        
        // Zapis spracovanych dat spat na zariadenie
        ssize_t bytesWritten = write_sectors_block(ctx, buffer, bytesRead, currentOffset);
        if (bytesWritten != bytesRead) {
            secure_clear_memory(buffer, buffer_size, true);
            return AES_XTS_ERROR_IO;  // Chyba pri zapise
        }
        
        // Aktualizacia premennych pre sledovanie priebehu
        currentOffset += bytesWritten;
        sector_num += bytesRead / SECTOR_SIZE;
        
        // Zobrazenie aktualneho priebehu
        uint64_t progress = currentOffset - startOffset;
        show_progress(progress, total_size, sector_num);
    }
    
    printf("\n");  // Ukoncenie riadka postupu
    secure_clear_memory(buffer, buffer_size, true);  // Bezpecne uvolnenie buffera
    return AES_XTS_SUCCESS;
}

/**
 * Operacie s hlavickou sifrovaneho oddielu
 *
 * Popis: Zabezpecuje citanie a zapis hlavicky sifrovaneho oddielu,
 * ktora obsahuje metadata potrebne pre desifrovanie: sol, velkost kluca,
 * verifikcne data, atd. Hlavicka je ulozena na specialnej pozicii
 * na zariadeni (typicky sektor 62).
 *
 * Proces:
 * 1. Alokacia buffera velkosti sektora pre hlavicku
 * 2. Nastavenie pozicie na sektor s hlavickou
 * 3. Rezim zapisu: Zapis hlavicky a flush na disk
 * 4. Rezim citania: Nacitanie a overenie signatury hlavicky
 * 5. Uvolnenie zdrojov
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/fd
 * @param header - Struktura pre hlavicku na zapis alebo do ktorej sa nacita hlavicka
 * @param isWrite - Priznak operacie (1 = zapis, 0 = citanie)
 *
 * Navratova hodnota:
 * @return kod vysledku operacie (AES_XTS_SUCCESS pri uspesnom dokonceni)
 *
 * Bezpecnostne aspekty:
 * - Bezpecne uvolnuje vsetky zdroje aj pri chybe
 * - Overuje signaturu hlavicky pri citani
 */
int header_io(device_context_t *ctx, xts_header_t *header, int isWrite) {
    // Alokacia buffera pre sektor s hlavickou
    uint8_t *sector = allocate_aligned_buffer(SECTOR_SIZE);
    if (!sector) {
        return AES_XTS_ERROR_MEMORY;  // Zlyhanie alokacie pamate
    }
    
    // Inicializacia buffera na nuly
    memset(sector, 0, SECTOR_SIZE);
    
    // Vypocet pozicie hlavicky
    const uint64_t headerPos = (uint64_t)HEADER_SECTOR * SECTOR_SIZE;
    ssize_t bytesTransferred;
    int result = AES_XTS_SUCCESS;
    
    // Nastavenie pozicie v zariadeni na miesto hlavicky
    if (!set_position(ctx, headerPos)) {
        result = AES_XTS_ERROR_IO;
        goto cleanup;  // Chyba pri nastavovani pozicie
    }
    
    if (isWrite) {
        // Rezim zapisu: Kopirovanie hlavicky do sektoroveho buffera
        memcpy(sector, header, sizeof(xts_header_t));
        
        // Zapis sektora s hlavickou na zariadenie
        bytesTransferred = write_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            result = AES_XTS_ERROR_IO;
            goto cleanup;  // Chyba pri zapise
        }
        
        // Flush zapisanych dat na fyzicke zariadenie (OS-specificka implementacia)
        #ifdef _WIN32
        FlushFileBuffers(ctx->handle);
        #else
        fsync(ctx->fd);
        #endif
    } else {
        // Rezim citania: Nacitanie sektora s hlavickou zo zariadenia
        bytesTransferred = read_data(ctx, sector, SECTOR_SIZE);
        if (bytesTransferred != SECTOR_SIZE) {
            result = AES_XTS_ERROR_IO;
            goto cleanup;  // Chyba pri citani
        }
        
        // Kopirovanie dat zo sektora do struktury hlavicky
        memcpy(header, sector, sizeof(xts_header_t));
        
        // Overenie signatury hlavicky
        if (memcmp(header->magic, HEADER_MAGIC, HEADER_MAGIC_SIZE) != 0) {
            result = AES_XTS_ERROR_PARAM;  // Neplatna hlavicka
        }
    }
    
cleanup:
    // Bezpecne uvolnenie buffera
    secure_clear_memory(sector, SECTOR_SIZE, true);
    return result;
}

/**
 * Nastavenie pozicie v zariadeni
 *
 * Popis: Nastavuje aktualnu poziciu v zariadeni pre nasledne operacie
 * citania alebo zapisu. Pouziva odlisne API pre rozne operacne systemy.
 *
 * Proces:
 * 1. Windows: Konvertuje 64-bitovu poziciu na LARGE_INTEGER a pouziva SetFilePointerEx
 * 2. Linux: Pouziva lseek s SEEK_SET flagom
 * 3. Kontroluje uspesnost operacie
 *
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/fd
 * @param position - Absolutna pozicia v zariadeni v bajtoch
 *
 * Navratova hodnota:
 * @return true ak sa podarilo nastavit poziciu, false v pripade zlyhania
 *
 * Platformove rozdiely:
 * - Windows: Pouziva LARGE_INTEGER a SetFilePointerEx pre 64-bitovy offset
 * - Linux: Pouziva lseek s 64-bitovou podporou
 */
bool set_position(device_context_t *ctx, uint64_t position) {
    #ifdef _WIN32
    // Windows implementacia - konverzia 64-bitovej hodnoty na LARGE_INTEGER
    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG)position;
    
    // Nastavenie pozicie s pouzitim Windows API
    if (!SetFilePointerEx(ctx->handle, pos, NULL, FILE_BEGIN)) {
        return false;  // Chyba pri nastavovani pozicie
    }
    #else
    // Linux implementacia - pouzitie lseek s kontrolou vysledku
    if (lseek(ctx->fd, (off_t)position, SEEK_SET) != (off_t)position) {
        return false;  // Chyba pri nastavovani pozicie
    }
    #endif
    return true;  // Uspesne nastavenie pozicie
}
/**
 * Citanie dat zo zariadenia
 * 
 * Popis: Platformovo nezavisla funkcia pre citanie dat zo zariadenia.
 * Abstrahuje rozdiely medzi Windows a Linux implementaciou.
 * 
 * Proces:
 * 1. Windows implementacia:
 *    - Pouziva ReadFile API
 *    - Kontroluje navratove hodnoty a v pripade chyby vracia -1
 * 2. Linux implementacia:
 *    - Pouziva standardne POSIX read() volanie
 * 
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/file descriptor
 * @param buffer - Vystupny buffer pre nacitane data
 * @param size - Velkost dat na precitanie v bajtoch
 * 
 * Navratova hodnota:
 * @return pocet precitanych bajtov, alebo -1 v pripade chyby
 * 
 * Poznamka: Navratova hodnota 0 znamena koniec suboru (EOF)
 */
ssize_t read_data(device_context_t *ctx, void *buffer, size_t size) {
    #ifdef _WIN32
    // Windows implementacia - pouziva Win32 API
    DWORD bytesRead = 0;
    if (!ReadFile(ctx->handle, buffer, size, &bytesRead, NULL)) {
        return -1;  // Chyba pri citani
    }
    return bytesRead;  // Vrati pocet precitanych bajtov
    #else
    // Linux implementacia - pouziva standardne POSIX volanie
    return read(ctx->fd, buffer, size);
    #endif
}

/**
 * Zapis dat na zariadenie
 * 
 * Popis: Platformovo nezavisla funkcia pre zapis dat na zariadenie.
 * Abstrahuje rozdiely medzi Windows a Linux implementaciou.
 * 
 * Proces:
 * 1. Windows implementacia:
 *    - Pouziva WriteFile API
 *    - Kontroluje navratove hodnoty a v pripade chyby vracia -1
 * 2. Linux implementacia:
 *    - Pouziva standardne POSIX write() volanie
 * 
 * Parametre:
 * @param ctx - Kontext zariadenia obsahujuci handle/file descriptor
 * @param buffer - Vstupny buffer s datami na zapis
 * @param size - Velkost dat na zapis v bajtoch
 * 
 * Navratova hodnota:
 * @return pocet zapisanych bajtov, alebo -1 v pripade chyby
 * 
 * Bezpecnostne aspekty:
 * - Je potrebne skontrolovat, ze vsetky pozadovane data boli zapisane
 * - V pripade nezhody medzi size a pocet zapisanych bajtov doslo k chybe
 */
ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size) {
    #ifdef _WIN32
    // Windows implementacia - pouziva Win32 API
    DWORD bytesWritten = 0;
    if (!WriteFile(ctx->handle, buffer, size, &bytesWritten, NULL)) {
        return -1;  // Chyba pri zapise
    }
    return bytesWritten;  // Vrati pocet zapisanych bajtov
    #else
    // Linux implementacia - pouziva standardne POSIX volanie
    return write(ctx->fd, buffer, size);
    #endif
}

#ifdef _WIN32

/**
 * Kontrola administratorskych opravneni
 * 
 * Popis: Zistuje, ci aktualne bezici proces ma administratorske opravnenia
 * v systeme Windows. Pouziva Windows Security API pre pristup k bezpecnostnym
 * tokenam a identifikacii clenstiev v skupinach.
 * 
 * Proces:
 * 1. Inicializacia SID struktury pre skupinu administratorov
 * 2. Overenie, ci aktualne token pouzivatelov je clenom skupiny administratorov
 * 3. Uvolnenie alokovanych zdrojov
 * 
 * Navratova hodnota:
 * @return TRUE ak proces bezi s administratorskymi pravami, FALSE inak
 * 
 * Bezpecnostne aspekty:
 * - Administratorske opravnenia su nevyhnutne pre manipulaciu s diskovymi oddielmi
 * - Tato funkcia dava pouzivatelovi informaciu o chybe na zaciatku behu programu
 */
BOOL is_admin(void) {
    BOOL isAdmin = FALSE;
    // Definicia autoritative identifikatora pre NT Authority
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;

    // Vytvorenie SID pre skupinu administratorov
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        // Kontrola, ci aktualne token patri do skupiny administratorov
        CheckTokenMembership(NULL, AdminGroup, &isAdmin);
        // Uvolnenie alokovanej SID
        FreeSid(AdminGroup);
    }
    return isAdmin;  // Vrati vysledok kontroly opravneni
}

/**
 * Zistenie typu zariadenia
 * 
 * Popis: Identifikuje typ zariadenia (fyzicky disk alebo logicky oddiel)
 * na zaklade cesty k zariadeniu vo Windows.
 * 
 * Proces:
 * 1. Kontrola, ci cesta zacina prefixom pre fyzicky disk ("\\\\.\\PhysicalDrive")
 * 2. Vrati prislusny typ zariadenia na zaklade vsledku kontroly
 * 
 * Parametre:
 * @param path - Cesta k zariadeniu (napr. "\\\\.\\PhysicalDrive0" alebo "\\\\.\\C:")
 * 
 * Navratova hodnota:
 * @return DEVICE_TYPE_DISK pre fyzicke disky, DEVICE_TYPE_VOLUME pre logicke oddiely
 * 
 * Poznamka: Tato informacia je dolezita pre spravny pristup k zariadeniu
 */
device_type_t get_device_type(const char *path) {
    // Identifikacia typu zariadenia podla cesty - kontrola prefixu PhysicalDrive
    return (strncmp(path, "\\\\.\\PhysicalDrive", 17) == 0) ? DEVICE_TYPE_DISK : DEVICE_TYPE_VOLUME;
}

/**
 * Uzamknutie a odpojenie volumnu
 * 
 * Popis: Uzamyka diskovy volumn a odpoji ho pre vyhradny pristup.
 * Toto je nevyhnutne pred vykonavanim nizkouronovych operacii s diskom.
 * 
 * Proces:
 * 1. Uzamknutie volumnu pomocou FSCTL_LOCK_VOLUME
 * 2. Odpojenie volumnu pomocou FSCTL_DISMOUNT_VOLUME
 * 
 * Parametre:
 * @param hDevice - Handle otvoreneho zariadenia
 * 
 * Navratova hodnota:
 * @return TRUE (vzdy, pretoze chyby sa nedetekuju v aktualnej implementacii)
 * 
 * Bezpecnostne aspekty:
 * - Zabranuje inym procesom pristupovat k volumnu pocas sifrovania/desifovania
 * - Zabranuje konfliktom pri pristupe k rovnakym sektorom
 */
BOOL lock_and_dismount_volume(HANDLE hDevice) {
    DWORD bytesReturned;
    // Uzamknutie volumnu pre vyhradny pristup
    DeviceIoControl(hDevice, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    // Odpojenie volumnu (podobne ako unmount v Linuxe)
    DeviceIoControl(hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    return TRUE;  // Vzdy vracia TRUE (nedetekuje chyby)
}

/**
 * Odomknutie disku
 * 
 * Popis: Odomyka diskovy volumn, ktory bol predtym uzamknuty.
 * Vola sa pri ukonceni prace so zariadenim.
 * 
 * Proces:
 * 1. Kontrola platnosti handle
 * 2. Odomknutie disku pomocou FSCTL_UNLOCK_VOLUME
 * 
 * Parametre:
 * @param hDevice - Handle zariadenia, ktore ma byt odomknute
 * 
 * Bezpecnostne aspekty:
 * - Umoznuje pristup k zariadeniu inym procesom po dokonceni prace
 */
void unlock_disk(HANDLE hDevice) {
    // Kontrola ci je handle platny
    if (hDevice != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        // Odomknutie volumnu - umozni pristup inym procesom
        DeviceIoControl(hDevice, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
    }
}

/**
 * Kontrola a vypis informacie o pripravovanej jednotke
 * 
 * Popis: Identifikuje a zobrazuje informaciu o priprave Windows jednotky
 * na zaklade cesty k zariadeniu.
 * 
 * Proces:
 * 1. Kontroluje, ci cesta ma format pre pristup k Win32 zariadeniu a ci obsahuje pismeno jednotky
 * 2. Zobrazi spravu o priprave prislusnej jednotky
 * 
 * Parametre:
 * @param path - Cesta k zariadeniu (napr. "\\\\.\\C:")
 * 
 * Vystup:
 * - Vypise informaciu o priprave jednotky, ak cesta zodpoveda logickemu oddielu
 */
void check_volume(const char *path) {
    // Kontrola ci je cesta v tvare "\\\\.\\X:" kde X je pismeno disku
    if (path[0] == '\\' && path[1] == '\\' && path[2] == '.' && path[3] == '\\' && isalpha(path[4])) {
        // Vypis informacie o priprave jednotky
        printf("Priprava jednotky %c: na pristup\n", path[4]);
    }
}

/**
 * Zistenie velkosti zariadenia
 * 
 * Popis: Ziskava celkovu velkost zariadenia (fyzickeho disku alebo
 * logickeho oddielu) v bajtoch. Pouziva rozne DeviceIoControl volania
 * v zavislosti od typu zariadenia.
 * 
 * Proces:
 * 1. Podla typu zariadenia vybera prislusne IOCTL volanie
 * 2. Pre volumny pouziva IOCTL_DISK_GET_LENGTH_INFO
 * 3. Pre fyzicke disky pouziva IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
 * 
 * Parametre:
 * @param hDevice - Handle otvoreneho zariadenia
 * @param type - Typ zariadenia (DEVICE_TYPE_DISK alebo DEVICE_TYPE_VOLUME)
 * 
 * Navratova hodnota:
 * @return LARGE_INTEGER obsahujuci velkost zariadenia v bajtoch
 * 
 * Poznamka: LARGE_INTEGER je 64-bitova struktura potrebna pre
 * zariadenia vacsie nez 4GB
 */
LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t type) {
    LARGE_INTEGER size = {0};
    DWORD bytesReturned;

    if (type == DEVICE_TYPE_VOLUME) {
        // Pre logicky oddiel (volume) pouzijeme IOCTL_DISK_GET_LENGTH_INFO
        GET_LENGTH_INFORMATION lengthInfo;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, 
                      &lengthInfo, sizeof(lengthInfo), &bytesReturned, NULL);
        size.QuadPart = lengthInfo.Length.QuadPart;
    } else {
        // Pre fyzicky disk pouzijeme IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
        DISK_GEOMETRY_EX diskGeometry;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, 
                      &diskGeometry, sizeof(diskGeometry), &bytesReturned, NULL);
        size.QuadPart = diskGeometry.DiskSize.QuadPart;
    }

    return size;  // Vrati velkost zariadenia
}

/**
 * Otvorenie zariadenia s opakovanim
 * 
 * Popis: Pokusi sa otvorit zariadenie najprv so standardnymi pristupovymi 
 * pravami a v pripade zlyhania skusi pripojenie s priamym pristupom.
 * 
 * Proces:
 * 1. Pokus o otvorenie zariadenia so standardnymi flagmi
 * 2. Ak to zlyhalo, pokus o otvorenie s flagmi pre priamy pristup k disku
 * 
 * Parametre:
 * @param path - Cesta k zariadeniu (napr. "\\\\.\\PhysicalDrive0" alebo "\\\\.\\C:")
 * 
 * Navratova hodnota:
 * @return Handle k otvorenemu zariadeniu alebo INVALID_HANDLE_VALUE pri zlyhani
 * 
 * Bezpecnostne aspekty:
 * - Podpora pre viacero scenarii pristupu k zariadeniu
 * - FLAG_NO_BUFFERING a FLAG_WRITE_THROUGH zabezpecia priamy pristup k disku
 */
HANDLE open_device_with_retry(const char *path) {
    // Prvy pokus - standardny sposob otvorenia so zdielanim pre citanie/zapis
    HANDLE handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 
                              OPEN_EXISTING, 0, NULL);

    // Ak to zlyhalo, skusime priamy pristup s vypnutim cache
    if (handle == INVALID_HANDLE_VALUE) {
        handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, 
                           OPEN_EXISTING, 
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    }

    return handle;  // Vrati handle zariadenia alebo INVALID_HANDLE_VALUE
}

/**
 * Priprava zariadenia na sifrovanie
 * 
 * Popis: Vykonava vsetky kroky potrebne na pripravu zariadenia pred
 * sifrovanim alebo desifrovanim dat. Zahŕňa kontrolu opravneni,
 * otvorenie zariadenia, uzamknutie a nastavenie specialnych operacnych modov.
 * 
 * Proces:
 * 1. Kontrola, ci proces bezi s administratorskymi pravami
 * 2. Zobrazenie informacie o pripravovanom zariadeni
 * 3. Otvorenie zariadenia pomocou open_device_with_retry
 * 4. Uzamknutie a odpojenie volumnu
 * 5. Povolenie rozsirenych DASD (Direct Access Storage Device) operacii
 * 
 * Parametre:
 * @param path - Cesta k zariadeniu
 * @param handle - Pointer na handle, kam sa ulozi handle otvoreneho zariadenia
 * 
 * Navratova hodnota:
 * @return true pri uspesnej priprave zariadenia, false pri zlyhani
 * 
 * Bezpecnostne aspekty:
 * - Vyzaduje administratorske opravnenia
 * - Pred sifrovanim/desifrovanim musia byt volumny odpojene
 * - FSCTL_ALLOW_EXTENDED_DASD_IO umoznuje pristup k specialnym sektorom
 */
bool prepare_device_for_encryption(const char *path, HANDLE *handle) {
    // Kontrola administratorskych opravneni
    if (!is_admin()) {
        fprintf(stderr, "Chyba: Vyzaduju sa administratorske opravnenia\n");
        return false;
    }

    // Kontrola a zobrazenie informacie o pripravovanom zariadeni
    check_volume(path);
    
    // Otvorenie zariadenia
    *handle = open_device_with_retry(path);

    // Kontrola uspesneho otvorenia
    if (*handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Zlyhalo otvorenie zariadenia: %lu\n", GetLastError());
        return false;
    }

    // Uzamknutie a odpojenie volumnu
    lock_and_dismount_volume(*handle);

    // Povolenie rozsirenych DASD operacii
    DWORD bytesReturned;
    DeviceIoControl(*handle, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &bytesReturned, NULL);

    return true;  // Uspesna priprava zariadenia
}

/**
 * Nastavenie pozicie suboru/zariadenia
 * 
 * Popis: Nastavi aktualnu poziciu ukazovatela v otvorenom subore
 * alebo zariadeni. Pouziva sa pred operaciami citania/zapisu na
 * specificke miesto.
 * 
 * Proces:
 * 1. Nastavenie pozicie pomocou SetFilePointerEx s flagom FILE_BEGIN
 * 
 * Parametre:
 * @param handle - Handle otvoreneho zariadenia/suboru
 * @param position - Absolutna pozicia v bajtoch
 * 
 * Navratova hodnota:
 * @return TRUE pri uspesnom nastaveni pozicie, FALSE pri zlyhani
 * 
 * Poznamka: Pouziva LARGE_INTEGER pre podporu velkych zariadeni nad 4GB
 */
BOOL set_file_position(HANDLE handle, LARGE_INTEGER position) {
    // Nastavenie absolutnej pozicie v subore/zariadeni
    return SetFilePointerEx(handle, position, NULL, FILE_BEGIN);
}

/**
 * Vypis Windows chybovej spravy
 * 
 * Popis: Ziska a zobrazi podrobnu chybovu spravu zo systemu Windows
 * na zaklade kodu poslednej chyby. Pouziva sa pre lepsiu diagnostiku
 * problemov s pristupom k zariadeniam.
 * 
 * Proces:
 * 1. Ziskanie kodu poslednej chyby pomocou GetLastError()
 * 2. Konverzia kodu na citatelnu spravu pomocou FormatMessageA
 * 3. Vypis formatovanej spravy na stderr
 * 
 * Parametre:
 * @param message - Prefix spravy pre identifikaciu miesta chyby
 * 
 * Vystup:
 * - Vypise chybovu spravu na stderr v formate: prefix: (kod) popis_chyby
 */
void report_windows_error(const char *message) {
    char error_message[ERROR_BUFFER_SIZE] = {0};
    DWORD error_code = GetLastError();

    // Ziskanie textovej reprezentacie chyboveho kodu
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                 NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
                 error_message, ERROR_BUFFER_SIZE, NULL);
                 
    // Vypis chybovej spravy
    fprintf(stderr, "%s: (%lu) %s\n", message, error_code, error_message);
}

#endif

/**
 * Platformovo nezavisly vypis chybovej spravy
 * 
 * Popis: Zobrazi chybovu spravu v zavislosti od operacneho systemu,
 * na ktorom program bezi. Na Windows pouziva GetLastError(), na Linuxe
 * strerror() alebo perror().
 * 
 * Proces:
 * 1. Windows implementacia: Pouzije GetLastError() pre kod chyby
 * 2. Linux implementacia: 
 *    - Ak je poskytnuty kod chyby, pouzije strerror() 
 *    - Inak pouzije perror() s kontextom aktualne nastavenej systemovej chyby
 * 
 * Parametre:
 * @param message - Popis kontextu, kde chyba nastala
 * @param error_code - Kod chyby (pouziva sa len v Linuxe)
 * 
 * Vystup:
 * - Vypise formatovanu chybovu spravu na stderr
 */
void report_error(const char *message, int error_code) {
    #ifdef _WIN32
    // Windows implementacia - ignorujeme error_code a pouzijeme GetLastError()
    (void)error_code;  // Potlacenie varovania o nepouzitej premennej
    fprintf(stderr, "%s: %lu\n", message, GetLastError());
    #else
    // Linux implementacia
    if (error_code) {
        // Ak bol poskytnuty specificky kod chyby
        fprintf(stderr, "%s: %s\n", message, strerror(error_code));
    } else {
        // Pouzitie aktualne nastaveneho kodu chyby
        perror(message);
    }
    #endif
}

/**
 * Ziskanie potvrdenia od pouzivatela
 * 
 * Popis: Zobrazi varovanie pouzivatela o nevratnej operacii 
 * sifrovania a vyzve ho na potvrdenie pokracovania. Pouziva sa
 * pred zacatim operacie, ktora bude modifikovat data na zariadeni.
 * 
 * Proces:
 * 1. Zobrazenie varovania s informaciami o operacii
 * 2. Vyzva na zadanie potvrdenia (a/n)
 * 3. Nacitanie a spracovanie odpovede
 * 4. Vycistenie vstupu
 * 
 * Parametre:
 * @param device_path - Cesta k zariadeniu, ktore bude modifikovane
 * @param key_bits - Velkost sifrovacieho kluca v bitoch
 * 
 * Navratova hodnota:
 * @return true ak pouzivatel potvrdil operaciu, false ak ju odmietol
 *         alebo nastala chyba pri citani vstupu
 * 
 * Bezpecnostne aspekty:
 * - Explicitne upozornenie pred nevratnou operaciou
 * - Vyzaduje aktivnu akciu pouzivatela pre potvrdenie
 */
bool process_user_confirmation(const char *device_path, int key_bits) {
    // Zobrazenie varovania
    printf("UPOZORNENIE: Vsetky data na zariadeni %s budu zasifrovane s %d-bitovym klucom!\n", 
           device_path, key_bits);
    
    // Vyzva na zadanie potvrdenia
    printf("Chcete pokracovat? (a/n): ");
    
    // Nacitanie odpovede
    char confirm;
    if (scanf(" %c", &confirm) != 1) {
        fprintf(stderr, "Chyba pri citani potvrdenia\n");
        return false;
    }
    
    // Vycistenie zvysnych znakov vstupneho buffra
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    // Vyhodnotenie odpovede (a/A/y/Y = suhlasim)
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
 * 1. Pri sifrovani zobrazi bezpecnostne odporucania pre vytvorenie silneho hesla
 * 2. Vyzve uzivatela na zadanie hesla (bez zobrazenia na obrazovke)
 * 3. Pri sifrovani v pripade kratkeho hesla zobrazi varovanie, ale pokracuje
 * 4. V pripade potreby vyzada potvrdenie hesla a porovna obidve hesla
 *
 * Parametre:
 * @param password - Buffer pre ulozenie zadaneho hesla
 * @param password_size - Velkost buffera pre heslo
 * @param verify - Priznak, ci sa ma vyzadovat potvrdenie hesla (1 = ano, 0 = nie)
 *                 a zaroven ci ide o sifrovanie (1) alebo desifrovanie (0)
 *
 * Navratova hodnota:
 * @return true ak bolo heslo uspesne zadane a potvrdene (ak sa vyzadovalo),
 *         false ak zadanie zlyhalo alebo hesla sa nezhoduju
 *
 * Bezpecnostne poznamky:
 * - Heslo zostava v pamati po volani, potrebne vycistit secure_clear_memory()
 * - Upozornuje na rizika slabych hesiel, ale neobmedzuje vstup podla kriterii
 */
bool process_password_input(uint8_t *password, size_t password_size, int verify) {
    // Bezpecnostne odporucania zobrazi len pri sifrovani (verify == 1)
    if (verify) {
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
    }
    
    read_password(password, password_size, "Zadajte heslo: ");
    
    // Upozornenie na kratke heslo sa zobrazi len pri sifrovani (verify == 1)
    if (verify && strlen((char*)password) < MIN_PASSWORD_LENGTH) {
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

/**
 * Vytvorenie verifikacnych dat na overenie spravnosti hesla
 * 
 * Popis: Vytvara kryptograficky hash z kluca a soli, ktory sluzi na overenie
 * spravnosti zadaneho hesla pri desifrovani bez potreby znalostt povodneho hesla.
 * Pouziva HMAC-SHA256 na vytvorenie verifikacnych dat.
 * 
 * Proces:
 * 1. Inicializacia HMAC algoritmu s klavesom a SHA256 digestom
 * 2. Update HMAC kontextu s konstantnym retazcom pre verifikaciu
 * 3. Update HMAC kontextu s hodnotou soli
 * 4. Finalizacia a ziskanie vystupneho hash kodu
 * 5. Uvolnenie HMAC kontextu a zdrojov
 * 
 * Parametre:
 * @param key - Sifrovaci kluc (prva polovica spojeneho kluca)
 * @param key_bits - Velkost kluca v bitoch (128 alebo 256)
 * @param salt - Sol pouzita pri derivacii kluca
 * @param verification_data - Buffer pre ulozenie vystupnych verifikacnych dat
 * 
 * Bezpecnostne aspekty:
 * - Verifikacne data umoznuju overenie spravnosti hesla bez desifrovaniat
 * - Nemozno z nich spatne ziskat povodne heslo
 * - Zachovavaju forward secrecy aj pri znalosti hlavicky
 */
void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data) {
    const char *verify_str = "AES-XTS-VERIFY";
    size_t hmac_key_len = key_bits / BITS_PER_BYTE;
    
    // Inicializacia HMAC algoritmu
    EVP_MAC *hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac) {
        print_openssl_error();
        return;
    }
    
    // Vytvorenie HMAC kontextu
    EVP_MAC_CTX *hmac_ctx = EVP_MAC_CTX_new(hmac);
    if (!hmac_ctx) {
        EVP_MAC_free(hmac);
        print_openssl_error();
        return;
    }
    
    // Nastavenie SHA256 digestu ako parametra pre HMAC
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    
    // Vypocet HMAC z kluca, konstantneho retazca a soli
    if (EVP_MAC_init(hmac_ctx, key, hmac_key_len, params) &&
        EVP_MAC_update(hmac_ctx, (uint8_t *)verify_str, strlen(verify_str)) &&
        EVP_MAC_update(hmac_ctx, salt, SALT_SIZE)) {
        
        // Ziskanie vysledneho HMAC
        size_t out_len = VERIFICATION_DATA_SIZE;
        EVP_MAC_final(hmac_ctx, verification_data, &out_len, VERIFICATION_DATA_SIZE);
    } else {
        print_openssl_error();
    }
    
    // Uvolnenie HMAC zdrojov
    EVP_MAC_CTX_free(hmac_ctx);
    EVP_MAC_free(hmac);
}

/**
 * Kontrola ci je oddiel pripojeny v systeme
 * 
 * Popis: Overuje, ci zadany diskovy oddiel nie je momentalne pripojeny (mounted)
 * v systeme, aby sa predislo poskodeniu dat pri sifrovani/desifrovani.
 * Funkcia je specificka pre Linux.
 * 
 * Proces:
 * 1. Otvorenie suboru /proc/mounts obsahujuceho zoznam pripojenych zariadeni
 * 2. Citanie suboru po riadkoch a hladanie zadanej cesty zariadenia
 * 3. Zatvorenie suboru a vratenie informacie, ci bolo zariadenie najdene
 * 
 * Parametre:
 * @param device_path - Cesta k zariadeniu, ktore sa overuje
 * 
 * Navratova hodnota:
 * @return true ak je zariadenie pripojene, false ak nie je
 * 
 * Bezpecnostne aspekty:
 * - Kriticky test pre zabranenie poskodenia dat
 * - V pripade zlyhania je bezpecnejsie predpokladat, ze zariadenie je pripojene
 */
#ifndef _WIN32
bool is_partition_mounted(const char *device_path) {
    // Otvorenie suboru so zoznamom pripojenych zariadeni
    FILE *mtab = fopen("/proc/mounts", "r");
    if (!mtab) return false;

    char line[ERROR_BUFFER_SIZE];
    bool mounted = false;

    // Hladanie zariadenia v zozname pripojenych zariadeni
    while (fgets(line, sizeof(line), mtab) && !mounted) {
        mounted = strstr(line, device_path) != NULL;
    }

    // Zatvorenie suboru so zoznamom
    fclose(mtab);
    return mounted;
}

/**
 * Ziskanie velkosti diskoveho oddielu
 * 
 * Popis: Ziskava celkovu velkost diskoveho oddielu v bajtoch pomocou
 * ioctl volania specifickeho pre Linux. Tato velkost je potrebna pre
 * spravne obmedzenie operacii citania/zapisu na zariadenie.
 * 
 * Proces:
 * 1. Volanie ioctl s BLKGETSIZE64 parametrom pre ziskanie velkosti v bajtoch
 * 2. Kontrola vysledku volania ioctl
 * 3. Vratenie veľkosti alebo 0 v pripade chyby
 * 
 * Parametre:
 * @param fd - File descriptor otvoreneho diskoveho oddielu
 * 
 * Navratova hodnota:
 * @return velkost diskoveho oddielu v bajtoch alebo 0 v pripade chyby
 */
uint64_t get_partition_size(int fd) {
    uint64_t size = 0;

    // Ziskanie velkosti pomocou ioctl volania BLKGETSIZE64
    if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
        perror("Chyba pri zistovani velkosti oddielu");
        return 0;
    }

    return size;
}
#endif

/**
 * Spracovanie a validacia argumentov prikazoveho riadka
 * 
 * Popis: Analyzuje argumenty prikazoveho riadka a extrahuje z nich
 * operaciu (sifrovanie/desifrovanie), cestu k zariadeniu a velkost kluca.
 * V pripade nedostatocnych alebo neplatnych argumentov zobrazuje napovedu.
 * 
 * Proces:
 * 1. Kontrola minimalneho poctu argumentov
 * 2. Extrahovanie operacie z prveho argumentu
 * 3. Analyza dalsich argumentov (volitelna velkost kluca, cesta k zariadeniu)
 * 4. Zobrazenie chyby alebo napovedy v pripade neuplnych argumentov
 * 
 * Parametre:
 * @param argc - Pocet argumentov prikazoveho riadka
 * @param argv - Pole argumentov prikazoveho riadka
 * @param operation - Pointer pre ulozenie typu operacie (encrypt/decrypt)
 * @param device_path - Pointer pre ulozenie cesty k zariadeniu
 * @param key_bits - Pointer pre ulozenie velkosti kluca v bitoch
 * 
 * Navratova hodnota:
 * @return true ak sa podarilo uspesne spracovat argumenty, false v pripade chyby
 */
bool parse_arguments(int argc, char *argv[], const char **operation, 
                    const char **device_path, int *key_bits) {
    // Kontrola minimalneho poctu argumentov
    if (argc < 3) {
        printf("AES-XTS Nastroj na sifrovanie diskov/oddielov\n");
        printf("=========================================\n\n");
        printf("Pouzitie:\n");
        printf("  %s encrypt [128|256] <zariadenie>\n", argv[0]);
        printf("  %s decrypt [128|256] <zariadenie>\n", argv[0]);
        printf("\nPriklady:\n");
        printf("  %s encrypt 128 /dev/sdb1   # Vyuzitie 128-bitoveho kluca na sifrovanie\n", argv[0]);
        printf("  %s encrypt 256 /dev/sdb1   # Vyuzitie 256-bitoveho kluca na sifrovanie\n", argv[0]);
        printf("  %s encrypt /dev/sdb1       # Bez argumentu sa pouzije 256-bitovy kluc\n", argv[0]);
        printf("  %s decrypt /dev/sdb1       # Pri desifrovani sa dlzka kluca nacita z hlavicky\n", argv[0]);
        return false;
    }

    // Ziskanie typu operacie z prveho argumentu
    *operation = argv[1];
    *device_path = NULL;
    
    // Analyza argumentov pre velkost kluca a cestu k zariadeniu
    if (argc >= 4 && (strcmp(argv[2], "128") == 0 || strcmp(argv[2], "256") == 0)) {
        *key_bits = atoi(argv[2]);
        *device_path = argv[3];
    } else if (argc >= 3) {
        *device_path = argv[2];
    }

    // Kontrola ci bola zadana cesta k zariadeniu
    if (!*device_path) {
        fprintf(stderr, "Chyba: Nie je zadana cesta k zariadeniu\n");
        return false;
    }
    
    return true;
}

/**
 * Sifrovanie diskoveho oddielu
 * 
 * Popis: Hlavna funkcia procesu sifrovania diskoveho oddielu. Riadi cely proces
 * od ziskania hesla od pouzivatela, cez vytvorenie hlavicky az po samotne
 * sifrovanie dat.
 * 
 * Proces:
 * 1. Zobrazenie informacii o velkosti kluca a ziadost o potvrdenie
 * 2. Vyzvanie pouzivatela na zadanie a potvrdenie hesla
 * 3. Alokacia pamate pre sifrovaci kluc
 * 4. Inicializacia hlavicky s metadatami a vygenerovanie nahodnej soli
 * 5. Derivacia kluca z hesla a soli pomocou KDF
 * 6. Vytvorenie verifikacnych dat pre buducu kontrolu spravnosti hesla
 * 7. Zapis hlavicky na disk
 * 8. Spustenie samotneho procesu sifrovania sektorov
 * 9. Bezpecne vymazanie citlivych udajov z pamate
 * 
 * Parametre:
 * @param ctx - Kontext diskoveho zariadenia
 * @param device_path - Cesta k sifrovanemu zariadeniu
 * @param key_bits - Velkost sifrovacieho kluca v bitoch
 * 
 * Navratova hodnota:
 * @return kod vysledku operacie alebo 0 ak operacia bola zrusena pouzivatelom
 * 
 * Bezpecnostne aspekty:
 * - Bezpecne uvolnenie vsetkych citlivych dat (heslo, kluc)
 * - Vykonanie vsetkych operacii so spravnym poradim pre zachovanie bezpecnosti
 */
int encrypt_device(device_context_t *ctx, const char *device_path, int key_bits) {
    uint8_t password[PASSWORD_BUFFER_SIZE] = {0};
    xts_header_t header = {0};
    int result = 0;
    
    // Zobrazenie informacie o pouzitej velkosti kluca
    printf("Pouziva sa %d-bitove sifrovanie\n", key_bits);
    
    // Ziskanie potvrdenia a hesla od pouzivatela
    if (!process_user_confirmation(device_path, key_bits) ||
        !process_password_input(password, sizeof(password), 1)) {
        return 0;
    }

    // Alokacia spojeneho kluca (dvojnasobna velkost pre XTS rezim)
    uint8_t *key = (uint8_t*)malloc(key_bits / BITS_PER_BYTE * 2);
    if (!key) {
        fprintf(stderr, "Chyba: Nedostatok pamate pri alokacii kluca\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    // Inicializacia hlavicky s metadatami sifrovania
    memcpy(header.magic, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    header.version = HEADER_VERSION;
    header.encryption_type = HEADER_ENCRYPTION_TYPE;
    header.start_sector = RESERVED_SECTORS;
    header.iterations = DEFAULT_ITERATIONS;
    header.memory_cost = DEFAULT_MEMORY_COST;
    header.key_bits = key_bits;

    // Vygenerovanie nahodnej soli pre KDF
    if (!RAND_bytes(header.salt, SALT_SIZE)) {
        print_openssl_error();
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }

    // Derivacia kluca z hesla a soli
    if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                               key, key_bits,
                               header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }
    
    // Vytvorenie verifikacnych dat pre kontrolu hesla
    create_verification_data(key, key_bits, header.salt, header.verification_data);
    
    // Zapis hlavicky na zariadenie
    if (header_io(ctx, &header, 1) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }
    
    // Spustenie sifrovania vsetkych sektorov zariadenia
    result = process_sectors(ctx, key, header.start_sector, ENCRYPT_MODE, key_bits);
    
    // Bezpecne vymazanie hesla a kluca z pamate
    secure_clear_memory(password, sizeof(password), false);
    secure_clear_memory(key, key_bits / BITS_PER_BYTE * 2, true);
    
    return result;
}

/**
 * Desifrovanie diskoveho oddielu
 * 
 * Popis: Hlavna funkcia procesu desifrovaniat diskoveho oddielu. Riadi cely
 * proces od nacitania hlavicky, cez overenie spravnosti hesla az po samotne
 * desifrovanie dat.
 * 
 * Proces:
 * 1. Nacitanie a overenie hlavicky zo zariadenia
 * 2. Vyzvanie pouzivatela na zadanie hesla
 * 3. Alokacia pamate pre desifraci kluc
 * 4. Derivacia kluca z hesla a soli z hlavicky
 * 5. Vytvorenie a porovnanie verifikacnych dat na kontrolu spravnosti hesla
 * 6. V pripade spravneho hesla spustenie procesu desifrovaniat sektorov
 * 7. Bezpecne vymazanie citlivych udajov z pamate
 * 
 * Parametre:
 * @param ctx - Kontext diskoveho zariadenia
 * 
 * Navratova hodnota:
 * @return kod vysledku operacie, 0 ak operacia bola zrusena pouzivatelom
 *         alebo AES_XTS_ERROR_WRONG_PWD pri nespravnom hesle
 * 
 * Bezpecnostne aspekty:
 * - Bezpecne uvolnenie vsetkych citlivych dat (heslo, kluc)
 * - Overenie spravnosti hesla pred zacatim desifrovaniat
 * - Prevzatie vsetkych parametrov z ulozenej hlavicky (backward kompatibilita)
 */
int decrypt_device(device_context_t *ctx) {
    uint8_t password[PASSWORD_BUFFER_SIZE] = {0};
    xts_header_t header = {0};
    int result = 0;
    
    // Nacitanie hlavicky zo zariadenia
    if (header_io(ctx, &header, 0) != AES_XTS_SUCCESS) {
        fprintf(stderr, "Neplatna alebo poskodena hlavicka\n");
        return 0;
    }
    
    // Ziskanie hesla od pouzivatela
    if (!process_password_input(password, sizeof(password), 0)) {
        return 0;
    }

    // Zobrazenie informacie o pouzitej velkosti kluca
    printf("Pouziva sa %d-bitove sifrovanie\n", header.key_bits);

    // Alokacia spojeneho kluca s velkostou podla nacitanej hlavicky
    uint8_t *key = (uint8_t*)malloc(header.key_bits / BITS_PER_BYTE * 2);
    if (!key) {
        fprintf(stderr, "Chyba: Nedostatok pamate pri alokacii kluca\n");
        return AES_XTS_ERROR_MEMORY;
    }
    
    // Derivacia kluca z hesla a soli z hlavicky
    if (derive_keys_from_password(password, header.salt, SALT_SIZE,
                               key, header.key_bits, 
                               header.iterations, header.memory_cost) != AES_XTS_SUCCESS) {
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
        return 0;
    }

    // Vytvorenie verifikacnych dat pre kontrolu spravnosti hesla
    uint8_t verification_check[VERIFICATION_DATA_SIZE];
    create_verification_data(key, header.key_bits, header.salt, verification_check);

    // Porovnanie vytvorenych verifikacnych dat s datami z hlavicky
    if (memcmp(verification_check, header.verification_data, VERIFICATION_DATA_SIZE) != 0) {
        fprintf(stderr, "Chyba: Neplatne heslo alebo poskodene data\n");
        secure_clear_memory(password, sizeof(password), false);
        secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
        return AES_XTS_ERROR_WRONG_PWD;
    }

    // Spustenie procesu desifrovaniat vsetkych sektorov
    result = process_sectors(ctx, key, header.start_sector, DECRYPT_MODE, header.key_bits);
    
    // Bezpecne vymazanie hesla a kluca z pamate
    secure_clear_memory(password, sizeof(password), false);
    secure_clear_memory(key, header.key_bits / BITS_PER_BYTE * 2, true);
    
    return result;
}

/**
 * Hlavna funkcia programu
 * 
 * Popis: Vstupny bod programu, ktory spracovava argumenty prikazoveho
 * riadka, inicializuje prostredie OpenSSL, otvara zariadenie a spusta
 * pozadovanu operaciu (sifrovanie/desifrovanie).
 * 
 * Proces:
 * 1. Spracovanie argumentov prikazoveho riadka
 * 2. Inicializacia kryptografickeho prostredia OpenSSL
 * 3. Otvorenie zariadenia pomocou OS-specifickych funkcii
 * 4. Spustenie pozadovanej operacie (sifrovanie alebo desifrovanie)
 * 5. Zatvorenie zariadenia a uvolnenie zdrojov
 * 6. Uvolnenie kryptografickeho prostredia
 * 7. Zobrazenie vysledku operacie a ukoncenie programu
 * 
 * Parametre:
 * @param argc - Pocet argumentov prikazoveho riadka
 * @param argv - Pole argumentov prikazoveho riadka
 * 
 * Navratova hodnota:
 * @return EXIT_SUCCESS pri uspesnom dokonceni operacie,
 *         EXIT_FAILURE pri chybe
 */
int main(int argc, char *argv[]) {
    const char *operation = NULL;
    const char *device_path = NULL;
    int key_bits = DEFAULT_KEY_BITS;
    int result = AES_XTS_ERROR_PARAM; 
    
    // Spracovanie argumentov prikazoveho riadka
    if (!parse_arguments(argc, argv, &operation, &device_path, &key_bits)) {
        return EXIT_FAILURE;
    }
    
    // Inicializacia kryptografickeho prostredia OpenSSL
    aes_xts_init();
    
    // Otvorenie zariadenia pre operacie citania/zapisu
    device_context_t ctx = {0};
    if (!open_device(device_path, &ctx)) {
        fprintf(stderr, "Chyba: Nepodarilo sa otvorit zariadenie %s\n", device_path);
        aes_xts_cleanup();
        return EXIT_FAILURE;
    }
    
    // Spustenie pozadovanej operacie (sifrovanie/desifrovanie)
    if (strcmp(operation, "encrypt") == 0) {
        result = encrypt_device(&ctx, device_path, key_bits);
    } else if (strcmp(operation, "decrypt") == 0) {
        result = decrypt_device(&ctx);
    } else {
        fprintf(stderr, "Neznamy prikaz: %s\n", operation);
        result = AES_XTS_ERROR_PARAM;
    }
    
    // Zatvorenie zariadenia a uvolnenie zdrojov
    close_device(&ctx);
    aes_xts_cleanup();
    
    // Zobrazenie vysledku operacie
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