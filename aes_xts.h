/************************************************************************
 * Nazov projektu: AES-XTS sifrovanie a desifrovanie diskov pomocou OpenSSL
 * ----------------------------------------------------------------------------
 * Subor: aes_xts.h 
 * Verzia: 2.1 
 * Datum: 25.3.2025
 *
 * Autor: Kamil Berecky
 * 
 * Popis: Hlavickovy subor pre implementaciu AES-XTS sifrovania a
 * desifovania diskov. Obsahuje deklaracie funkcii, struktury, konstanty
 * a typy potrebne pre implementaciu sifrovania diskov pomocou algoritmu
 * AES-XTS. Poskytuje platformovo nezavisle rozhranie pre manipulaciu
 * s diskovymi zariadeniami.
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
#ifndef AES_XTS_H
#define AES_XTS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>     // OpenSSL EVP API pre algoritmy sifrovania
#include <openssl/rand.h>    // OpenSSL funkcie pre generovanie nahodnych dat
#include <openssl/err.h>     // OpenSSL chybove kody a spravy
#include <openssl/kdf.h>     // OpenSSL KDF pre derivaciu klucov
#include <openssl/crypto.h>  // Zakladne kryptograficke funkcie OpenSSL
#include <ctype.h>
#include <stdbool.h>
#include <omp.h>             // OpenMP pre paralelizaciu vypoctu

// Platformovo specificke hlavickove subory
#ifdef _WIN32
    #include <windows.h>     // Zakladne Windows API
    #include <time.h>   
    #include <conio.h>       // Pre _getch() - bezpecne citanie hesiel
    #include <winioctl.h>    // Windows zariadenia, IOCTL volania
#else
    #include <unistd.h>      // POSIX API
    #include <fcntl.h>       // File control operacie
    #include <sys/ioctl.h>   // IOCTL volania v Linuxe
    #include <linux/fs.h>    // Linux file system specificke deklaracie
    #include <termios.h>     // Pre terminaly a ovladanie konzoly
    #include <sys/stat.h>    // File status funkcie
    #include <linux/hdreg.h> // Hard disk specificke IOCTL volania
    #include <dirent.h>      // Pre manipulaciu s adresarmi
#endif

/* ========== Navratove kody funkcii ========== */
#define AES_XTS_SUCCESS            0   // Uspesne vykonanie operacie
#define AES_XTS_ERROR_OPENSSL     -1   // Chyba v OpenSSL kniznici
#define AES_XTS_ERROR_IO          -2   // Chyba pri vstupno/vystupnych operaciach
#define AES_XTS_ERROR_PARAM       -3   // Neplatny parameter funkcie
#define AES_XTS_ERROR_MEMORY      -4   // Nedostatok pamate
#define AES_XTS_ERROR_PERMISSION  -5   // Nedostatocne opravnenia
#define AES_XTS_ERROR_WRONG_PWD   -6   // Nespravne heslo

/* ========== Velkosti bufferov a konstant ========== */
#define BUFFER_SIZE               (8 * 1024 * 1024)  /* 8 MB - velkost hlavneho buffra pre prenos dat */
#define SECTOR_SIZE               4096               /* Velkost jedneho sektora, pouziva sa na zarovnanie */
#define ERROR_BUFFER_SIZE         1024               /* Velkost buffra pre chybove spravy */
#define PASSWORD_BUFFER_SIZE      128                /* Maximalny pocet znakov hesla */
#define RESERVED_SECTORS          64                 /* Pocet rezervovanych sektorov pre metadata */

/* ========== Kryptograficke konstanty ========== */
#define SALT_SIZE                 16                 /* Velkost soli v bajtoch */
#define IV_SIZE                   16                 /* Velkost inicializacneho vektora */
#define VERIFICATION_DATA_SIZE    32                 /* Velkost verifikacnych dat pre kontrolu hesla */
#define BITS_PER_BYTE             8                  /* Pocet bitov v bajte */
#define DEFAULT_KEY_BITS          256                /* Predvolena velkost kluca v bitoch (moze byt 128 alebo 256) */
#define ENCRYPT_MODE              1                  /* Oznacenie rezimu sifrovania */
#define DECRYPT_MODE              0                  /* Oznacenie rezimu desifovania */

/* ========== Konstanty pre hlavicku ========== */
#define HEADER_MAGIC              "AESXTS"           /* Magicky retazec pre identifikaciu hlavicky */
#define HEADER_MAGIC_SIZE         6                  /* Velkost magickeho retazca */
#define HEADER_VERSION            1                  /* Verzia formatu hlavicky */
#define HEADER_SECTOR             62                 /* Cislo sektora kde je ulozena hlavicka */
#define HEADER_ENCRYPTION_TYPE    1                  /* Typ sifrovania (1 = AES-XTS) */

/* ========== Parametre pre KDF (Key Derivation Function) ========== */
#define DEFAULT_ITERATIONS        10                 /* Pocet iteracii pre Argon2id */
#define DEFAULT_MEMORY_COST       65536              /* Pamatova narocnost Argon2id v KB */
#define DEFAULT_PARALLELISM       4                  /* Pocet vlakien pre Argon2id */
#define MIN_PASSWORD_LENGTH       8                  /* Minimalna dlzka hesla */

/* ========== Zobrazenie postupu ========== */
#define PROGRESS_UPDATE_INTERVAL  10000              /* Ako casto aktualizovat zobrazenie postupu (v sektoroch) */
#define BYTES_PER_MB              (1024 * 1024)      /* Pocet bajtov v 1 MB */
#define SLEEP_MS                  10                 /* Pauza medzi aktualizaciami zobrazenia v ms */

/* ========== Platformovo specificke konstanty ========== */
#ifdef _WIN32
// Format pre zobrazenie postupu vo Windows - pouziva %llu pre 64-bit cisla
#define PROGRESS_FORMAT           "Priebeh: %.1f%% (%llu/%llu MB)\r"
// Funkcia pre pauzu vo Windows
#define SLEEP_FUNCTION            Sleep(SLEEP_MS)
#else
// Format pre zobrazenie postupu v Linuxe - pouziva %lu pre 64-bit cisla
#define PROGRESS_FORMAT           "Priebeh: %.1f%% (%lu/%lu MB)\r"
// Funkcia pre pauzu v Linuxe
#define SLEEP_FUNCTION            usleep(SLEEP_MS * 1000)
#endif

/**
 * Typ zariadenia - rozlisuje medzi fyzickym diskom a logickym oddielom
 * Pouziva sa len vo Windows implementacii pre spravne IOCTL volania
 */
typedef enum {
    DEVICE_TYPE_UNKNOWN,    // Neznamy typ zariadenia
    DEVICE_TYPE_DISK,       // Fyzicky disk (napr. \\\\.\\PhysicalDrive0)
    DEVICE_TYPE_VOLUME      // Logicky oddiel (napr. \\\\.\\C:)
} device_type_t;

/**
 * Struktura pre metadatovu hlavicku sifrovaneho oddielu
 * Obsahuje vsetky potrebne udaje pre desifrovanie, okrem samotneho hesla
 */
#pragma pack(push, 1)  // Zarovnanie 1-bajt - dolezite pre spravnu velkost struktury
typedef struct {
    char magic[6];                   // Identifikator "AESXTS" 
    uint8_t version;                 // Verzia formatu hlavicky
    uint8_t encryption_type;         // Typ sifrovania (1 = AES-XTS)
    uint32_t start_sector;           // Od ktoreho sektora zacinaju sifrovane data 
    uint32_t iterations;             // Pocet iteracii pre KDF
    uint32_t memory_cost;            // Pamatova narocnost pre KDF v KB
    uint32_t key_bits;               // Velkost kluca v bitoch (128 alebo 256)
    uint8_t salt[SALT_SIZE];         // Sol pouzita pri derivacii kluca
    uint8_t verification_data[32];   // Data pre overenie spravnosti hesla 
    uint8_t padding[0];              // Zarovnanie na velkost sektora (desatruktor v case kompilacie)
} xts_header_t;
#pragma pack(pop)  // Obnovenie povodneho zarovnania

/**
 * Kontext zariadenia - obsahuje vsetky potrebne informacie pre manipulaciu so zariadenim
 * Ma rozne cleny v zavislosti od operacneho systemu
 */
typedef struct {
    #ifdef _WIN32
    HANDLE handle;            // Handle na otvorene zariadenie vo Windows
    LARGE_INTEGER size;       // Velkost zariadenia v bajtoch
    device_type_t type;       // Typ zariadenia (disk/oddiel)
    char path[MAX_PATH];      // Cesta k zariadeniu
    #else
    int fd;                   // File descriptor otvoreneho zariadenia v Linuxe
    uint64_t size;            // Velkost zariadenia v bajtoch
    #endif
} device_context_t;

/* ========== Deklaracie funkcii ========== */

/**
 * Inicializacia OpenSSL kniznice, musi sa volat pred pouzitim kryptografickych funkcii
 */
void aes_xts_init(void);

/**
 * Uvolnenie zdrojov OpenSSL kniznice, musi sa volat pred ukoncenim programu
 */
void aes_xts_cleanup(void);

/**
 * Vypis poslednej OpenSSL chyby na stderr
 */
void print_openssl_error(void);

/**
 * Sifrovanie alebo desifrovanie jedneho sektora dat pomocou AES-XTS
 */
int32_t aes_xts_crypt_sector(
    const uint8_t *key,      // Spojeny kluc (dvojnasobnej velkosti pre XTS rezim)
    uint64_t sector_num,     // Cislo sektora (pouzite ako tweak)
    uint8_t *data,           // Buffer s datami na sifrovanie/desifrovanie
    size_t data_len,         // Velkost dat v buffri
    int encrypt,             // 1 = sifrovanie, 0 = desifrovanie
    int key_bits             // Velkost kluca v bitoch (128 alebo 256)
);

/**
 * Derivacia kluca z hesla pomocou Argon2id KDF
 */
int derive_keys_from_password(
    const uint8_t *password,  // Heslo zadane pouzivatelom
    const uint8_t *salt,      // Nahodna sol
    size_t salt_len,          // Velkost soli
    uint8_t *key,             // Vystupny buffer pre derivovany kluc
    int key_bits,             // Velkost kluca v bitoch
    uint32_t iterations,      // Pocet iteracii Argon2id
    uint32_t memory_cost      // Pamatova narocnost v KB
);

/**
 * Bezpecne nacitanie hesla od pouzivatela bez zobrazovania znakov
 */
void read_password(uint8_t *password, size_t max_len, const char *prompt);

/**
 * Zobrazenie varovania a ziskanie potvrdenia od pouzivatela pred sifrovanim
 */
bool process_user_confirmation(const char *device_path, int key_bits);

/**
 * Spracovanie zadania hesla s volitelnym overovanim (pre sifrovanie)
 */
bool process_password_input(uint8_t *password, size_t password_size, int verify);

/**
 * Otvorenie diskoveho zariadenia pre citanie a zapis
 */
bool open_device(const char *path, device_context_t *ctx);

/**
 * Zatvorenie diskoveho zariadenia a uvolnenie zdrojov
 */
void close_device(device_context_t *ctx);

/**
 * Spracovanie (sifrovanie/desifrovanie) vsetkych sektorov zariadenia
 */
int process_sectors(
    device_context_t *ctx,    // Kontext zariadenia
    uint8_t *key,             // Kluc pre sifrovanie/desifrovanie
    uint64_t start_sector,    // Od ktoreho sektora zacat
    int encrypt,              // 1 = sifrovanie, 0 = desifrovanie
    int key_bits              // Velkost kluca v bitoch
);

/**
 * Vytvorenie verifikacnych dat na overenie spravnosti hesla
 */
void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data);

/**
 * Alokacia pamatoveho buffera zarovnaneho na velkost sektora
 */
uint8_t* allocate_aligned_buffer(size_t size);

/**
 * Bezpecne vymazanie senzitivnych dat z pamate s volitelnym uvolnenim
 */
void secure_clear_memory(void *buffer, size_t size, bool free_memory);

/**
 * Operacie s metadatovou hlavickou zariadenia (citanie/zapis)
 */
int header_io(device_context_t *ctx, xts_header_t *header, int isWrite);

/**
 * Vypis chybovej spravy v platformovo nezavislom formate
 */
void report_error(const char *message, int error_code);

/**
 * Proces sifrovania celeho zariadenia
 */
int encrypt_device(device_context_t *ctx, const char *device_path, int key_bits);

/**
 * Proces desifovania celeho zariadenia
 */
int decrypt_device(device_context_t *ctx);

/**
 * Spracovanie argumentov prikazoveho riadka
 */
bool parse_arguments(int argc, char *argv[], const char **operation, 
    const char **device_path, int *key_bits);

/**
 * Nastavenie pozicie v zariadeni pre nasledne citanie/zapis
 */
bool set_position(device_context_t *ctx, uint64_t position);

/**
 * Platformovo nezavisle citanie dat zo zariadenia
 */
ssize_t read_data(device_context_t *ctx, void *buffer, size_t size);

/**
 * Platformovo nezavisly zapis dat na zariadenie
 */
ssize_t write_data(device_context_t *ctx, const void *buffer, size_t size);

/* ========== Windows-specificke funkcie ========== */
#ifdef _WIN32
/**
 * Kontrola ci proces bezi s administratorskymi opravneniami
 */
BOOL is_admin(void);

/**
 * Nastavenie pozicie v subore/zariadeni (Windows specificka implementacia)
 */
BOOL set_file_position(HANDLE handle, LARGE_INTEGER position);

/**
 * Odomknutie predtym zamknuteho disku
 */
void unlock_disk(HANDLE hDevice);

/**
 * Urcenie typu zariadenia podla cesty
 */
device_type_t get_device_type(const char *path);

/**
 * Priprava zariadenia na sifrovanie (uzamknutie, odpojenie)
 */
bool prepare_device_for_encryption(const char *path, HANDLE *handle);

/**
 * Zistenie velkosti zariadenia v bajtoch
 */
LARGE_INTEGER get_device_size(HANDLE hDevice, device_type_t deviceType);

/**
 * Kontrola a zobrazenie informacie o pristupe k Windows jednotke
 */
void check_volume(const char *path);

/* ========== Linux-specificke funkcie ========== */
#else
/**
 * Kontrola ci je oddiel momentalne pripojeny v systeme
 */
bool is_partition_mounted(const char *device_path);

/**
 * Zistenie velkosti oddielu pomocou ioctl
 */
uint64_t get_partition_size(int fd);

#endif

#endif /* AES_XTS_H */