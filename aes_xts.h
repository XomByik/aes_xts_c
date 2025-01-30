// aes_xts.h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef AES_XTS_H
#define AES_XTS_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/thread.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <locale.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// Konfiguracne konstanty
#define BUFFER_SIZE 4096        // Velkost bufferu pre sifrovanie/desifrovanie
#define AES_KEY_LENGTH 16       // Dlzka kluca (2x 128-bitovy kluc)
#define SALT_LENGTH 16          // Dlzka hodnoty salt
#define TWEAK_LENGTH 16         // Velkost tweak hodnoty pre XTS mod
#define MAX_LINE_LENGTH 2048    // Maximalna dlzka riadku pre testovacie vektory
#define SECTOR_SIZE 512         // Velkost sektora
#define INITIAL_TWEAK_LENGTH 16 // Dlzka pociatocneho tweaku
#define AES_KEY_LENGTH_128 32   // 2x 128-bit pre XTS-AES-128
#define AES_KEY_LENGTH_256 64   // 2x 256-bit pre XTS-AES-256

// Struktura pre testovacie vektory podla standardu IEEE 1619-2007
typedef struct
{
    unsigned char key1[16];    // Prvy kluc pre sifrovanie dat
    unsigned char key2[16];    // Druhy kluc pre spracovanie tweak hodnoty
    unsigned char ducn[16];    // Data Unit Complex Number (tweak hodnota)
    unsigned char *plaintext;  // Buffer pre nesifrovane data
    int plaintext_len;         // Dlzka nesifrovaneho textu
    unsigned char *ciphertext; // Buffer pre sifrovane data
    int ciphertext_len;        // Dlzka sifrovaneho textu
} TestVector;

// Hlavne kryptograficke funkcie

/**
 * Spracovanie chyb OpenSSL kniznice
 * Vypise chybove hlasky a ukonci program
 */
void handle_errors(void);

/**
 * Konvertuje hexadecimalny retazec na pole bajtov
 *
 * @param hex_str Vstupny hexadecimalny retazec
 * @param bytes Vystupne pole bajtov
 * @param expected_len Ocakavana dlzka vystupu v bajtoch
 * @return Pocet skonvertovanych bajtov alebo -1 pri chybe
 */
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len);

/**
 * Odvodzuje sifrovaci kluc z hesla pomocou funkcie Argon2id
 *
 * @param password Heslo zadane pouzivatelom
 * @param salt Nahodna salt hodnota
 * @param key Vystupny buffer pre kluc (32 bajtov pre AES-128-XTS, 64 bajtov pre AES-256-XTS)
 * @param key_length Pozadovana dlzka kluca v bajtoch (32 pre 128-bit, 64 pre 256-bit)
 * @return 0 pri uspesnom odvodeni, -1 pri chybe
 */
int derive_key_from_password(const char *password, const unsigned char *salt,
                             unsigned char *key, size_t key_length);

/**
 * Sifruje alebo desifruje data pomocou AES-XTS
 *
 * @param ctx Kontext pre sifrovanie/desifrovanie
 * (Konfiguracna struktura sifrovania/desifrovania potrebna pre OpenSSL)
 * @param in Vstupny buffer s datami
 * @param in_len Dlzka vstupnych dat
 * @param out Vystupny buffer pre data
 * @param out_len Dlzka vystupnych dat
 * @param tweak Tweak hodnota pre AES-XTS
 * @return 0 pri uspesnej operacii, -1 pri chybe
 */
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len,
                  unsigned char *out, int *out_len, unsigned char *tweak);

/**
 * Vypocita tweak hodnotu pre sektor
 *
 * @param initial_tweak Inicialna tweak hodnota
 * @param sector_number Cislo sektoru
 * @param output_tweak Vystupna tweak hodnota
 */
void calculate_sector_tweak(const unsigned char *initial_tweak, uint64_t sector_number,
                            unsigned char *output_tweak);

// Funkcie pre pracu s testovacimi vektormi

/**
 * Nacita testovacie vektory zo suboru
 *
 * @param filename Nazov suboru s testovacimi vektormi
 * @param vectors Vystupne pole testovacich vektorov
 * @param count Vystupny pocet vektorov
 * @return 0 pri uspesnom nacitani, -1 pri chybe
 */
int load_test_vectors(const char *filename, TestVector **vectors, int *count);

/**
 * Testuje nacitane vektory pre sifrovanie/desifrovanie
 *
 * @param vectors Pole testovacich vektorov
 * @param vector_count Pocet testovacich vektorov
 */
void test_vectors(TestVector *vectors, int vector_count);

/**
 * Vypise data v hexadecimalnom formate
 *
 * @param label Popisok pre vystup
 * @param data Buffer s datami na vypis
 * @param len Dlzka dat
 */
void print_hex_output(const char *label, const unsigned char *data, int len);

// Pomocne funkcie

/**
 * Bezpecne nacita heslo od pouzivatela
 *
 * @param password Vystupny buffer pre heslo
 * @param len Dlzka vystupneho bufferu
 */
void get_password(char *password, size_t len);

/**
 * Pripoji priponu k nazvu suboru
 *
 * @param filename Povodny nazov suboru
 * @param extension Pripona na pridanie
 * @return Novy nazov suboru s priponou
 */
char *append_extension(const char *filename, const char *extension);

/**
 * Vytvori nazov desifrovaneho suboru
 *
 * @param filename Povodny nazov suboru
 * @return Novy nazov pre desifrovany subor
 */
char *generate_decrypted_filename(const char *filename);

/**
 * Spracuje subor pre sifrovanie alebo desifrovanie
 *
 * @param operation Operacia (sifrovanie/desifrovanie)
 * @param input_filename Nazov vstupneho suboru
 * @param password Heslo pre sifrovanie/desifrovanie
 * @param key_bits Velkost kluca v bitoch (128 alebo 256)
 *                 - 128-bit: potrebuje 32 bajtov (2x 16B kluc)
 *                 - 256-bit: potrebuje 64 bajtov (2x 32B kluc)
 */
void process_file(const char *operation, const char *input_filename,
                  const char *password, int key_bits);

#endif // AES_XTS_H