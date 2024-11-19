//aes_xts.h

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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <locale.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

// Konštanty pre nastavenie šifrovania
#define BUFFER_SIZE 4096            // Veľkosť bufferu na šifrovanie a dešifrovanie
#define AES_KEY_LENGTH 32           // Dĺžka kľúča pre AES-256-XTS (2 x 128-bitové kľúče)
#define SALT_LENGTH 16              // Dĺžka salt hodnoty pre odvodenie kľúča
#define MAX_LINE_LENGTH 2048        // Maximálna dĺžka riadku pri načítaní testovacích vektorov

// Štruktúra na ukladanie testovacích vektorov
typedef struct {
    unsigned char key1[16];         // Prvý 128-bitový kľúč
    unsigned char key2[16];         // Druhý 128-bitový kľúč
    unsigned char ducn[16];         // 128-bitová tweak hodnota (DUCN) pre AES-XTS
    unsigned char *plaintext;       // Pole bajtov pre plaintext
    int plaintext_len;              // Dĺžka plaintextu
    unsigned char *ciphertext;      // Pole bajtov pre ciphertext
    int ciphertext_len;             // Dĺžka ciphertextu
} TestVector;

// Prototypy funkcií

// Spracovanie chýb
void handle_errors();

// Konverzia hex reťazca na bajty
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len);

// Odvodenie kľúča z hesla pomocou Argon2id
int derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key);

// Načítanie testovacích vektorov zo súboru
int load_test_vectors(const char *filename, TestVector **vectors, int *count);

// Šifrovanie/dešifrovanie AES-XTS
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak);

// Formátovanie výstupu do hexadecimálneho formátu
void print_hex_output(const char *label, const unsigned char *data, int len);

// Testovanie načítaných vektorov
void test_vectors(TestVector *vectors, int vector_count);

// Zabezpečené zadávanie hesla
void get_password(char *password, size_t len);

// Utility funkcie pre manipuláciu s názvami súborov
char* append_extension(const char *filename, const char *extension);

char* generate_decrypted_filename(const char *filename);

#endif // AES_XTS_H