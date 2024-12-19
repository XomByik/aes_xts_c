# AES-XTS šifrovanie a dešifrovanie súborov s využitím knižnice OpenSSL

## Obsah
1. [Základný prehľad](#základný-prehľad)
2. [Inštalácia](#inštalácia)
3. [Ako to funguje](#ako-to-funguje)
4. [Používanie programu](#používanie-programu)
5. [Technická dokumentácia](#technická-dokumentácia)
6. [Bezpečnostné informácie](#bezpečnostné-informácie)
7. [Odkazy na dokumentáciu](#odkazy-na-dokumentáciu)

## Základný prehľad

Tento program slúži na bezpečné šifrovanie a dešifrovanie súborov. Je vhodný pre:
- Zálohovanie citlivých dokumentov
- Bezpečné ukladanie dát na externé médiá
- Ochranu súborov pred neoprávneným prístupom

### Hlavné výhody
- Využíva moderný šifrovací algoritmus (AES-XTS s podporou 128-bitových a 256-bitových kľúčov)
- Jednoduchý na použitie
- Podporuje súbory akejkoľvek veľkosti
- Funguje na Windows aj Linux systémoch

### Použité technológie

1. **AES-XTS šifrovanie**
   - Využíva 128/256-bitové kľúče pre šifrovanie aj blokové úpravy
   - Celkový 256/512-bitový kľúč rozdelený na dve 128/256-bitové časti
   - Špeciálne navrhnutý režim pre šifrovanie diskov, je však možné ho využiť aj na jednotlivé súbory
   - Odolný voči manipulácii s dátami
   - Veľkosť blokov: 128-bitov
   - Implementovaný pomocou OpenSSL
   - [Viac o AES-XTS](https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS)

2. **Argon2id**
   - Moderný, odporúčaný algoritmus pre deriváciu kľúčov
   - Odolný voči GPU/ASIC útokom
   - 128-bitový salt
   - Generuje 256/512-bitový kľúč
   - Optimalizovaný pre bezpečnosť aj výkon
   - [Podrobnosti o Argon2](https://github.com/P-H-C/phc-winner-argon2)

## Inštalácia

### Windows
1. Nainštalujte Chocolatey:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

2. Nainštalujte OpenSSL:
```powershell
choco install openssl
```

### Linux
Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install openssl
```

## Používanie programu

### Kompilácia programu

#### Automatická kompilácia pomocou Makefile v priečinku s programom
```bash
make
```

### Šifrovanie súborov
```bash
./aes_xts encrypt 128 dokument.pdf obrazok.jpg    # Pre 128-bitové kľúče
./aes_xts encrypt 256 dokument.pdf obrazok.jpg    # Pre 256-bitové kľúče
```
- Vytvorí súbory: dokument.pdf.enc, obrazok.jpg.enc

### Dešifrovanie súborov
```bash
./aes_xts decrypt dokument.pdf.enc obrazok.jpg.enc
```
- Vytvorí súbory: dokument_dec.pdf, obrazok_dec.jpg

### Otestovanie vektorov
```bash
./aes_xts test test_vectors.txt
```
## Ako to funguje

### Proces šifrovania
1. Zadanie vstupných parametrov:
   - Veľkosť kľúča (128 alebo 256 bitov)
   - Názov súboru ktorý chceme zašifrovať
   - Heslo od používateľa
   
2. Príprava hlavičky súboru:
   - Vygenerovanie náhodného 128-bitového salt
   - Vygenerovanie náhodnej 128-bitovej blokovej úpravy
   - Uloženie salt a blokovej úpravy na začiatok súboru

3. Derivácia kľúčov:
   - Z hesla a salt sa pomocou Argon2id vytvorí šifrovací kľúč
   - Pre AES-128-XTS: 256 bitov (2x 128-bitový kľúč)
   - Pre AES-256-XTS: 512 bitov (2x 256-bitový kľúč)
   - Prvá polovica sa použije pre šifrovanie dát
   - Druhá polovica sa použije pre blokové úpravy

4. Spracovanie súboru po sektoroch (4096 bitov):
   - Pre každý sektor sa vypočíta jedinečná bloková úprava
   - Bloková úprava = počiatočná bloková úprava XOR číslo_sektora
   - Číslo sektora je logická pozícia v súbore
   - Šifrovanie dát v sektore pomocou AES-XTS s vypočítanou blokovou úpravou

### Proces dešifrovania
1. Zadanie parametrov:
   - Heslo od používateľa
   - Názov súboru ktorý chceme rozšifrovať
   - Veľkosť kľúča (musí byť rovnaká ako pri šifrovaní)

2. Čítanie hlavičky súboru:
   - Načítanie 128-bitovej soli
   - Načítanie 128-bitovej počiatočnej blokovej úpravy

3. Derivácia rovnakých kľúčov:
   - Použitie rovnakého hesla a načítaného salt
   - Vytvorenie rovnakých kľúčov ako pri šifrovaní

4. Spracovanie súboru po sektoroch:
   - Výpočet blokovej úpravy pre každý sektor rovnakým spôsobom
   - Dešifrovanie dát pomocou AES-XTS s patričnou blokovou úpravou

### Režim XTS a využitie blokových úprav
- XTS (XEX-based tweaked-codebook mode with ciphertext stealing) je špecializovaný
  režim pre šifrovanie úložísk
- Bloková úprava zabezpečuje, že rovnaké dáta na rôznych pozíciách budú zašifrované inak
- Výhody použitia blokových úprav:
  - Ochrana proti útoku preskladaním sektorov
  - Ochrana proti kopírovaniu sektorov
  - Každý sektor má unikátne šifrovanie

### Spracovanie sektorov
- Veľkosť sektora: 512 bajtov (štandardná veľkosť)
- Číslovanie sektorov:
  - Začíname od 0
  - Každý sektor dostáva svoje poradové číslo
- Bloková úprava pre sektor:
  - Kombinácia počiatočnej blokovej úpravy a čísla sektora
  - Zabezpečuje unikátnosť šifrovania pre každý sektor

## Technická dokumentácia

### Implementované funkcie

#### process_file
```c
void process_file(const char *operation, const char *input_filename, const char *password)
```
- **Účel**: Hlavná funkcia pre šifrovanie alebo dešifrovanie súboru
- **Parametre**:
  - operation: "encrypt" alebo "decrypt"
  - input_filename: cesta k vstupnému súboru
  - password: používateľské heslo
- **Proces**:
  1. Vytvorí výstupný názov súboru (.enc alebo _dec prípona)
  2. Otvorí vstupný a výstupný súbor
  3. Pri šifrovaní:
     - Vygeneruje náhodný salt a blokovú úpravu
     - Zapíše ich na začiatok výstupného súboru
  4. Pri dešifrovaní:
     - Načíta salt a blokovú úpravu zo začiatku súboru
  5. Vygeneruje kľúč z hesla a salt pomocou Argon2
  6. Inicializuje AES-XTS kontext s kľúčom a blokovou úpravou
  7. Spracováva súbor po blokoch:
     - Načíta blok dát
     - Šifruje/dešifruje blok
     - Zapíše výsledok
  8. Vyčistí a uvoľní použité prostriedky

#### derive_key_from_password
```c
int derive_key_from_password(const char *password, const unsigned char *salt, unsigned char *key, size_t key_length)
```
- **Účel**: Generuje šifrovací kľúč z hesla pomocou Argon2
- **Parametre**:
  - password: používateľské heslo
  - salt: 16-bajtový salt
  - key: buffer pre výstupný 64-bajtový kľúč
  - key_length: dĺžka kľúča
- **Proces**:
  1. Inicializuje Argon2 s parametrami:
     - t_cost = 3 (počet iterácií)
     - m_cost = 65536 (64MB pamäte)
     - parallelism = 4 (počet vlákien)
  2. Nastaví používateľské heslo ako vstup
  3. Pridá salt pre jedinečnosť
  4. Spustí Argon2id algoritmus
  5. Vygeneruje 32-bajtový kľúč
  6. Vyčistí pamäť pre Argon2
  7. Vráti výsledok operácie (0 = úspech)

#### aes_xts_crypt
```c
int aes_xts_crypt(EVP_CIPHER_CTX *ctx, unsigned char *in, int in_len, unsigned char *out, int *out_len, unsigned char *tweak)
```
- **Účel**: Vykonáva XTS šifrovanie/dešifrovanie bloku dát
- **Parametre**:
  - ctx: OpenSSL kontext
  - in: vstupné dáta
  - in_len: dĺžka vstupných dát
  - out: výstupný buffer
  - out_len: dĺžka výstupných dát
  - tweak: hodnota blokovej úpravy pre XTS
- **Proces**:
  1. Nastaví blokovú úpravu pre aktuálny blok
  2. Inicializuje šifrovanie/dešifrovanie s blokovou úpravou
  3. Spracuje vstupné dáta:
     - Rozdelí na 128-bitové bloky
     - Aplikuje XTS na každý blok
     - Spája zašifrované/dešifrované bloky
  4. Aktualizuje dĺžku výstupných dát
  5. Vráti stav operácie (1 = úspech)

#### calculate_sector_tweak
```c
void calculate_sector_tweak(const unsigned char *initial_tweak, uint64_t sector_number, unsigned char *output_tweak)
```
- **Účel**: Vypočíta blokovú úpravu pre daný sektor
- **Parametre**:
  - initial_tweak: počiatočná bloková úprava
  - sector_number: číslo sektora
  - output_tweak: výstupný buffer pre blokovú úpravu
- **Proces**:
  1. Skopíruje počiatočnú blokovú úpravu do výstupného buffera
  2. Aplikuje modifikáciu podľa čísla sektora:
     - Upraví posledných 64 bitov blokovej úpravy
     - Pripočíta číslo sektora k hodnote
  3. Zabezpečí little-endian reprezentáciu

#### hex_to_bytes
```c
int hex_to_bytes(const char *hex_str, unsigned char *bytes, size_t bytes_len)
```
- **Účel**: Konvertuje hexadecimálny reťazec na bajty
- **Parametre**:
  - hex_str: vstupný hex string
  - bytes: výstupný buffer
  - bytes_len: veľkosť buffera
- **Proces**:
  1. Kontroluje dĺžku vstupného reťazca
  2. Pre každý pár znakov:
     - Validuje, či sú hexadecimálne
     - Konvertuje prvý znak na horné 4 bity
     - Konvertuje druhý znak na dolné 4 bity
     - Kombinuje bity do jedného bajtu
  3. Ukladá výsledné bajty do buffera
  4. Vracia počet spracovaných bajtov

#### print_hex_output
```c
void print_hex_output(const unsigned char *data, size_t len)
```
- **Účel**: Vypíše dáta v hexadecimálnom formáte
- **Parametre**:
  - data: dáta na vypísanie
  - len: dĺžka dát
- **Proces**:
  1. Pre každý bajt dát:
     - Konvertuje na dvojciferné hex číslo
     - Pridá medzeru medzi bajtami
  2. Po 16 bajtoch pridá nový riadok
  3. Vypisuje formátovaný výstup na konzolu

#### get_password
```c
char *get_password()
```
- **Účel**: Bezpečné načítanie hesla od používateľa
- **Proces**:
  1. Vypne echo terminálu
  2. Zobrazí výzvu na zadanie hesla
  3. Načíta heslo zo štandardného vstupu
  4. Odstráni znak nového riadku
  5. Zapne echo terminálu
  6. Vráti načítané heslo

#### append_extension / generate_decrypted_filename
```c
char *append_extension(const char *filename, const char *ext)
char *generate_decrypted_filename(const char *encrypted_filename)
```
- **Účel**: Správa názvov súborov
- **Proces**:
  1. append_extension:
     - Alokuje pamäť pre nový názov
     - Skopíruje pôvodný názov
     - Pridá požadovanú príponu
  2. generate_decrypted_filename:
     - Odstráni .enc príponu
     - Vloží _dec pred pôvodnú príponu
     - Vráti nový názov súboru

#### load_test_vectors / test_vectors
```c
void load_test_vectors(const char *filename)
int test_vectors(const char *test_file)
```
- **Účel**: Funkcie pre testovanie implementácie
- **Proces**:
  1. load_test_vectors:
     - Otvorí súbor s testovacími vektormi
     - Načíta vstupné dáta, kľúče a očakávané výstupy
     - Spracuje formátovanie a validuje dáta
  2. test_vectors:
     - Načíta testovacie vektory
     - Pre každý vektor:
       * Inicializuje AES-XTS kontext
       * Vykoná šifrovanie/dešifrovanie
       * Porovná s očakávaným výsledkom
     - Vypíše výsledky testov

### Formát šifrovaného súboru
```
+---------------+-------------------+-------------------+
| SALT          | Bloková úprava    | Šifrované dáta    |
| (128 bitov)   | (128 bitov)       | (n-bajtov)        |
+---------------+-------------------+-------------------+
```

## Bezpečnostné informácie

### Odporúčania pre heslá
- Minimálna dĺžka: 8 znakov
- Použite kombináciu:
  - Veľké písmená (A-Z)
  - Malé písmená (a-z)
  - Čísla (0-9)
  - Špeciálne znaky (!@#$%^&*)

### Ako funguje XTS
- Používa dva kľúče: jeden pre šifrovanie, druhý pre blokovú úpravu
- Každý blok má unikátnu blokovú úpravu vytvorenú z čísla sektora
- Vzorec: C = E(K1, P ⊕ T) ⊕ T, kde T = E(K2, i) ⊗ α^j
  - K1, K2: šifrovacie kľúče
  - P: plaintext
  - i: číslo sektora (fyzické alebo logické)
  - j: pozícia bloku v sektore (od 0)
  - α: primitívny prvok poľa GF(2^128)

### Bezpečnostné vlastnosti programu
1. **Ochrana proti útokom**
   - Odolnosť voči brute-force útokom
   - Ochrana proti rainbow table útokom
   - Zabezpečenie proti útokom postranným kanálom

2. **Kryptografická bezpečnosť**
   - 128/256-bitová bezpečnostná úroveň
   - Jedinečný salt pre každý súbor
   - Jedinečná bloková úprava pre každý sektor
   - Bezpečné mazanie pamäte

## Odkazy na dokumentáciu

### OpenSSL
- [Hlavná dokumentácia](https://www.openssl.org/docs/)
- [EVP rozhranie](https://www.openssl.org/docs/man3.0/man7/evp.html)
- [Argon2 implementácia](https://www.openssl.org/docs/man3.0/man7/EVP_KDF-ARGON2.html)

### Štandardy
- [IEEE 1619-2007](https://standards.ieee.org/standard/1619-2007.html)
- [NIST SP 800-38E](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf)
