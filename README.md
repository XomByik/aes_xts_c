# AES-XTS šifrovanie a dešifrovanie diskov s využitím knižnice OpenSSL

## Obsah
1. [Základný prehľad](#základný-prehľad)
2. [Inštalácia](#inštalácia)
3. [Ako to funguje](#ako-to-funguje)
4. [Používanie programu](#používanie-programu)
5. [Technická dokumentácia](#technická-dokumentácia)
6. [Bezpečnostné informácie](#bezpečnostné-informácie)
7. [Odkazy na dokumentáciu](#odkazy-na-dokumentáciu)

## Základný prehľad

Tento program slúži na bezpečné šifrovanie a dešifrovanie diskových partícií. Je vhodný pre:
- Bezpečné šifrovanie diskových partícií a externých médií
- Ochranu dát pred neoprávneným prístupom

### Hlavné výhody
- Využíva moderný šifrovací algoritmus (AES-XTS s podporou 128-bitových a 256-bitových kľúčov)
- Jednoduchý na použitie
- Podporuje šifrovanie celých diskových partícií
- Funguje na Windows aj Linux systémoch
- Využíva paralelné spracovanie pre zvýšenie výkonu

### Použité technológie

1. **AES-XTS šifrovanie**
   - Využíva 128/256-bitové kľúče pre šifrovanie aj blokové úpravy
   - Celkový 256/512-bitový kľúč pre AES-XTS režim
   - Špeciálne navrhnutý režim pre šifrovanie diskov
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

3. **OpenMP**
   - Paralelizácia spracovania dát pre zvýšenie výkonu
   - Efektívne využitie viacjadrových procesorov
   - Dynamické rozdelenie záťaže medzi dostupné vlákna
   - [Dokumentácia OpenMP](https://www.openmp.org/)

## Inštalácia OpenSSL

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
sudo apt-get install openssl libssl-dev
```

## Používanie programu

### Kompilácia programu

#### Automatická kompilácia pomocou Makefile v priečinku s programom
```bash
make
```

### Windows použitie
```powershell
# Šifrovanie celých diskov
aes_xts.exe encrypt 128 \\.\PhysicalDrive1    # Pre 128-bitové kľúče
aes_xts.exe encrypt 256 \\.\PhysicalDrive1    # Pre 256-bitové kľúče
aes_xts.exe encrypt \\.\PhysicalDrive1        # Pre predvolené 256-bitové kľúče

# Šifrovanie partícií
aes_xts.exe encrypt 256 \\.\E:               # Šifrovanie partície E:

# Dešifrovanie diskov
aes_xts.exe decrypt \\.\PhysicalDrive1
aes_xts.exe decrypt \\.\E:
```

**Poznámka:** V systéme Windows je potrebné spustiť program s administrátorskými oprávneniami.

### Linux použitie
```bash
./aes_xts encrypt 128 /dev/sdb1    # Pre 128-bitové kľúče
./aes_xts encrypt 256 /dev/sdb1    # Pre 256-bitové kľúče
./aes_xts encrypt /dev/sdb1        # Pre predvolené 256-bitové kľúče
```

### Dešifrovanie diskových partícií
```bash
./aes_xts decrypt /dev/sdb1
```

## Ako to funguje

### Proces šifrovania
1. Zadanie vstupných parametrov:
   - Veľkosť kľúča (128 alebo 256 bitov)
   - Cesta k diskovej partícii
   - Heslo od používateľa
   
2. Príprava hlavičky:
   - Vygenerovanie náhodnej 128-bitovej soli cez CSPRNG
   - Vytvorenie verifikačných dát pre kontrolu správnosti hesla
   - Uloženie hlavičky do sektora 62 (za MBR/GPT)
   - Tento prístup zabezpečuje, že partíciu je možné rozšifrovať na rôznych systémoch (Windows/Linux)

3. Derivácia kľúčov:
   - Z hesla a salt sa pomocou Argon2id vytvorí šifrovací kľúč
   - Pre AES-128-XTS: 256 bitov (kombinovaný kľúč)
   - Pre AES-256-XTS: 512 bitov (kombinovaný kľúč)
   - Kľúč obsahuje obe časti potrebné pre XTS režim (šifrovanie dát a blokové úpravy)

4. Spracovanie partície po sektoroch (4096 bajtov):
   - Pre každý sektor sa vypočíta jedinečná bloková úprava
   - Preskočenie prvých 64 sektorov (rezervované pre MBR/GPT a hlavičku)
   - Šifrovanie dát v sektore pomocou AES-XTS s vypočítanou blokovou úpravou
   - Paralelné spracovanie blokov dát pomocou OpenMP pre zvýšenie výkonu

### Proces dešifrovania
1. Zadanie parametrov:
   - Heslo od používateľa
   - Cesta k zašifrovanej partícii

2. Čítanie hlavičky:
   - Načítanie hlavičky zo sektora 62
   - Extrakcia soli, veľkosti kľúča a ďalších parametrov

3. Derivácia kľúča:
   - Použitie rovnakého hesla a načítaného salt
   - Vytvorenie rovnakého kľúča ako pri šifrovaní
   - Overenie správnosti hesla pomocou verifikačných dát

4. Spracovanie partície po sektoroch:
   - Výpočet blokovej úpravy pre každý sektor rovnakým spôsobom
   - Dešifrovanie dát pomocou AES-XTS s patričnou blokovou úpravou
   - Paralelné spracovanie blokov pomocou OpenMP

### Režim XTS a využitie blokových úprav
- XTS (XEX-based tweaked-codebook mode with ciphertext stealing) je špecializovaný
  režim pre šifrovanie úložísk
- Bloková úprava zabezpečuje, že rovnaké dáta na rôznych pozíciách budú zašifrované inak
- Výhody použitia blokových úprav:
  - Ochrana proti útoku preskladaním sektorov
  - Ochrana proti kopírovaniu sektorov
  - Každý sektor má unikátne šifrovanie

### Spracovanie sektorov
- Veľkosť sektora: 4096 bajtov
- Číslovanie sektorov:
  - Začíname od rezervovanej oblasti (64 sektorov)
  - Každý sektor dostáva svoje poradové číslo
- Bloková úprava pre sektor:
  - Kombinácia počiatočného IV a čísla sektora
  - Zabezpečuje unikátnosť šifrovania pre každý sektor
- Paralelné spracovanie:
  - Využitie OpenMP na paralelizáciu spracovania blokov
  - Dynamické priradenie sektorov jednotlivým vláknam pre optimálny výkon

## Technická dokumentácia

### Implementované funkcie

#### aes_xts_crypt_sector
```c
int32_t aes_xts_crypt_sector(
    const uint8_t *key,     // Jeden spojený kľúč
    uint64_t sector_num,
    uint8_t *data,
    size_t data_len,
    int encrypt,
    int key_bits 
)
```
- **Účel**: Vykonáva šifrovanie alebo dešifrovanie jedného sektora pomocou AES-XTS
- **Parametre**:
  - key: spojený kľúč (obsahuje obe časti pre XTS režim)
  - sector_num: číslo sektora
  - data: dáta na šifrovanie/dešifrovanie
  - data_len: veľkosť dát
  - encrypt: 1 pre šifrovanie, 0 pre dešifrovanie
  - key_bits: veľkosť kľúča (128 alebo 256)
- **Proces**:
  1. Vytvorí IV z čísla sektora
  2. Inicializuje OpenSSL kontext pre AES-XTS
  3. Vykoná šifrovanie alebo dešifrovanie podľa parametra encrypt
  4. Vyčistí kontext a vráti výsledok

#### derive_keys_from_password
```c
int derive_keys_from_password(
    const uint8_t *password, 
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *key,          // Jeden spojený kľúč
    int key_bits,
    uint32_t iterations,
    uint32_t memory_cost
)
```
- **Účel**: Generuje šifrovací kľúč z hesla pomocou Argon2id
- **Parametre**:
  - password: používateľské heslo
  - salt: salt pre deriváciu kľúča
  - salt_len: dĺžka salt
  - key: buffer pre výsledný spojený kľúč
  - key_bits: veľkosť kľúča v bitoch (128 alebo 256)
  - iterations: počet iterácií Argon2 algoritmu
  - memory_cost: pamäťová náročnosť Argon2 algoritmu
- **Proces**:
  1. Inicializuje Argon2id KDF v OpenSSL
  2. Nastaví parametre pre deriváciu (iterácie, pamäť, paralelizmus)
  3. Vytvorí kľúč z hesla a salt
  4. Výsledok obsahuje celý spojený kľúč potrebný pre XTS režim
  5. Vráti výsledok operácie

#### process_sectors
```c
int process_sectors(
    device_context_t *ctx,
    uint8_t *key,          // Jeden spojený kľúč
    uint64_t start_sector,
    int encrypt,
    int key_bits  
)
```
- **Účel**: Spracováva sektory zariadenia (šifrovanie/dešifrovanie)
- **Parametre**:
  - ctx: kontext zariadenia
  - key: spojený kľúč pre XTS režim
  - start_sector: prvý sektor na spracovanie
  - encrypt: 1 pre šifrovanie, 0 pre dešifrovanie
  - key_bits: veľkosť kľúča v bitoch
- **Proces**:
  1. Alokuje buffer pre efektívne spracovanie (8MB)
  2. Nastaví pozíciu na začiatočný sektor
  3. Číta dáta zo zariadenia po blokoch
  4. Paralelne spracováva sektory v bloku pomocou OpenMP
  5. Zapisuje spracované dáta späť na zariadenie
  6. Zobrazuje priebeh operácie
  7. Vyčistí a uvoľní použité prostriedky

#### header_io
```c
int header_io(device_context_t *ctx, xts_header_t *header, int isWrite)
```
- **Účel**: Zapisuje a číta hlavičku šifrovania z partície
- **Parametre**:
  - ctx: kontext zariadenia
  - header: štruktúra s hlavičkou
  - isWrite: 1 pre zápis, 0 pre čítanie
- **Proces**:
  1. Alokuje buffer pre sektor
  2. Pre zápis:
     - Inicializuje sektor s hlavičkou
     - Zapisuje na pozíciu HEADER_SECTOR
  3. Pre čítanie:
     - Číta sektor z pozície HEADER_SECTOR
     - Overí magic hodnotu "AESXTS"
     - Naplní štruktúru s hlavičkou
  4. Vyčistí a uvoľní použité prostriedky

#### create_verification_data
```c
void create_verification_data(const uint8_t *key, int key_bits, const uint8_t *salt, uint8_t *verification_data)
```
- **Účel**: Vytvára verifikačné dáta pre overenie správnosti hesla
- **Parametre**:
  - key: šifrovací kľúč (prvá polovica spojeného kľúča)
  - key_bits: veľkosť kľúča v bitoch
  - salt: salt použitý pri derivácii kľúča
  - verification_data: výstupný buffer pre verifikačné dáta
- **Proces**:
  1. Inicializuje HMAC s SHA256
  2. Spracuje konštantný reťazec a salt
  3. Vygeneruje 32 bajtov verifikačných dát
  4. Vyčistí a uvoľní OpenSSL kontext

### Paralelizácia pomocou OpenMP

Program využíva OpenMP pre paralelné spracovanie blokov dát:

```c
#pragma omp parallel for schedule(dynamic, 32)
for (size_t i = 0; i < num_sectors; i++) {
    // Spracovanie jednotlivých sektorov
    aes_xts_crypt_sector(key, current_sector + i, sector_data, sector_size, encrypt, key_bits);
}
```

- **Výhody paralelizácie**:
  - Výrazné zrýchlenie na viacjadrových procesoroch
  - Efektívne využitie dostupných výpočtových zdrojov
  - Dynamické rozdelenie práce medzi vlákna
  - Škálovateľný výkon podľa dostupných CPU jadier

### Formát hlavičky šifrovanej partície
```
+---------------+------------------+------------------+-----------------+
| Magic (6B)    | Version (1B)     | Enc Type (1B)    | Start Sector    |
+---------------+------------------+------------------+-----------------+
| Iterations    | Memory Cost      | Key Bits         | Salt (16B)      |
+---------------+------------------+------------------+-----------------+
| Verification Data (32B)          | Padding          |                 |
+---------------+------------------+------------------+-----------------+
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
   - Odolnosť voči brute-force útokom vďaka Argon2id
   - Ochrana proti rainbow table útokom pomocou náhodného salt
   - Verifikačné dáta pre kontrolu správnosti hesla

2. **Kryptografická bezpečnosť**
   - 128/256-bitová bezpečnostná úroveň
   - Jedinečný salt pre každý partíciu
   - Jedinečná bloková úprava pre každý sektor
   - Bezpečné mazanie pamäte po použití

3. **Systémová integrácia**
   - Preskakuje prvých 64 sektorov pre zachovanie MBR/GPT
   - Hlavička v sektore 62 pre kompatibilitu s rôznymi systémami

## Odkazy na dokumentáciu

### OpenSSL
- [Hlavná dokumentácia](https://www.openssl.org/docs/)
- [EVP rozhranie](https://www.openssl.org/docs/man3.0/man7/evp.html)
- [Argon2 implementácia](https://www.openssl.org/docs/man3.0/man7/EVP_KDF-ARGON2.html)

### Štandardy
- [IEEE 1619-2007](https://standards.ieee.org/standard/1619-2007.html)
- [NIST SP 800-38E](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf)
