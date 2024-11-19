# AES-XTS Šifrovanie/Dešifrovanie pre BP

## Popis

Tento projekt poskytuje nástroj na šifrovanie a dešifrovanie súborov pomocou algoritmu AES-128-XTS s využitím knižnice OpenSSL. Program umožňuje šifrovať viaceré súbory naraz, automaticky generovať vhodné názvy výstupných súborov a využíva bezpečnú funkciu na odvodenie kľúča zo zadaného hesla pomocou Argon2id.

## Funkcie

- **Šifrovanie a Dešifrovanie**: Podpora pre šifrovanie a dešifrovanie viacerých súborov naraz.
- **Automatické Generovanie Názvov Súborov**:
  - Pri šifrovaní sa k názvu súboru pridáva prípona `.enc`.
  - Pri dešifrovaní sa prípona `_dec` vkladá pred pôvodnú príponu (napr. `example.txt.enc` → `example_dec.txt`).
- **Bezpečné Zadávanie Hesla**: Heslo sa zadáva bezpečne bez zobrazovania na obrazovke.
- **Odvodenie Kľúča pomocou Argon2id**: Použitie modernej funkcie na odvodenie kľúča zo zadaného hesla pre dostatočnú bezpečnosť.
- **Testovanie s Testovacími Vektormi**: Možnosť otestovať testovacie vektory zo štandardu.

## Požiadavky

- **C Kompilátor**: Pre kompiláciu použitie kompilátor gcc.
- **OpenSSL**: OpenSSL vo verzii aspoň 3.3.0.

## Kompilácia

- **Windows/Unix systémy**: gcc.
