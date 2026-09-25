🇬🇧 [English version](README.md)

# 🔐 System szyfrowania i deszyfrowania plików z weryfikacją integralności danych

Aplikacja desktopowa do szyfrowania, deszyfrowania, podpisywania i weryfikowania plików z wykorzystaniem klasycznych, nowoczesnych oraz postkwantowych algorytmów kryptograficznych.

Aplikacja obsługuje szyfrowanie symetryczne i asymetryczne, mechanizmy kapsułkowania klucza (KEM), podpisy cyfrowe, szyfrowanie oparte na haśle, weryfikację integralności, bezpieczne generowanie kluczy, metadane plików, anulowanie operacji oraz wiele motywów interfejsu.

---

## ✨ Funkcje

- Szyfrowanie i deszyfrowanie dowolnych plików, w tym dokumentów, archiwów, obrazów, plików audio i wideo.
- Szyfrowanie symetryczne z użyciem wielu szyfrów blokowych i strumieniowych.
- Szyfrowanie asymetryczne z RSA-OAEP.
- Postkwantowe kapsułkowanie klucza z ML-KEM.
- Podpisy cyfrowe z RSA-PSS, EdDSA, ECDSA, ML-DSA i SLH-DSA.
- Szyfrowanie oparte na haśle z Argon2id lub PBKDF2-HMAC-SHA256.
- Wbudowany generator haseł i fraz hasłowych.
- Generowanie fraz hasłowych na podstawie EFF Large Wordlist.
- Uwierzytelnione szyfrowanie i weryfikacja integralności z użyciem trybów AEAD, MAC oraz podpisów cyfrowych.
- Przetwarzanie strumieniowe/chunked dla dużych plików tam, gdzie jest obsługiwane.
- Automatyczne zapisywanie metadanych wewnątrz zaszyfrowanych plików.
- Automatyczne odtwarzanie parametrów algorytmu po otwarciu obsługiwanego pliku `.enc`.
- Generowanie kluczy symetrycznych i asymetrycznych.
- Bezpieczne usuwanie plików źródłowych z uwzględnieniem charakterystyki HDD/SSD.
- Obsługa przeciągnij i upuść dla plików i kluczy.
- Historia plików, kluczy, kluczy prywatnych, kluczy publicznych i podpisów.
- Pasek postępu operacji z wartością procentową, ETA i możliwością anulowania.
- Integracja postępu z paskiem zadań Windows.
- Interfejs w języku angielskim i polskim.
- Motywy jasny, ciemny, systemowy oraz własne motywy QSS.
- Automatyczne wykrywanie jasnego/ciemnego trybu Windows.
- Trwałe zapisywanie ustawień aplikacji.

---

## 🛠️ Technologie

- **Python 3.12**
- **PySide6** – graficzny interfejs użytkownika.
- **PyCryptodome** – prymitywy i algorytmy kryptograficzne.
- **cryptography** – nowoczesne prymitywy kryptograficzne i obsługa ECC.
- **pqcrypto** – postkwantowe algorytmy kryptograficzne.
- **PySkein** – obsługa Skein i Threefish.
- **pyserpent** – implementacja Serpent.
- **argon2-cffi** – wyprowadzanie klucza z hasła przy użyciu Argon2id.
- **hashlib / PBKDF2-HMAC-SHA256** – wyprowadzanie klucza za pomocą PBKDF2.
- **psutil** – monitorowanie procesu i wykorzystania pamięci.
- **darkdetect** – wykrywanie motywu systemu operacyjnego.
- **PyInstaller** – budowanie aplikacji wykonywalnej dla Windows.

---

## 🔒 Uwagi dotyczące bezpieczeństwa

Projekt został stworzony w celach edukacyjnych, portfolio oraz demonstracyjnych. Pokazuje praktyczne wykorzystanie wielu algorytmów kryptograficznych, trybów uwierzytelnionego szyfrowania, kodów uwierzytelniania wiadomości, funkcji wyprowadzania klucza z hasła oraz podpisów cyfrowych.

Tryby uwierzytelnionego szyfrowania, takie jak AES-GCM, AES-EAX, 3DES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305 i ASCON, zapewniają poufność i integralność w jednej konstrukcji.

Inne algorytmy wykorzystują dodatkowe mechanizmy integralności tam, gdzie jest to wymagane, np. Encrypt-then-MAC.

Algorytmy podpisu cyfrowego są obsługiwane niezależnie od algorytmów szyfrowania i mogą służyć do podpisywania oraz weryfikowania plików.

Przy szyfrowaniu opartym na haśle samo hasło nigdy nie jest zapisywane. Zaszyfrowany plik przechowuje natomiast sól oraz parametry KDF wymagane do ponownego wyprowadzenia klucza podczas deszyfrowania.

Argon2id jest zalecaną funkcją KDF dla haseł. Dla kompatybilności dostępne jest również PBKDF2-HMAC-SHA256.

Mechanizmy bezpiecznego usuwania plików uwzględniają różnice pomiędzy dyskami HDD i SSD. Ze względu na wear leveling, over-provisioning, działanie kontrolera, migawki oraz zachowanie systemu plików całkowite fizyczne usunięcie danych z SSD nie zawsze może być zagwarantowane.

---

## 🎨 Interfejs aplikacji

Interfejs obsługuje motywy wbudowane i własne. Wybrany motyw jest zapisywany pomiędzy uruchomieniami aplikacji.

Dostępne tryby motywu:

- Jasny
- Ciemny
- Systemowy
- Własne motywy `.qss` wykrywane w katalogu motywów

Tryb systemowy automatycznie dopasowuje się do jasnego/ciemnego wyglądu Windows.

### 🔹 Główne okno

> 📷 Miejsce na zrzut ekranu — główne okno aplikacji

### 🔹 Jasny motyw

> 📷 Miejsce na zrzut ekranu — jasny motyw

### 🔹 Ciemny motyw

> 📷 Miejsce na zrzut ekranu — ciemny motyw

### 🔹 Własne motywy

> 📷 Miejsce na zrzut ekranu — motyw Neon Green

> 📷 Miejsce na zrzut ekranu — motyw Arctic Cyan

> 📷 Miejsce na zrzut ekranu — motyw Shadow Monarch

> 📷 Miejsce na zrzut ekranu — motyw Windows 11

---

## 🔑 Źródła klucza

Dla szyfrowania symetrycznego aplikacja może używać pliku klucza albo hasła.

### 🔹 Plik klucza

Klucz symetryczny może zostać wygenerowany przez aplikację i zapisany w pliku `.key`.

> 📷 Miejsce na zrzut ekranu — plik klucza symetrycznego

### 🔹 Hasło

Zamiast pliku klucza można użyć hasła, z którego wyprowadzany jest klucz szyfrujący.

Obsługiwane KDF:

- **Argon2id**
  - pamięciochłonna funkcja do hashowania/wyprowadzania klucza z hasła,
  - losowa sól,
  - konfigurowalne parametry zapisywane w metadanych zaszyfrowanego pliku.

- **PBKDF2-HMAC-SHA256**
  - PBKDF2 oparty na SHA-256,
  - losowa sól,
  - liczba iteracji zapisywana w metadanych zaszyfrowanego pliku.

Aplikacja wymusza minimalną długość hasła dla nowych operacji szyfrowania, ale nadal pozwala odszyfrować starsze pliki, jeśli ich hasło zostało utworzone przy innej polityce.

Hasła mogą zawierać spacje, znaki Unicode, symbole i emoji.

> 📷 Miejsce na zrzut ekranu — szyfrowanie oparte na haśle

### 🔹 Wskaźnik siły hasła

GUI zawiera wskaźnik siły hasła uwzględniający długość hasła, różnorodność znaków, powtarzające się znaki, proste sekwencje oraz popularne słabe wzorce.

Wskaźnik pełni funkcję pomocniczą w interfejsie i nie jest formalnym estymatorem entropii.

> 📷 Miejsce na zrzut ekranu — wskaźnik siły hasła

---

## 🎲 Generator haseł i fraz hasłowych

Aplikacja zawiera wbudowany generator umożliwiający tworzenie haseł bez opuszczania procesu szyfrowania.

### Tryb losowego hasła

Dostępne opcje:

- długość hasła,
- wielkie litery,
- cyfry,
- symbole.

Generator gwarantuje, że każda włączona klasa znaków będzie reprezentowana w wygenerowanym haśle.

### Tryb frazy hasłowej

Frazy hasłowe są generowane na podstawie **EFF Large Wordlist** przy użyciu kryptograficznie bezpiecznej losowości.

Dostępne opcje:

- liczba słów,
- formatowanie wielkimi literami,
- sufiks liczbowy,
- separator będący symbolem.

Oficjalna lista słów EFF zawiera 7 776 pozycji i jest dołączana do aplikacji.

> 📷 Miejsce na zrzut ekranu — generator haseł

---

## 🔐 Klucze asymetryczne

Algorytmy asymetryczne używają oddzielnych plików klucza prywatnego i publicznego tam, gdzie ma to zastosowanie.

Aplikacja może generować klucze prywatne oraz tworzyć/wyprowadzać odpowiadające im klucze publiczne.

Obsługiwane zastosowania kryptografii asymetrycznej:

- szyfrowanie/deszyfrowanie,
- podpisy cyfrowe,
- postkwantowe kapsułkowanie klucza.

> 📷 Miejsce na zrzut ekranu — pliki klucza prywatnego i publicznego

---

# 🔢 Zaimplementowane algorytmy

Aplikacja dzieli algorytmy na dwie główne grupy:

- **Szyfrowanie i KEM**
- **Podpisy cyfrowe**

> 📷 Miejsce na zrzut ekranu — lista wyboru algorytmów

---

## 🔒 Szyfrowanie symetryczne

### AES

**Typ:** Symetryczny szyfr blokowy  
**Standard:** NIST FIPS 197  
**Rozmiar bloku:** 128 bitów  
**Długości klucza:** 128, 192, 256 bitów

Obsługiwane tryby:

- **GCM (AEAD)** – uwierzytelnione szyfrowanie, obsługa streamingu.
- **EAX (AEAD)** – uwierzytelnione szyfrowanie, obsługa streamingu.
- **SIV (AEAD)** – uwierzytelnione szyfrowanie odporne na niewłaściwe użycie nonce, bez streamingu w obecnej implementacji. Używa kluczy SIV 256, 384 lub 512 bitów, odpowiadających wewnętrznie AES-128, AES-192 lub AES-256.
- **CCM (AEAD)** – uwierzytelnione szyfrowanie, bez streamingu w obecnej implementacji.
- **OCB (AEAD)** – uwierzytelnione szyfrowanie, bez streamingu w obecnej implementacji.
- **CTR** – tryb licznikowy, obsługa streamingu, sam w sobie nie zapewnia uwierzytelnienia.
- **CBC** – tryb wiązania bloków szyfrogramu, obsługa streamingu, sam w sobie nie zapewnia uwierzytelnienia.
- **ECB** – tryb elektronicznej książki kodowej, obsługa streamingu, nie zapewnia uwierzytelnienia i nie ukrywa powtarzających się wzorców bloków tekstu jawnego.

Dla trybów AEAD tag uwierzytelniający jest weryfikowany przed zapisaniem odszyfrowanych danych do pliku wynikowego. Nagłówek zaszyfrowanego pliku jest uwierzytelniany jako associated data tam, gdzie dany tryb to obsługuje.

> 📷 Miejsce na zrzut ekranu — ustawienia AES i wszystkie dostępne tryby

---

### ASCON

**Typ:** Lekki algorytm uwierzytelnionego szyfrowania  
**Standard:** NIST SP 800-232  
**Długość klucza:** 128 bitów

Obsługiwany tryb:

- **Ascon-128 (AEAD)** – uwierzytelnione szyfrowanie, obsługa streamingu.

ASCON łączy poufność i integralność w lekkiej konstrukcji opartej na permutacji.

> 📷 Miejsce na zrzut ekranu — ustawienia ASCON

---

### Serpent-HMAC

**Typ:** Symetryczny szyfr blokowy z uwierzytelnieniem Encrypt-then-MAC  
**Rodzina:** Serpent + HMAC  
**Rozmiar bloku:** 128 bitów  
**Długości klucza:** 128, 192, 256 bitów

Obsługiwany tryb:

- **CBC + HMAC-SHA256** – Serpent-CBC chroniony przez HMAC-SHA256 w konstrukcji Encrypt-then-MAC; obsługa streamingu.

MAC jest weryfikowany przed zapisaniem odszyfrowanego tekstu jawnego do pliku wynikowego.

> 📷 Miejsce na zrzut ekranu — ustawienia Serpent-HMAC

---

### Camellia

**Typ:** Symetryczny szyfr blokowy  
**Standard:** RFC 3713 / ISO/IEC 18033-3  
**Rozmiar bloku:** 128 bitów  
**Długości klucza:** 128, 192, 256 bitów

Obsługiwane tryby:

- **CFB** – tryb sprzężenia zwrotnego szyfrogramu, obsługa streamingu.
- **CBC** – tryb wiązania bloków szyfrogramu, obsługa streamingu.

Tryby te zapewniają poufność, ale same w sobie nie zapewniają uwierzytelnienia.

> 📷 Miejsce na zrzut ekranu — ustawienia i tryby Camellia

---

### 3DES

**Typ:** Symetryczny szyfr blokowy  
**Status:** Legacy  
**Standard:** NIST SP 800-67 (wycofany)  
**Rozmiar bloku:** 64 bity  
**Długość klucza:** 192 bity

Obsługiwane tryby:

- **EAX (AEAD)** – uwierzytelnione szyfrowanie, obsługa streamingu.
- **CTR** – tryb licznikowy, obsługa streamingu.
- **CFB** – tryb sprzężenia zwrotnego szyfrogramu, obsługa streamingu.
- **OFB** – tryb sprzężenia zwrotnego wyjścia, obsługa streamingu.

Tylko EAX zapewnia uwierzytelnienie samodzielnie. 3DES pozostaje w aplikacji głównie ze względów kompatybilnościowych, historycznych i edukacyjnych.

Przy pracy opartej na haśle parzystość wyprowadzonego klucza jest dostosowywana do wymagań 3DES.

> 📷 Miejsce na zrzut ekranu — ustawienia 3DES i wszystkie dostępne tryby

---

### ChaCha20-Poly1305

**Typ:** Symetryczny szyfr strumieniowy AEAD  
**Standard:** RFC 8439  
**Długość klucza:** 256 bitów  
**Streaming:** Obsługiwany

ChaCha20 zapewnia szyfrowanie, natomiast Poly1305 odpowiada za uwierzytelnienie i weryfikację integralności.

> 📷 Miejsce na zrzut ekranu — ustawienia ChaCha20-Poly1305

---

### XChaCha20-Poly1305

**Typ:** Symetryczny szyfr strumieniowy AEAD  
**Specyfikacja:** draft-irtf-cfrg-xchacha  
**Długość klucza:** 256 bitów  
**Streaming:** Obsługiwany

XChaCha20-Poly1305 rozszerza ChaCha20-Poly1305 o większą przestrzeń nonce, zachowując uwierzytelnione szyfrowanie.

> 📷 Miejsce na zrzut ekranu — ustawienia XChaCha20-Poly1305

---

### Salsa20

**Typ:** Symetryczny szyfr strumieniowy  
**Pochodzenie:** eSTREAM Portfolio  
**Długość klucza:** 256 bitów  
**Streaming:** Obsługiwany

Salsa20 przetwarza pliki przyrostowo i zapewnia poufność. Sam w sobie nie zapewnia uwierzytelnienia.

> 📷 Miejsce na zrzut ekranu — ustawienia Salsa20

---

### Threefish-Skein-MAC

**Typ:** Tweakowalny szyfr blokowy z uwierzytelnieniem MAC  
**Pochodzenie:** finalista konkursu SHA-3 – Skein  
**Rozmiary bloku/klucza:** 256, 512, 1024 bitów  
**Streaming:** Obsługiwany

Threefish jest połączony z Skein-MAC w celu zapewnienia ochrony integralności. Aplikacja wykorzystuje konstrukcję Encrypt-then-MAC z oddzielnie wyprowadzonym kluczem uwierzytelniającym.

> 📷 Miejsce na zrzut ekranu — ustawienia Threefish-Skein-MAC

---

## 🔐 Szyfrowanie asymetryczne

### RSA-OAEP

**Typ:** Szyfrowanie asymetryczne  
**Standard:** PKCS #1 v2.2 / RFC 8017  
**Długości klucza:** 2048, 3072, 4096 bitów  
**Streaming:** Obsługiwany przez przepływ operacji aplikacji

Obsługiwane funkcje skrótu:

- **SHA3-512**
- **SHA3-384**
- **SHA3-256**
- **SHA-512**
- **SHA-384**
- **SHA-256**

Szyfrowanie wykorzystuje klucz publiczny, a deszyfrowanie odpowiadający mu klucz prywatny.

> 📷 Miejsce na zrzut ekranu — ustawienia RSA-OAEP

---

## 🧬 Postkwantowe kapsułkowanie klucza

### ML-KEM

**Typ:** Postkwantowy mechanizm kapsułkowania klucza (KEM)  
**Standard:** NIST FIPS 203  
**Rodzina:** Module-lattice KEM  
**Streaming:** Obsługiwany przez przepływ operacji aplikacji

Obsługiwane zestawy parametrów:

- **ML-KEM-1024**
- **ML-KEM-768**
- **ML-KEM-512**

ML-KEM ustanawia współdzielony sekret, który jest następnie używany przez proces szyfrowania pliku.

> 📷 Miejsce na zrzut ekranu — wybór zestawu parametrów ML-KEM

---

# ✍️ Podpisy cyfrowe

Algorytmy podpisu cyfrowego są wyświetlane oddzielnie od algorytmów szyfrowania i KEM.

Po wybraniu algorytmu podpisu główne operacje zmieniają się z **Szyfruj / Deszyfruj** na **Podpisz / Zweryfikuj**.

Pliki podpisów używają rozszerzenia `.sig`.

---

## RSA-PSS

**Typ:** Podpis cyfrowy RSA  
**Standard:** NIST FIPS 186-5 / RFC 8017  
**Długości klucza:** 2048, 3072, 4096 bitów  
**Streaming:** Obsługiwany

Obsługiwane funkcje skrótu:

- **SHA3-512**
- **SHA3-384**
- **SHA3-256**
- **SHA-512**
- **SHA-384**
- **SHA-256**

> 📷 Miejsce na zrzut ekranu — ustawienia RSA-PSS

---

## EdDSA

**Typ:** Podpis cyfrowy na krzywych Edwardsa  
**Standard:** RFC 8032  
**Streaming:** Obsługiwany

Obsługiwane krzywe:

- **Ed25519**
- **Ed448**

> 📷 Miejsce na zrzut ekranu — wybór krzywej EdDSA

---

## ECDSA

**Typ:** Podpis cyfrowy oparty na kryptografii krzywych eliptycznych  
**Standard:** NIST FIPS 186-5  
**Streaming:** Obsługiwany

Obsługiwane krzywe:

- **P-521 (secp521r1)**
- **P-384 (secp384r1)**
- **P-256 (secp256r1)**

Obsługiwane funkcje skrótu:

- **SHA3-512**
- **SHA3-384**
- **SHA3-256**
- **SHA-512**
- **SHA-384**
- **SHA-256**

> 📷 Miejsce na zrzut ekranu — wybór krzywej i funkcji skrótu ECDSA

---

## ML-DSA

**Typ:** Postkwantowy podpis cyfrowy  
**Standard:** NIST FIPS 204  
**Rodzina:** Podpis module-lattice  
**Streaming:** Nieobsługiwany w obecnej implementacji

Obsługiwane zestawy parametrów:

- **ML-DSA-87**
- **ML-DSA-65**
- **ML-DSA-44**

> 📷 Miejsce na zrzut ekranu — wybór zestawu parametrów ML-DSA

---

## SLH-DSA

**Typ:** Postkwantowy bezstanowy podpis cyfrowy oparty na funkcjach skrótu  
**Standard:** NIST FIPS 205  
**Streaming:** Nieobsługiwany w obecnej implementacji

Obsługiwane zestawy parametrów:

- **SLH-DSA-SHAKE-256s**
- **SLH-DSA-SHAKE-256f**
- **SLH-DSA-SHA2-256s**
- **SLH-DSA-SHA2-256f**
- **SLH-DSA-SHAKE-192s**
- **SLH-DSA-SHAKE-192f**
- **SLH-DSA-SHA2-192s**
- **SLH-DSA-SHA2-192f**
- **SLH-DSA-SHAKE-128s**
- **SLH-DSA-SHAKE-128f**
- **SLH-DSA-SHA2-128s**
- **SLH-DSA-SHA2-128f**

> 📷 Miejsce na zrzut ekranu — wybór zestawu parametrów SLH-DSA

---

## 📦 Format zaszyfrowanego pliku

Zaszyfrowane pliki używają rozszerzenia `.enc`.

Każdy zaszyfrowany plik zawiera nagłówek metadanych aplikacji opisujący algorytm i parametry wymagane do prawidłowej interpretacji zaszyfrowanego payloadu.

Przykładowe metadane mogą zawierać:

- nazwę algorytmu,
- tryb szyfru,
- długość klucza,
- funkcję skrótu,
- padding,
- krzywą eliptyczną,
- postkwantowy zestaw parametrów,
- źródło klucza,
- nazwę KDF dla hasła,
- sól KDF,
- parametry KDF.

Po wybraniu pliku `.enc` aplikacja może automatycznie odtworzyć obsługiwane ustawienia algorytmu z zapisanych metadanych.

Zmniejsza to ryzyko próby deszyfrowania z niezgodnymi parametrami.

> 📷 Miejsce na zrzut ekranu — metadane zaszyfrowanego pliku / automatyczna konfiguracja

---

## 🛡️ Integralność i uwierzytelnianie danych

W zależności od wybranego algorytmu weryfikacja integralności jest realizowana przez:

- tagi uwierzytelniające AEAD,
- MAC,
- konstrukcje Encrypt-then-MAC,
- podpisy cyfrowe.

W trybach uwierzytelnionego szyfrowania modyfikacja zaszyfrowanego payloadu lub uwierzytelnionych metadanych powoduje niepowodzenie deszyfrowania.

Nieuwierzytelniony tekst jawny nie jest zapisywany bezpośrednio do docelowego pliku przed pomyślną weryfikacją. Uwierzytelnione deszyfrowanie wykorzystuje tymczasowe buforowanie i zapisuje wynik końcowy dopiero po poprawnej weryfikacji.

> 📷 Miejsce na zrzut ekranu — błąd weryfikacji integralności

---

## 📚 Streaming i przetwarzanie dużych plików

Obsługiwane algorytmy przetwarzają pliki przyrostowo zamiast wczytywać cały plik do pamięci.

Aplikacja wykorzystuje chunked I/O dla obsługiwanych operacji szyfrowania, deszyfrowania, podpisywania i weryfikowania.

Korzyści:

- mniejsze wykorzystanie pamięci,
- obsługa dużych plików,
- responsywne raportowanie postępu,
- możliwość anulowania operacji podczas przetwarzania.

Podczas operacji kryptograficznych wykorzystywane są tymczasowe pliki wynikowe. Plik końcowy zastępuje plik tymczasowy dopiero po pomyślnym zakończeniu operacji.

Zapobiega to pozostawieniu częściowo zapisanego pliku końcowego po błędzie lub anulowaniu operacji.

---

## 🗑️ Bezpieczne usuwanie plików

Aplikacja zawiera opcjonalne bezpieczne usuwanie plików źródłowych po pomyślnym szyfrowaniu lub deszyfrowaniu.

### HDD

Dla tradycyjnych dysków twardych aplikacja może wykonywać przebiegi nadpisywania przed usunięciem pliku.

### SSD

W przypadku SSD tradycyjne nadpisywanie nie może zagwarantować fizycznego usunięcia danych ze względu na wear leveling i działanie kontrolera.

Aplikacja stosuje więc mechanizmy uwzględniające rodzaj nośnika i może korzystać z technik w stylu crypto-erase oraz obsługiwanych mechanizmów optymalizacji systemowej, jeśli są dostępne.

> 📷 Miejsce na zrzut ekranu — ustawienia bezpiecznego usuwania

---

## 📂 Zarządzanie plikami i kluczami

Aplikacja zawiera:

- podgląd ścieżki pliku,
- wyświetlanie rozmiaru pliku,
- podgląd ścieżki klucza,
- otwieranie lokalizacji pliku/klucza po dwukrotnym kliknięciu,
- przyciski czyszczenia pól,
- obsługę przeciągnij i upuść,
- oddzielną historię plików i różnych typów kluczy,
- usuwanie pojedynczych pozycji z historii,
- konfigurowalny limit historii.

> 📷 Miejsce na zrzut ekranu — ścieżki plików i kluczy

> 📷 Miejsce na zrzut ekranu — historia ostatnich plików/kluczy

> 📷 Miejsce na zrzut ekranu — przeciągnij i upuść

---

## ⚙️ Proces szyfrowania / deszyfrowania

Typowy proces szyfrowania:

1. Wybierz plik źródłowy.
2. Wybierz algorytm szyfrowania.
3. Skonfiguruj parametry algorytmu.
4. Wybierz plik klucza lub hasło, jeśli dany algorytm to obsługuje.
5. Rozpocznij szyfrowanie.
6. Aplikacja zapisze plik `.enc` zawierający wymagane metadane i zaszyfrowany payload.

Typowy proces deszyfrowania:

1. Wybierz plik `.enc`.
2. Aplikacja odczyta zapisane metadane.
3. Obsługiwane parametry algorytmu zostaną automatycznie odtworzone.
4. Podaj wymagany klucz lub hasło.
5. Rozpocznij deszyfrowanie.
6. Integralność zostanie zweryfikowana przed zapisaniem pliku końcowego.

> 📷 Miejsce na zrzut ekranu — proces szyfrowania

> 📷 Miejsce na zrzut ekranu — proces deszyfrowania

---

## ✍️ Proces podpisywania / weryfikowania

Typowy proces podpisywania:

1. Wybierz plik źródłowy.
2. Wybierz algorytm podpisu cyfrowego.
3. Wybierz klucz prywatny.
4. Utwórz podpis.
5. Zapisz wygenerowany plik `.sig`.

Typowy proces weryfikacji:

1. Wybierz oryginalny plik.
2. Wybierz plik podpisu.
3. Wybierz klucz publiczny.
4. Uruchom weryfikację.
5. Aplikacja poinformuje, czy podpis jest prawidłowy.

> 📷 Miejsce na zrzut ekranu — proces podpisywania

> 📷 Miejsce na zrzut ekranu — weryfikacja podpisu

---

## ⏳ Postęp, ETA i anulowanie

Długotrwałe operacje kryptograficzne raportują postęp za pomocą paska postępu aplikacji.

GUI zapewnia:

- postęp procentowy,
- ETA,
- możliwość anulowania,
- integrację z paskiem postępu na pasku zadań Windows,
- wskazanie błędu w przypadku niepowodzenia operacji.

Anulowanie jest sprawdzane podczas przetwarzania chunked.

> 📷 Miejsce na zrzut ekranu — aktywny postęp szyfrowania

> 📷 Miejsce na zrzut ekranu — postęp na pasku zadań Windows

---

## 🌐 Języki

Aplikacja obecnie obsługuje:

- angielski,
- polski.

Tłumaczenia są przechowywane w plikach JSON i ładowane dynamicznie.

Wybrany język jest zapisywany w ustawieniach aplikacji.

> 📷 Miejsce na zrzut ekranu — wybór języka

---

## 🎨 System motywów

Wbudowane motywy:

- Light
- Dark

Dodatkowe własne motywy mogą być automatycznie wykrywane z plików `.qss` znajdujących się w katalogu motywów.

Obecne własne motywy:

- Neon Green
- Arctic Cyan
- Shadow Monarch
- Windows 11

Po zmianie aktywnego motywu GUI ponownie oblicza geometrię layoutu, dzięki czemu motywy mogą bezpiecznie używać różnych fontów, paddingów, obramowań i rozmiarów kontrolek.

> 📷 Miejsce na zrzut ekranu — wybór motywu

---

## ⚙️ Ustawienia

Ustawienia aplikacji obejmują opcje związane z:

- językiem interfejsu,
- motywem aplikacji,
- podążaniem za motywem systemowym,
- zachowaniem bezpiecznego usuwania,
- liczbą przebiegów nadpisywania,
- rozmiarem historii.

Ustawienia są zapisywane za pomocą `QSettings`.

> 📷 Miejsce na zrzut ekranu — okno ustawień

---

## 🧰 Wymagania i instalacja

### Python

Zalecany jest Python 3.12.

### Instalacja zależności

Zainstaluj zależności z `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Uruchomienie ze źródeł

```bash
python main.py
```

---

## 📦 Budowanie aplikacji dla Windows

Do utworzenia aplikacji dla Windows można użyć PyInstaller.

Przykładowa komenda budowania:

```bash
python -m PyInstaller --windowed --icon="assets/icon.ico" --name="File Encryption & Decryption" --add-data="assets/icon.ico;assets" --add-data="resources/eff_large_wordlist.txt;resources" "main.py"
```

Lista słów EFF jest dołączana do aplikacji przez PyInstaller.

Katalogi `lang` i `theme` mogą pozostać zewnętrzne, dzięki czemu tłumaczenia i własne motywy QSS można modyfikować lub rozszerzać bez ponownego budowania pliku wykonywalnego.

Skrypt release/build może skopiować je obok wygenerowanej aplikacji przed utworzeniem końcowego archiwum ZIP.

---

## 📁 Struktura projektu

```text
file-encryption-system/
├── algorithms/
│   ├── base.py
│   ├── registry.py
│   ├── aes.py
│   ├── ascon.py
│   ├── serpent.py
│   ├── camellia.py
│   ├── des3.py
│   ├── chacha20.py
│   ├── salsa20.py
│   ├── threefish.py
│   ├── rsa.py
│   ├── eddsa.py
│   ├── ecdsa.py
│   ├── ml_kem.py
│   ├── ml_dsa.py
│   └── slh_dsa.py
├── gui/
│   ├── main_window.py
│   ├── widgets.py
│   ├── algorithm_info.py
│   ├── settings_dialog.py
│   ├── history_manager.py
│   ├── language_manager.py
│   ├── theme_manager.py
│   └── password_generator_dialog.py
├── resources/
│   └── eff_large_wordlist.txt
├── theme/
├── lang/
├── crypto_worker.py
├── key_generation_worker.py
├── file_format.py
├── key_manager.py
├── password_kdf.py
├── password_generator.py
└── main.py
```

---

## 🧠 Planowane ulepszenia

Możliwe kierunki dalszego rozwoju:

- Dodatkowe algorytmy AEAD i postkwantowe.
- Bardziej zaawansowana konfiguracja nonce, IV, tagu uwierzytelniającego i KDF.
- Dodatkowe KDF dla haseł, np. scrypt.
- Ulepszenie obsługi podpisów odłączonych i dodatkowe formaty podpisów.
- Dalsza optymalizacja operacji strumieniowych dla bardzo dużych plików.
- Wersjonowanie formatu pliku i dodatkowe mechanizmy kompatybilności wstecznej.
- Rozszerzenie testów automatycznych dla operacji kryptograficznych i obsługi formatu pliku.
- Więcej własnych motywów i opcji dostępności.
- Dodatkowe języki.
- Ulepszone pakowanie i dystrybucja wieloplatformowa.
- Dalsze rozdzielenie warstwy GUI, kryptografii, formatu pliku i narzędzi pomocniczych.

---

## 📄 Licencja

Copyright © 2026 Michał Rusek. Wszelkie prawa zastrzeżone.

O ile nie zaznaczono inaczej, kod źródłowy jest publicznie dostępny wyłącznie
do użytku prywatnego, niekomercyjnego oraz edukacyjnego.

Użycie komercyjne, redystrybucja, sublicencjonowanie oraz rozpowszechnianie
zmodyfikowanych wersji są zabronione bez uprzedniej pisemnej zgody autora.

Komponenty zewnętrzne podlegają własnym licencjom.

Szczegóły dotyczące licencji projektu znajdują się w pliku
[LICENSE](LICENSE), a informacje o licencjach komponentów zewnętrznych w
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

---

📌 **Autor:** *Michał Rusek (Vyroxes)*