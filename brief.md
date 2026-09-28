# BRIEF — Website Interaktif: XOR Stream Cipher & One-Time Pad

> Dokumen ini adalah instruksi lengkap untuk AI agent. Baca seluruhnya sebelum menulis kode. Semua yang dibutuhkan (spesifikasi tugas, desain, test case, pesan error) sudah ada di sini, jadi tidak perlu bertanya balik kecuali ada kontradiksi yang benar-benar memblokir.

---

## 0. Ringkasan

Bangun **satu aplikasi web statis** untuk tugas mini-proyek Kriptografi (presentasi + demo minggu depan). Topik kelompok: **XOR Stream Cipher dan One-Time Pad (OTP)**.

Aplikasi harus memungkinkan pengguna untuk:

1. Mengenkripsi pesan
2. Mendekripsi pesan
3. Melihat langkah-langkah penting algoritma (visualisasi XOR per karakter/bit)
4. Menjalankan test case dan melihat PASS/FAIL
5. Melihat demo satu serangan: **key/keystream reuse** (two-time pad)
6. Memahami syarat OTP

Penilaian dosen: (a) program berjalan benar, (b) kelompok bisa **menjelaskan cara kerja konsep**. Jadi UI harus **jelas secara edukatif**, cocok diproyeksikan di kelas, dan kodenya mudah dibaca serta dijelaskan oleh mahasiswa.

**Bahasa antarmuka: Bahasa Indonesia.** Istilah teknis (plaintext, ciphertext, keystream, XOR, OTP) boleh tetap dalam bahasa Inggris.

---

## 1. Batasan Teknis (WAJIB)

- **Vanilla only: HTML5 + CSS3 + JavaScript (ES2020).** Tanpa React/Vue/Tailwind/Bootstrap/jQuery, tanpa bundler, tanpa npm, tanpa build step.
- Harus bisa dijalankan dengan **double-click `index.html`** (protokol `file://`). Karena itu:
  - **Jangan pakai ES Modules** (`type="module"`, `import`/`export`). Pakai `<script defer src="...">` biasa dan satu namespace global `window.XorApp`.
  - Jangan pakai `fetch()` untuk file lokal.
- **Tanpa CDN JavaScript/CSS.** Satu-satunya resource eksternal yang boleh adalah Google Fonts (Inter + Geist Mono) lewat `<link>`, dan **semua font wajib punya fallback stack** agar tampilan tetap layak saat offline.
- Tanpa gambar eksternal. Semua visual dibuat dengan CSS/SVG inline.
- Jangan gunakan `localStorage`/`sessionStorage`. State cukup disimpan di memori.
- **Keamanan DOM:** input pengguna hanya boleh masuk ke DOM lewat `textContent` / `createElement`, **jangan `innerHTML` dengan data pengguna**.
- Random key memakai `crypto.getRandomValues` (bukan `Math.random`).

### Struktur file

```
/
├── index.html
├── css/
│   └── style.css
└── js/
    ├── cipher.js    # logika murni (tanpa DOM): XOR, validasi, hex, keystream
    ├── tests.js     # daftar test case + test runner (tanpa DOM)
    ├── attack.js    # logika murni serangan key reuse
    └── ui.js        # semua event handler & rendering DOM
```

Urutan `<script defer>` di `index.html`: `cipher.js` → `attack.js` → `tests.js` → `ui.js`.

**Pisahkan logika dari UI.** `cipher.js`, `attack.js`, `tests.js` tidak boleh menyentuh `document`. Ini yang membuat test case bisa memanggil fungsi yang sama persis dengan tombol Enkripsi/Dekripsi.

---

## 2. Spesifikasi Algoritma

### 2.1 Representasi data

- Plaintext dan key adalah **teks ASCII yang dapat dicetak (kode 32–126)**. Karakter lain (emoji, huruf beraksen, newline, tab, `€`, dll.) → error validasi.
- Setiap karakter → 1 byte (kode ASCII). Pesan dan key dikonversi ke array byte.
- **Ciphertext ditampilkan sebagai heksadesimal huruf besar, dipisah spasi**: `08 0A 1D 16`. (Hasil XOR bisa berupa byte non-printable, jadi tidak ditampilkan sebagai teks.)
- Input ciphertext untuk dekripsi menerima hex dengan atau tanpa spasi, huruf besar/kecil: `080A1D16` = `08 0a 1d 16`.
- Maksimal panjang pesan: **256 karakter**.

### 2.2 Keystream & dua mode

Pengguna memilih mode lewat segmented toggle (default: **Stream Cipher**):

| Mode | Keystream | Aturan |
|------|-----------|--------|
| **Stream Cipher** | Key diulang siklik sampai sepanjang pesan (`K[i mod len(K)]`). | Key boleh lebih pendek dari pesan. Jika key lebih pendek, tampilkan **peringatan** (bukan error): "Kunci diulang → keystream berpola, ini bukan OTP." |
| **One-Time Pad** | Key dipakai apa adanya. | Key **harus** ≥ panjang pesan, jika tidak → error (lihat §5). Jika key lebih panjang, hanya `n` byte pertama dipakai (tampilkan catatan). |

Tersedia tombol **"Acak kunci"** yang membuat key acak ASCII printable sepanjang pesan (panjang pesan saat ini; jika pesan kosong, gunakan 16) dengan `crypto.getRandomValues` (gunakan rejection sampling agar tidak bias pada rentang 95 karakter). Beri catatan kecil: *"Demo: karakter dibatasi ASCII printable agar mudah diketik. OTP sungguhan memakai byte acak penuh."*

### 2.3 Operasi

```
Enkripsi: C[i] = P[i] XOR KS[i]
Dekripsi: P[i] = C[i] XOR KS[i]      // operasi yang SAMA, karena (P XOR K) XOR K = P
```

### 2.4 API di `cipher.js` (`window.XorApp.cipher`)

Semua fungsi **tidak boleh throw**; kembalikan objek hasil.

```js
encrypt(plaintext, key, mode)      // -> { ok:true, cipherBytes, cipherHex, steps, warnings[] }
                                   //  | { ok:false, error:"❌ Error: ..." }
decrypt(cipherHex, key, mode)      // -> { ok:true, plainText, plainBytes, steps, warnings[] }
                                   //  | { ok:false, error:"❌ Error: ..." }
xorBytes(a, b)                     // XOR dua array byte (panjang = min)
buildKeystream(keyBytes, n, mode)
toHex(bytes)                       // "08 0A 1D 16"
parseHex(str)                      // -> { ok, bytes } | { ok:false, error }
generateRandomKey(length)          // string ASCII printable
validateText(str, label)           // cek karakter ASCII 32–126
```

`steps` = array objek per karakter untuk visualisasi:
`{ index, inputChar, inputDec, inputBin, keyChar, keyDec, keyBin, xorDec, xorBin, xorHex }`.

---

## 3. Pesan Validasi (Single Source of Truth)

Semua input yang salah harus menampilkan pesan yang berguna dan **tidak boleh membuat aplikasi crash**. Format pesan error selalu diawali `❌ Error:`; peringatan diawali `⚠ Peringatan:`. Pakai teks **persis** berikut (tes akan membandingkan string-nya):

| Kondisi | Pesan |
|---------|-------|
| Plaintext kosong | `❌ Error: Plaintext tidak boleh kosong.` |
| Ciphertext kosong | `❌ Error: Ciphertext tidak boleh kosong.` |
| Key kosong | `❌ Error: Silakan masukkan kunci.` |
| Key hanya spasi | `❌ Error: Kunci tidak boleh hanya berisi spasi.` |
| Karakter tidak didukung | `❌ Error: Karakter "€" (posisi 3) tidak didukung. Gunakan karakter ASCII yang dapat dicetak (kode 32–126).` *(karakter & posisi dinamis, posisi dihitung dari 1; berlaku untuk plaintext maupun key)* |
| Pesan > 256 karakter | `❌ Error: Pesan terlalu panjang (maksimal 256 karakter).` |
| Format hex salah (karakter non-hex, atau jumlah digit ganjil) | `❌ Error: Format ciphertext tidak valid. Gunakan pasangan digit heksadesimal (0–9, A–F), contoh: 08 0A 1D 16.` |
| Mode OTP, key terlalu pendek | `❌ Error: Mode OTP membutuhkan kunci minimal sepanjang pesan (10 karakter), sedangkan kunci Anda hanya 3 karakter.` *(angka dinamis)* |
| Hasil dekripsi mengandung byte di luar 32–126 | `⚠ Peringatan: Hasil dekripsi mengandung byte non-teks. Kemungkinan kunci salah atau mode tidak sesuai.` *(tetap tampilkan hasil; byte non-printable diganti `·`)* |
| Stream mode, key lebih pendek dari pesan | `⚠ Peringatan: Kunci diulang karena lebih pendek dari pesan. Ini bukan OTP dan lebih mudah diserang.` |

Perilaku UI untuk error:
- Tampilkan di area pesan tepat di bawah tombol, dengan `role="alert"` / `aria-live="polite"`.
- Tandai field bermasalah (border berubah warna error + `aria-invalid="true"`).
- Bersihkan error saat pengguna mulai mengetik ulang atau menekan tombol lagi.
- Urutan cek: kosong → karakter tidak didukung → panjang → aturan mode → proses.

---

## 4. Fitur Per Bagian

### 4.1 Enkripsi (Bagian 1 tugas)

Pengguna dapat: mengisi **Plaintext**, mengisi **Key**, memilih **mode**, menekan tombol **"Enkripsi"**, lalu melihat **Ciphertext (hex)**.

- Nilai awal placeholder/contoh boleh `HELLO` / `ABCDE` (ini contoh dari soal). **Jangan pakai pasangan ini di test case** (lihat §4.4).
- Tampilkan juga: panjang pesan, panjang key, panjang keystream.
- Tombol sekunder: **"Salin"** (copy hasil), **"Kirim ke Dekripsi"** (mengisi field ciphertext + key + mode di bagian dekripsi lalu scroll ke sana), **"Acak kunci"**.
- Hasil enkripsi otomatis mengisi **Visualisasi** (§4.3).

### 4.2 Dekripsi (Bagian 2 tugas)

Pengguna dapat: mengisi **Ciphertext (hex)**, **Key**, memilih **mode**, menekan **"Dekripsi"**, lalu melihat **Plaintext asli**.

- Pakai operasi XOR yang sama; tampilkan catatan kecil: *"Dekripsi = XOR ulang dengan keystream yang sama."*
- Jika key salah, hasil tetap ditampilkan (dengan `·` untuk byte non-printable) + peringatan dari §3. Ini juga bahan demo yang bagus di kelas.
- Hasil dekripsi otomatis mengisi **Visualisasi**.

### 4.3 Visualisasi Langkah Algoritma

Tampilkan dua hal:

**(a) Diagram alur** (HTML/CSS, bukan gambar), bergaya terminal, dua baris:

```
Plaintext  ─┐
            ├─▶  XOR  ─▶  Ciphertext
Keystream  ─┘

Ciphertext ─┐
            ├─▶  XOR  ─▶  Plaintext
Keystream  ─┘   (keystream yang SAMA)
```

**(b) Tabel langkah per karakter** (dari `steps`), kolom:
`#` | Karakter | ASCII (desimal) | Biner 8-bit | Karakter key | Biner key | Hasil XOR (biner) | Hex

- Bit hasil XOR bernilai `1` diberi warna aksen (Gold Leaf) agar terlihat bit mana yang berbeda; bit `0` diredam (Bone Gray). Ini boleh karena tabel ini berada **di dalam panel bergaya terminal**.
- Tombol **"Animasikan"**: menampilkan baris satu per satu (± 400 ms/baris) + tombol **"Langkah berikutnya"** untuk mode manual (berguna saat presentasi). Tombol **"Tampilkan semua"** mengembalikan semua baris. Hormati `prefers-reduced-motion` (langsung tampilkan semua).
- Jika baris > 32, tabel scroll di dalam container-nya sendiri (`overflow: auto`, `max-height`), jangan membuat halaman melebar.
- Panel kecil **"Kenapa XOR bisa dibalik?"**: tabel kebenaran XOR (`0⊕0=0, 0⊕1=1, 1⊕0=1, 1⊕1=0`) dan identitas `(P ⊕ K) ⊕ K = P`.

### 4.4 Test Cases (Bagian 3 tugas)

Sediakan tabel test case + tombol **"Jalankan semua tes"** (dan jalankan otomatis sekali saat halaman dimuat). Sebelum tabel, tampilkan alur:

```
Input → Algoritma → Output Anda → Output yang Diharapkan → PASS / FAIL
```

Kolom tabel: `#` | Deskripsi | Input (teks, key, mode) | Algoritma (Enkripsi/Dekripsi) | Output Anda | Output Diharapkan | Status.
Tampilkan ringkasan: `9 / 9 lulus`.

**Aturan penting:**
- **Nilai "Output Diharapkan" harus di-hardcode** sebagai literal (jangan dihitung oleh kode aplikasi, itu bukan pengujian).
- "Output Anda" **harus berasal dari fungsi asli** `encrypt`/`decrypt` di `cipher.js`, fungsi yang sama dengan tombol UI.
- Test case **berbeda dari contoh saat pengembangan** (`HELLO`/`ABCDE`/`KHOOR`). Jangan pakai itu di sini.
- Baris PASS diberi status hijau, FAIL merah (ikon + teks, jangan hanya warna).

**Daftar test case (semua sudah diverifikasi manual):**

| # | Deskripsi | Algoritma | Mode | Teks | Key | Output Diharapkan |
|---|-----------|-----------|------|------|-----|-------------------|
| 1 | Enkripsi dasar, huruf besar | Enkripsi | stream | `CODE` | `KEYS` | `08 0A 1D 16` |
| 2 | Enkripsi campuran huruf kapital/kecil | Enkripsi | otp | `Cat` | `Dog` | `07 0E 13` |
| 3 | Dekripsi | Dekripsi | stream | `18 14 05 15` | `Rust` | `Java` |
| 4 | Key pendek diulang (mode stream) | Enkripsi | stream | `AAAAAA` | `xy` | `39 38 39 38 39 38` |
| 5 | Edge case: plaintext = key → semua nol | Enkripsi | stream | `Test` | `Test` | `00 00 00 00` |
| 6 | Karakter spasi, angka, simbol | Enkripsi | otp | `Hi 5` | `7Q!z` | `7F 38 01 4F` |
| 7 | Validasi: key kosong | Enkripsi | stream | `Hello` | *(kosong)* | `❌ Error: Silakan masukkan kunci.` |
| 8 | Validasi: hex tidak valid | Dekripsi | stream | `0G 12` | `abc` | `❌ Error: Format ciphertext tidak valid. Gunakan pasangan digit heksadesimal (0–9, A–F), contoh: 08 0A 1D 16.` |
| 9 | Validasi: key OTP terlalu pendek | Enkripsi | otp | `Halo Dunia` | `abc` | `❌ Error: Mode OTP membutuhkan kunci minimal sepanjang pesan (10 karakter), sedangkan kunci Anda hanya 3 karakter.` |

Struktur data test (di `tests.js`):

```js
{ id: 1, description: "...", op: "encrypt"|"decrypt", mode: "stream"|"otp",
  input: "CODE", key: "KEYS", expected: "08 0A 1D 16" }
```

Tambahkan juga kemampuan **"Tambah test case sendiri"** *(opsional, prioritas rendah)*: form kecil untuk mencoba input + expected sendiri, agar bisa didemokan saat presentasi.

### 4.5 Fitur Keamanan / Serangan (Bagian 5 tugas): Key Reuse

Bagian ini membuktikan mengapa **menggunakan ulang keystream itu berbahaya**.

**Input:** Pesan 1, Pesan 2, **satu Key yang sama**. Default contoh (sama panjang, 15 karakter, dan ada bagian yang identik agar kebocoran terlihat):
- Pesan 1: `SERANG DI FAJAR`
- Pesan 2: `MUNDUR DI SENJA`
- Key: `kunci-rahasia-01`

**Tampilkan langkah bertahap (P0, wajib):**

1. `C1 = M1 ⊕ K`  (hex)
2. `C2 = M2 ⊕ K`  (hex), **key yang sama**
3. Penyerang hanya melihat C1 dan C2, lalu menghitung `C1 ⊕ C2`  (hex)
4. Sebagai bukti, hitung terpisah `M1 ⊕ M2` (hex) dan tampilkan indikator **`C1 ⊕ C2 = M1 ⊕ M2 ✓ IDENTIK`**. Key **hilang** dari persamaan.
5. Sorot byte `00` pada `C1 ⊕ C2`: itu posisi di mana kedua pesan memakai karakter yang sama (di contoh: ` DI `). Beri penjelasan satu kalimat: *"Byte 00 membocorkan bahwa kedua pesan identik di posisi tersebut."*
6. Jika panjang pesan berbeda, XOR hanya sampai panjang terpendek dan tampilkan catatan.
7. Kotak kesimpulan: *"Tanpa mengetahui key, penyerang sudah memperoleh hubungan langsung antar dua pesan. Jika satu pesan bisa ditebak, pesan lainnya terbuka."*

**Tambahan (P1, sebaiknya ada):** **Crib dragging sederhana.**
- Input "Tebakan kata di Pesan 1" (mis. `SERANG`). Aplikasi menggeser tebakan itu ke setiap posisi, meng-XOR dengan `C1 ⊕ C2`, dan menampilkan fragmen kemungkinan Pesan 2 di tiap posisi. Fragmen yang seluruhnya printable ASCII disorot (hasil bermakna kemungkinan besar di posisi yang benar).
- Tombol **"Jika Pesan 1 diketahui penuh"**: tampilkan `M2 = C1 ⊕ C2 ⊕ M1` dan hasilnya terbaca utuh.

**Tambahan (P2, opsional):** toggle **"Pakai key berbeda (OTP yang benar)"**: buat dua key acak berbeda, lalu tampilkan bahwa `C1 ⊕ C2 ≠ M1 ⊕ M2` sehingga serangan gagal.

Validasi bagian ini: pesan/key kosong, karakter non-ASCII, dan pesan > 256 karakter memakai pesan error di §3.

### 4.6 Bagian OTP (syarat tambahan dari soal)

Bagian singkat berisi 4 syarat OTP sebagai **daftar vertikal** (bukan grid kartu), masing-masing dengan ikon check-outline, judul, dan satu kalimat penjelasan:

1. **Key benar-benar acak:** Key dibuat dari sumber acak sejati; pola pada key membuka celah analisis.
2. **Key minimal sepanjang pesan:** Key yang lebih pendek harus diulang, lalu keystream berpola.
3. **Key dirahasiakan:** Keamanan bergantung sepenuhnya pada kerahasiaan key.
4. **Key tidak pernah dipakai ulang:** Reuse melahirkan serangan two-time pad (lihat bagian Serangan).

Tambahkan **"Pemeriksa OTP"** kecil yang menilai key dan pesan yang sedang ada di form Enkripsi (P1):

| Syarat | Cara cek di aplikasi |
|--------|----------------------|
| Panjang key ≥ pesan | Otomatis: ✓ / ✗ |
| Key acak | ✓ jika key dibuat lewat tombol "Acak kunci" dan belum diubah; selain itu "Tidak dapat diverifikasi" |
| Key rahasia | Tidak dapat diverifikasi aplikasi (tampilkan sebagai pengingat) |
| Key belum pernah dipakai | Aplikasi mengingat key yang sudah dipakai enkripsi **dalam sesi (memori saja)**; jika key yang sama dipakai lagi untuk pesan berbeda → ✗ dengan peringatan |

Tambahkan satu paragraf ringkas: OTP yang memenuhi keempat syarat bersifat aman secara teoritis (perfect secrecy, Shannon), tetapi tidak praktis karena distribusi key sepanjang pesan.

Tidak perlu membuat sistem RNG kompleks (sesuai soal). `crypto.getRandomValues` sudah cukup.

---

## 5. Struktur Halaman (satu halaman, scroll vertikal)

Urutan section (semua punya `id` untuk anchor nav):

1. **Announcement banner** — teks: `Proyek Mini Kriptografi · XOR Stream Cipher & One-Time Pad · [NAMA KELOMPOK]` (placeholder jelas agar mudah diganti).
2. **Top navigation** (sticky) — brand + link anchor: Enkripsi · Dekripsi · Visualisasi · Test Cases · Serangan · OTP. Di kanan: tombol filled "Jalankan Tes" → `#tests`.
3. **Hero** — headline, sub-headline, CTA, mockup terminal.
4. `#enkripsi`
5. `#dekripsi`
6. `#visualisasi`
7. `#tests`
8. `#serangan`
9. `#otp`
10. **Footer** — nama kelompok/anggota (placeholder), mata kuliah, catatan "Hanya untuk tujuan edukasi. Jangan pakai untuk mengamankan data nyata."

**Hero:**
- Headline (68px): `Enkripsi dengan satu operasi: XOR.`
- Sub-headline: `Pelajari cara kerja stream cipher dan One-Time Pad, lalu lihat sendiri mengapa key tidak boleh dipakai dua kali.`
- CTA: tombol filled **"Mulai enkripsi ↓"** (ke `#enkripsi`) + ghost link **"Lihat serangan"** (ke `#serangan`).
- Di bawah CTA, satu baris bergaya terminal dengan prompt hijau (#7ba564): `$ xor "HELLO" --key "ABCDE"`. Dekoratif saja.
- Sisi kanan: **mockup terminal** yang menampilkan alur plaintext ⊕ keystream = ciphertext (statis, boleh dianimasikan ringan). Ini **satu-satunya elemen** yang boleh memakai glow biru (`--shadow-glow`).

Layout desktop: dua kolom pada hero (teks maks ±520px). Bagian Enkripsi dan Dekripsi boleh berdampingan pada layar ≥ 960px (dua panel terminal), lalu bertumpuk di layar kecil. Section lain: tumpukan vertikal (heading + panel).

---

## 6. Desain Visual

**Konsep: "Moonlit terminal behind amber glass".** Ruang kendali gelap yang hangat: kanvas hampir hitam kecoklatan, tipografi geometris rapat, permukaan datar tanpa bayangan dekoratif. Warna aksen dijatah ketat.

### 6.1 Design tokens (salin ke `:root` di `style.css`)

```css
:root {
  /* Neutrals (semuanya hangat, tidak ada abu kebiruan) */
  --color-warm-off-white: #faf9f6;  /* teks utama, tombol utama */
  --color-pale-stone:     #b4b4b2;  /* teks tersier, label ghost */
  --color-bone-gray:      #868684;  /* teks sekunder, caption */
  --color-faint-linen:    #e3e2e0;  /* outline state terpilih (pakai hemat) */
  --color-slate-hearth:   #40403f;  /* modal/floating */
  --color-iron-veil:      #383838;  /* hover/kontrol, hairline, chrome bar */
  --color-smoke-charcoal: #2f2f2f;  /* kartu, panel terminal */
  --color-smoked-onyx:    #1e1e1d;  /* footer, band section, latar input */
  --color-deep-ember:     #121212;  /* kanvas halaman */
  --color-ink-black:      #080808;
  --color-absolute:       #000000;  /* nav, banner */

  /* Aksen: HANYA di dalam konteks terminal/kode + heading section */
  --color-gold-leaf:      #bd9f65;  /* string, bit hasil, nilai penting */
  --color-muted-cobalt:   #6f839f;  /* identifier, heading section */

  /* Warna status fungsional (pengecualian kecil, lihat 6.3) */
  --color-status-pass:    #7ba564;
  --color-status-error:   #ff5f57;
  --color-status-warn:    #febc20;

  /* Surface */
  --surface-canvas:   #121212;
  --surface-band:     #1e1e1d;
  --surface-card:     #2f2f2f;
  --surface-elevated: #383838;
  --surface-floating: #40403f;

  /* Font */
  --font-sans: 'Inter', ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-mono: 'Geist Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;

  /* Radius */
  --radius-button: 4px;
  --radius-nav: 4px;
  --radius-card: 8px;
  --radius-image: 20px;

  /* Spasi (kelipatan 2 dan 10) */
  --space-4: 4px;   --space-8: 8px;   --space-10: 10px;  --space-12: 12px;
  --space-16: 16px; --space-24: 24px; --space-32: 32px;  --space-40: 40px;
  --space-64: 64px;

  /* Layout */
  --page-max: 1200px;
  --section-gap: clamp(80px, 10vw, 120px);
  --card-padding: 24px;

  /* Glow: HANYA untuk mockup terminal di hero */
  --shadow-glow: 0 0 32px 10px rgba(33, 126, 255, 0.5);
}
```

### 6.2 Tipografi

Font asli desain (Matter) berlisensi, jadi pakai **Inter** sebagai pengganti (weight 400 & 500 saja) dengan nilai tracking yang sama. Font mono: **Geist Mono**. Aktifkan `font-feature-settings: "tnum" on` untuk angka.

| Peran | Ukuran | Line-height | Letter-spacing |
|-------|--------|-------------|----------------|
| display (hero H1) | 68px → `clamp(40px, 7vw, 68px)` | 1.0 | -2.04px (-0.03em) |
| heading-lg (judul section) | 48px → `clamp(32px, 5vw, 48px)` | 1.1 | -1.44px |
| heading | 32px | 1.19 | -0.64px |
| heading-sm | 24px | 1.2 | -0.48px |
| subheading | 20px | 1.3 | -0.2px |
| body | 16px | 1.38 | 0.16px |
| body-sm | 14px | 1.38 | 0.14px |
| caption-tracked (eyebrow, HURUF KAPITAL) | 11px | 1.2 | 2.2px (0.2em) |

Ukuran teks minimum di UI interaktif: 14px (proyektor kelas!). Jangan pakai teks 11px kecuali untuk eyebrow.

### 6.3 Aturan warna

- Kanvas halaman `#121212`. Teks utama `#faf9f6`. **Jangan pernah pakai `#ffffff`** sebagai warna teks.
- Teks sekunder `#868684` (caption), tersier/deskripsi `#b4b4b2`.
- **Gold Leaf `#bd9f65` dan Muted Cobalt `#6f839f`** hanya untuk: isi panel terminal (hex, bit, string, identifier) dan **heading section**. Jangan untuk tombol, badge, tag, atau chrome UI.
- **Tidak ada warna CTA berwarna.** Tombol utama = fill `#faf9f6` + teks `#121212`.
- **Pengecualian fungsional (dibatasi):** PASS = `#7ba564`, error/FAIL = `#ff5f57`, peringatan = `#febc20`. Dipakai **hanya** untuk teks/ikon/border-kiri status yang kecil, **bukan fill area besar**. Selalu sertakan ikon atau kata (✓ PASS, ✗ FAIL, ❌, ⚠), jangan mengandalkan warna saja.
- Hairline/divider memakai `#383838` (bukan `#e3e2e0`, yang terlalu terang di kanvas gelap). `#e3e2e0` hanya untuk outline elemen terpilih/fokus dengan opasitas rendah.
- **Tanpa drop shadow** pada kartu, tombol, atau modal. Hanya `--shadow-glow` pada mockup hero.

### 6.4 Komponen

- **Tombol utama (filled):** bg `#faf9f6`, teks `#121212`, Inter 500 16px, radius **4px**, padding `10px 16px`, tanpa border/shadow. Boleh disertai ikon panah 16px. **Jangan pill/rounded penuh.** Hover: turun sedikit ke `#e3e2e0`. Fokus: outline 2px `#faf9f6` offset 2px.
- **Tombol ghost:** transparan, teks `#faf9f6` 14–16px, tanpa border; hover teks jadi `#b4b4b2`. Pasangkan dengan tombol filled, **jangan menumpuk dua tombol filled** dalam satu grup aksi.
- **Tombol sekunder** (Acak kunci, Salin, dsb.): bg `#383838`, teks `#faf9f6`, radius 4px; hover `#40403f`. Tidak boleh dijadikan CTA utama.
- **Panel terminal (wadah utama tiap section fungsional):** radius 8px, body `#2f2f2f`, bar judul `#383838` setinggi 32px dengan tiga lingkaran 10px (`#ff5f57`, `#febc20`, `#28c840`) di kiri dan judul panel di tengah/kiri (mono 12px, `#b4b4b2`). Padding isi 20–24px. Isi hasil (hex, tabel, output) memakai Geist Mono, dasar `#faf9f6`, sorotan `#bd9f65`, identifier/label `#6f839f`.
- **Input/textarea:** bg `#1e1e1d`, border 1px `#383838`, radius 4px, teks `#faf9f6` di Geist Mono 16px, placeholder `#868684`. Fokus: border `#b4b4b2` + outline `#faf9f6` tipis (tanpa glow). State error: border `#ff5f57`. Label di atas field memakai gaya eyebrow (11px, kapital, tracking 2.2px, `#b4b4b2`), di ukuran layar kecil boleh 12px.
- **Segmented toggle mode:** dua opsi, bg `#1e1e1d`, opsi aktif fill `#383838` + teks `#faf9f6`, radius 4px. Accessible (`role="radiogroup"`, panah kiri/kanan).
- **Kotak hasil:** bg `#1e1e1d`, border `#383838`, mono, `word-break: break-all`, tombol Salin di pojok kanan atas.
- **Pesan error/peringatan:** blok dengan border-kiri 2px warna status, bg `#1e1e1d`, teks `#faf9f6` (ikon/prefix berwarna status).
- **Tabel:** header eyebrow-style `#868684`, baris dipisah hairline `#383838`, tanpa zebra ramai, angka `tnum`.
- **Badge status test:** teks kecil kapital mono dengan ikon (✓ PASS / ✗ FAIL), tanpa fill besar.
- **Heading section:** eyebrow (mis. `01 · ENKRIPSI`) + heading-lg berwarna `#6f839f` (rata kiri), deskripsi `#b4b4b2` maks ±60ch.
- **Nav:** bg `#000`, radius 4px pada containernya, tinggi ±56px, brand teks/glyph `XOR` di `#faf9f6`. Sticky dengan `top: 0` dan `z-index` tinggi. Link aktif (scroll-spy sederhana, opsional) berwarna `#faf9f6`, lainnya `#b4b4b2`.
- **Banner:** bg `#000`, teks 12–14px `#faf9f6` terpusat, border-bawah 1px `#2f2f2f`.
- **Footer:** bg `#1e1e1d`, link 14px `#b4b4b2`, header kolom `#868684`.
- **Ikon:** SVG inline, outline tipis (stroke 1.5px), monokrom `#faf9f6`. Tanpa ikon berwarna/bulat/penuh.

### 6.5 Ritme & layout

- Container maks 1200px, tengah. Jarak antar-section 80–120px. Jarak antar-elemen kecil memakai kelipatan 10 (`10px`, `20px`) atau 2 (`8`, `12`, `16`, `24`); jangan 15px/18px.
- Latar hero: gradien radial hangat yang sangat halus (mis. `#1e1e1d` → `#121212`) sebagai pengganti foto lanskap. **Tanpa gambar.**
- Selang-seling band `#121212` / `#1e1e1d` antar-section boleh dipakai.

### 6.6 Aksesibilitas & responsif

- Kontras teks memadai di atas kanvas gelap; semua kontrol dapat dijangkau keyboard dengan fokus terlihat.
- `<label for>` untuk setiap input; region hasil pakai `aria-live="polite"`; error pakai `role="alert"`.
- `<html lang="id">`. Landmark semantik: `header`, `nav`, `main`, `section` (dengan `aria-labelledby`), `footer`.
- Responsif: desktop (≥960px), tablet, ponsel (≥360px). Tidak ada scroll horizontal pada `body`; tabel dan hex panjang scroll di dalam containernya.
- Hormati `prefers-reduced-motion`. Animasi seminimal mungkin dan fungsional.

---

## 7. Kualitas Kode

- Kode **mudah dibaca mahasiswa dan dijelaskan saat presentasi**: fungsi kecil, nama jelas (identifier bahasa Inggris), **komentar dalam Bahasa Indonesia** pada bagian inti (XOR, pembangunan keystream, parsing hex, penyerangan).
- Tidak ada variabel global liar selain `window.XorApp`.
- Tidak ada `eval`, tidak ada `innerHTML` dengan input pengguna.
- Hindari duplikasi logika: enkripsi dan dekripsi berbagi `xorBytes` + `buildKeystream`.
- Seluruh string pesan error terkumpul di satu objek konstanta di `cipher.js` (mis. `XorApp.MESSAGES`).
- Tidak ada `console.error` saat kondisi normal; tidak ada exception yang lolos ke pengguna. Bungkus handler UI dengan `try/catch` sebagai jaring pengaman terakhir dan tampilkan pesan umum: `❌ Error: Terjadi kesalahan tak terduga. Muat ulang halaman dan coba lagi.`

---

## 8. Definition of Done (checklist penerimaan)

**Sesuai instruksi tugas:**
- [ ] (1) Enkripsi: isi plaintext + key → klik "Enkripsi" → ciphertext hex muncul
- [ ] (2) Dekripsi: isi ciphertext + key → klik "Dekripsi" → plaintext asli muncul; round-trip enkripsi→dekripsi selalu kembali ke plaintext awal
- [ ] (3) ≥ 3 test case (di sini 9), menampilkan alur Input → Algoritma → Output Anda → Diharapkan → PASS/FAIL, semuanya PASS, dan **berbeda dari contoh HELLO/ABCDE**
- [ ] (4) Validasi: plaintext kosong, key kosong, key tidak valid (hanya spasi), format hex salah, karakter tidak didukung, OTP key pendek → pesan jelas, tanpa crash
- [ ] (5) Fitur serangan key reuse: `C1 ⊕ C2 = M1 ⊕ M2` terbukti di layar
- [ ] (6) UI rapi, terorganisir, interaktif, terbaca di proyektor
- [ ] Bagian OTP dengan 4 syarat (acak, ≥ panjang pesan, rahasia, tidak dipakai ulang)
- [ ] Visualisasi XOR per karakter/bit

**Teknis:**
- [ ] Berjalan dengan double-click `index.html` (tanpa server, tanpa internet selain font opsional)
- [ ] Hanya HTML/CSS/JS vanilla, tanpa dependensi
- [ ] Tidak ada error di console pada penggunaan normal
- [ ] Tampilan sesuai design tokens (§6) dan tidak melanggar daftar larangan (§9)
- [ ] Keyboard-friendly dan responsif

**Uji manual sebelum menyerahkan (agent wajib menjalankan atau menelusuri secara mental):**
- [ ] Enkripsi `CODE` + `KEYS` = `08 0A 1D 16`; dekripsi hasil itu dengan `KEYS` → `CODE`
- [ ] Enkripsi `Halo Dunia` + `abc` di mode OTP → error panjang key
- [ ] Dekripsi dengan key salah → peringatan non-teks, tidak crash
- [ ] Input emoji `😀` → error karakter tidak didukung
- [ ] Pesan 257 karakter → error terlalu panjang
- [ ] Pada demo serangan default, `C1 ⊕ C2` memiliki empat byte `00` berurutan di posisi 7–10

---

## 9. Larangan

- ❌ Framework/library/CDN JS, ES Modules, build tools
- ❌ Warna aksen cerah baru (biru/ungu/hijau sebagai warna brand), warna CTA berwarna
- ❌ `#ffffff` sebagai warna teks
- ❌ Drop shadow dekoratif (selain glow tunggal di mockup hero)
- ❌ Tombol pill/rounded penuh
- ❌ Ikon berwarna atau berisi/tebal; ilustrasi, render 3D, foto stok
- ❌ Menghitung "Output Diharapkan" test case dengan kode aplikasi
- ❌ `innerHTML` dengan input pengguna; `Math.random` untuk key
- ❌ Memakai `HELLO/ABCDE/KHOOR` sebagai test case
- ❌ Mengklaim implementasi ini aman untuk data nyata

---

## 10. Format Laporan Akhir dari Agent

Setelah selesai, balas ringkas (maks ±15 baris):

1. Daftar file yang dibuat dan cara membukanya.
2. Ringkasan singkat cara kerja tiap file (agar mahasiswa bisa menjelaskan saat presentasi).
3. Daftar keputusan/asumsi yang kamu ambil (mis. hex sebagai format ciphertext, dua mode, batas 256 karakter).
4. Hasil uji manual pada checklist §8.
5. Bagian mana yang tidak sempat dibuat (P1/P2), jika ada.

Jangan menempelkan seluruh kode ke dalam laporan.
