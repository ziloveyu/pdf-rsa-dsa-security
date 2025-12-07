🔒 SecureDoc: Enkripsi Dokumen Hibrida (RSA+AES) & Tanda Tangan Digital (DSA)
SecureDoc adalah aplikasi desktop berbasis Python yang dirancang untuk mengamankan pertukaran dokumen rahasia (khususnya PDF). Aplikasi ini menjamin Kerahasiaan (Confidentiality) dan Otentikasi (Authentication) sekaligus dalam satu alur kerja yang mudah digunakan melalui antarmuka GUI Tkinter.

🚀 Fitur Utama
Sistem ini menerapkan mekanisme kriptografi ganda:

Manajemen Kunci (Key Management)

Pembangkitan kunci asimetris ganda: RSA-2048 (untuk enkripsi) dan DSA-2048 (untuk tanda tangan digital).

Penyimpanan kunci privat dan publik secara terpisah untuk simulasi Pengirim dan Penerima.

Mode Pengirim (Encrypt & Sign)

Digital Signature: Dokumen ditandatangani menggunakan DSA Private Key (Hashing SHA-256) untuk menjamin keaslian pengirim.

Hybrid Encryption: Dokumen dienkripsi menggunakan AES-128 (Mode EAX) untuk kecepatan, kemudian kunci sesi AES tersebut dibungkus (dienkripsi) menggunakan RSA Public Key penerima.

Mode Penerima (Decrypt & Verify)

Dekripsi: Membuka kunci sesi menggunakan RSA Private Key, lalu mendekripsi dokumen asli.

Verifikasi: Memastikan dokumen tidak dimanipulasi di tengah jalan dengan memvalidasi tanda tangan menggunakan DSA Public Key pengirim.

Indikator Status: Notifikasi visual (Hijau/Merah) untuk status validitas dokumen.

🛠️ Teknologi yang Digunakan
Language: Python 3.x

GUI: Tkinter (Bawaan Python)

Cryptography Library: PyCryptodome
