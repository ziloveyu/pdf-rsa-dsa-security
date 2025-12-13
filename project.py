import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistem RSA (Enkripsi) & DSA (Tanda Tangan) by Kelompok 4")
        self.root.geometry("750x600")

        # Tab Control
        tabControl = ttk.Notebook(root)
        
        self.tab1 = ttk.Frame(tabControl)
        self.tab2 = ttk.Frame(tabControl)
        self.tab3 = ttk.Frame(tabControl)
        
        tabControl.add(self.tab1, text='1. Buat Kunci (RSA & DSA)')
        tabControl.add(self.tab2, text='2. Kirim (Encrypt RSA & Sign DSA)')
        tabControl.add(self.tab3, text='3. Terima (Decrypt RSA & Verify DSA)')
        tabControl.pack(expand=1, fill="both")

        self.setup_tab1()
        self.setup_tab2()
        self.setup_tab3()

# halaman tab 1
    def setup_tab1(self):
        frame = ttk.LabelFrame(self.tab1, text="Pembuatan Kunci Ganda")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="Nama User:").pack(pady=5)
        self.key_name_entry = ttk.Entry(frame)
        self.key_name_entry.pack(pady=5)

        ttk.Button(frame, text="Generate Keys (RSA + DSA)", command=self.generate_keys).pack(pady=20)
        self.log_tab1 = tk.Text(frame, height=15, width=70)
        self.log_tab1.pack(pady=5)

    def generate_keys(self):
        name = self.key_name_entry.get()
        if not name:
            messagebox.showerror("Error", "Masukkan nama user!")
            return

        self.log_tab1.delete(1.0, tk.END)
        self.log_tab1.insert(tk.END, "Sedang membuat kunci, mohon tunggu...\n")
        self.root.update()

        try:
            # 1. Generate RSA Key (Untuk Enkripsi)
            rsa_key = RSA.generate(2048)
            with open(f'{name}_RSA_private.pem', 'wb') as f:
                f.write(rsa_key.export_key())
            with open(f'{name}_RSA_public.pem', 'wb') as f:
                f.write(rsa_key.publickey().export_key())

            # 2. Generate DSA Key (Untuk Tanda Tangan)
            dsa_key = DSA.generate(2048)
            with open(f'{name}_DSA_private.pem', 'wb') as f:
                f.write(dsa_key.export_key())
            with open(f'{name}_DSA_public.pem', 'wb') as f:
                f.write(dsa_key.publickey().export_key())

            self.log_tab1.insert(tk.END, f"SUKSES! 4 File Kunci dibuat untuk {name}:\n")
            self.log_tab1.insert(tk.END, f"1. {name}_RSA_private.pem (Rahasia - Dekripsi)\n")
            self.log_tab1.insert(tk.END, f"2. {name}_RSA_public.pem (Sebar - Enkripsi)\n")
            self.log_tab1.insert(tk.END, f"3. {name}_DSA_private.pem (Rahasia - Tanda Tangan)\n")
            self.log_tab1.insert(tk.END, f"4. {name}_DSA_public.pem (Sebar - Verifikasi)\n")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

#  halaman tab 2
    def setup_tab2(self):
        frame = ttk.LabelFrame(self.tab2, text="Pengirim: Sign (DSA) lalu Encrypt (RSA)")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        # File PDF
        ttk.Button(frame, text="1. Pilih File PDF", command=self.select_file_pdf_enc).pack(pady=2)
        self.lbl_pdf_enc = ttk.Label(frame, text="File: -", foreground="blue")
        self.lbl_pdf_enc.pack()

        # Kunci DSA Private (Untuk Sign)
        ttk.Button(frame, text="2. Pilih Private Key DSA PENGIRIM (Sign)", command=self.select_dsa_priv).pack(pady=2)
        self.lbl_dsa_priv = ttk.Label(frame, text="DSA Priv Key: -", foreground="red")
        self.lbl_dsa_priv.pack()

        # Kunci RSA Public (Untuk Encrypt)
        ttk.Button(frame, text="3. Pilih Public Key RSA PENERIMA (Encrypt)", command=self.select_rsa_pub).pack(pady=2)
        self.lbl_rsa_pub = ttk.Label(frame, text="RSA Pub Key: -", foreground="green")
        self.lbl_rsa_pub.pack()

        ttk.Button(frame, text="EKSEKUSI: Sign & Encrypt", command=self.process_encryption).pack(pady=15)
        self.log_tab2 = tk.Text(frame, height=8, width=70)
        self.log_tab2.pack(pady=5)

    def select_file_pdf_enc(self):
        self.file_path_enc = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        self.lbl_pdf_enc.config(text=os.path.basename(self.file_path_enc))

    def select_dsa_priv(self): # Sender DSA Private
        self.path_dsa_priv = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.lbl_dsa_priv.config(text=os.path.basename(self.path_dsa_priv))

    def select_rsa_pub(self): # Receiver RSA Public
        self.path_rsa_pub = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.lbl_rsa_pub.config(text=os.path.basename(self.path_rsa_pub))

    def process_encryption(self):
        try:
            # Baca PDF
            with open(self.file_path_enc, 'rb') as f:
                pdf_data = f.read()

            # --- PROSES 1: DSA SIGNATURE ---
            # Hash file dulu
            h = SHA256.new(pdf_data)
            # Load DSA Private Key
            with open(self.path_dsa_priv, 'rb') as k:
                dsa_key = DSA.import_key(k.read())
            # Buat signer object
            signer = DSS.new(dsa_key, 'fips-186-3')
            signature = signer.sign(h)

            # --- PROSES 2: RSA ENCRYPTION (Hybrid) ---
            # Buat kunci sesi AES
            session_key = get_random_bytes(16)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(pdf_data)

            # Enkripsi kunci AES dengan RSA Public Key Penerima
            with open(self.path_rsa_pub, 'rb') as k:
                rsa_key = RSA.import_key(k.read())
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            # Simpan Output
            base_name = os.path.basename(self.file_path_enc)
            
            with open(f"enc_{base_name}", 'wb') as f:
                [f.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]
            
            with open(f"key_{base_name}.bin", 'wb') as f:
                f.write(enc_session_key)

            with open(f"sig_{base_name}.dsa", 'wb') as f:
                f.write(signature)

            self.log_tab2.insert(tk.END, "Sukses!\nFile terenkripsi, kunci sesi, dan signature DSA telah dibuat.\n")

        except Exception as e:
            messagebox.showerror("Gagal", str(e))

# halaman tab 3
    def setup_tab3(self):
        frame = ttk.LabelFrame(self.tab3, text="Penerima: Decrypt (RSA) lalu Verify (DSA)")
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        # File Inputs
        btn_frame = ttk.Frame(frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame, text="File Encrypted (enc_...)", command=self.sel_file_dec).grid(row=0, column=0, padx=5)
        self.lbl_file_dec = ttk.Label(btn_frame, text="-")
        self.lbl_file_dec.grid(row=0, column=1)

        ttk.Button(btn_frame, text="File Key (key_...)", command=self.sel_key_dec).grid(row=1, column=0, padx=5)
        self.lbl_key_dec = ttk.Label(btn_frame, text="-")
        self.lbl_key_dec.grid(row=1, column=1)

        ttk.Button(btn_frame, text="File Sig (sig_...)", command=self.sel_sig_dec).grid(row=2, column=0, padx=5)
        self.lbl_sig_dec = ttk.Label(btn_frame, text="-")
        self.lbl_sig_dec.grid(row=2, column=1)

        # Keys Input
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=10)
        
        ttk.Button(frame, text="Pilih Private Key RSA PENERIMA (Decrypt)", command=self.sel_rsa_priv).pack()
        self.lbl_rsa_priv = ttk.Label(frame, text="RSA Priv Key: -", foreground="green")
        self.lbl_rsa_priv.pack()

        ttk.Button(frame, text="Pilih Public Key DSA PENGIRIM (Verify)", command=self.sel_dsa_pub).pack()
        self.lbl_dsa_pub = ttk.Label(frame, text="DSA Pub Key: -", foreground="red")
        self.lbl_dsa_pub.pack()

        ttk.Button(frame, text="EKSEKUSI: Decrypt & Verify", command=self.process_decryption).pack(pady=20)
        self.status_label = ttk.Label(frame, text="Status: Menunggu...", font=("Arial", 12, "bold"))
        self.status_label.pack()

    def sel_file_dec(self): 
        self.path_f_dec = filedialog.askopenfilename()
        self.lbl_file_dec.config(text=os.path.basename(self.path_f_dec))
    def sel_key_dec(self): 
        self.path_k_dec = filedialog.askopenfilename()
        self.lbl_key_dec.config(text=os.path.basename(self.path_k_dec))
    def sel_sig_dec(self): 
        self.path_s_dec = filedialog.askopenfilename()
        self.lbl_sig_dec.config(text=os.path.basename(self.path_s_dec))
    def sel_rsa_priv(self): 
        self.path_rsa_priv = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.lbl_rsa_priv.config(text=os.path.basename(self.path_rsa_priv))
    def sel_dsa_pub(self): 
        self.path_dsa_pub = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        self.lbl_dsa_pub.config(text=os.path.basename(self.path_dsa_pub))

    def process_decryption(self):
        try:
            # --- PROSES 1: DEKRIPSI RSA & AES ---
            # Buka Private Key RSA Penerima
            with open(self.path_rsa_priv, 'rb') as k:
                rsa_key = RSA.import_key(k.read())
            
            # Decrypt AES Session Key
            with open(self.path_k_dec, 'rb') as f:
                enc_session_key = f.read()
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

            # Decrypt File PDF
            with open(self.path_f_dec, 'rb') as f:
                nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            decrypted_pdf = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Simpan sementara
            with open("hasil_dekripsi_dsa.pdf", "wb") as f:
                f.write(decrypted_pdf)

            # --- PROSES 2: VERIFIKASI DSA ---
            # Hash hasil dekripsi
            h = SHA256.new(decrypted_pdf)
            
            # Load Public Key DSA Pengirim
            with open(self.path_dsa_pub, 'rb') as k:
                dsa_key = DSA.import_key(k.read())
            
            # Load Signature File
            with open(self.path_s_dec, 'rb') as f:
                signature = f.read()

            # Verifikasi
            verifier = DSS.new(dsa_key, 'fips-186-3')
            try:
                verifier.verify(h, signature)
                self.status_label.config(text="SUKSES: Valid (DSA) & Terdekripsi (RSA)", foreground="green")
                messagebox.showinfo("Sukses", "Dokumen valid secara DSA dan berhasil didekripsi RSA.")
            except ValueError:
                self.status_label.config(text="PERINGATAN: Signature DSA TIDAK VALID", foreground="red")
                messagebox.showwarning("Warning", "Dokumen terbuka tapi Tanda Tangan DSA PALSU/RUSAK.")

        except Exception as e:
            messagebox.showerror("Error", f"Gagal: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
