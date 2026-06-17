import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii

class ECCUI:
    def __init__(self, master):
        self.master = master
        self.master.title("ECC Encryption & Decryption")
        self.master.geometry("600x500")
        
        self.private_key = None
        self.public_key = None
        
        # UI Elements
        tk.Label(master, text="ECC Encryption / Decryption", font=("Helvetica", 16, "bold")).pack(pady=10)
        
        # Key Generation
        key_frame = tk.Frame(master)
        key_frame.pack(pady=5)
        self.btn_gen_key = tk.Button(key_frame, text="Generate ECC Key Pair", command=self.generate_keys)
        self.btn_gen_key.pack(side=tk.LEFT, padx=5)
        
        self.lbl_key_status = tk.Label(key_frame, text="No keys generated.", fg="red")
        self.lbl_key_status.pack(side=tk.LEFT, padx=5)
        
        # Input Text
        tk.Label(master, text="Plaintext:").pack(anchor="w", padx=20)
        self.txt_plaintext = tk.Text(master, height=5, width=70)
        self.txt_plaintext.pack(padx=20)
        
        # Buttons
        btn_frame = tk.Frame(master)
        btn_frame.pack(pady=10)
        self.btn_encrypt = tk.Button(btn_frame, text="Encrypt", command=self.encrypt_text)
        self.btn_encrypt.pack(side=tk.LEFT, padx=10)
        
        self.btn_decrypt = tk.Button(btn_frame, text="Decrypt", command=self.decrypt_text)
        self.btn_decrypt.pack(side=tk.LEFT, padx=10)
        
        self.btn_clear = tk.Button(btn_frame, text="Clear", command=self.clear_text)
        self.btn_clear.pack(side=tk.LEFT, padx=10)
        
        # Ciphertext Text
        tk.Label(master, text="Ciphertext (Hex):").pack(anchor="w", padx=20)
        self.txt_ciphertext = tk.Text(master, height=5, width=70)
        self.txt_ciphertext.pack(padx=20)
        
        # Decrypted Text
        tk.Label(master, text="Decrypted Text:").pack(anchor="w", padx=20)
        self.txt_decrypted = tk.Text(master, height=5, width=70)
        self.txt_decrypted.pack(padx=20)

    def generate_keys(self):
        try:
            self.private_key = ECC.generate(curve='P-256')
            self.public_key = self.private_key.public_key()
            self.lbl_key_status.config(text="Keys generated successfully!", fg="green")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")

    def encrypt_text(self):
        if not self.public_key:
            messagebox.showwarning("Warning", "Please generate keys first.")
            return
            
        plain_text = self.txt_plaintext.get("1.0", tk.END).strip()
        if not plain_text:
            messagebox.showwarning("Warning", "Please enter plaintext.")
            return
            
        try:
            # Generate ephemeral key
            ephemeral_priv_key = ECC.generate(curve='P-256')
            ephemeral_pub_key = ephemeral_priv_key.public_key()
            
            # Calculate shared secret using ECDH
            shared_point = self.public_key.pointQ * ephemeral_priv_key.d
            shared_secret = int(shared_point.x).to_bytes(32, 'big')
            
            # Derive AES key
            aes_key = SHA256.new(shared_secret).digest()
            
            # Encrypt with AES-GCM
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
            
            # Format: ephemeral_pub_key_x (32) + ephemeral_pub_key_y (32) + nonce (16) + tag (16) + ciphertext
            ephemeral_x = int(ephemeral_pub_key.pointQ.x).to_bytes(32, 'big')
            ephemeral_y = int(ephemeral_pub_key.pointQ.y).to_bytes(32, 'big')
            
            encrypted_data = ephemeral_x + ephemeral_y + cipher.nonce + tag + ciphertext
            encrypted_hex = binascii.hexlify(encrypted_data).decode('utf-8')
            
            self.txt_ciphertext.delete("1.0", tk.END)
            self.txt_ciphertext.insert(tk.END, encrypted_hex)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_text(self):
        if not self.private_key:
            messagebox.showwarning("Warning", "Please generate keys first.")
            return
            
        encrypted_hex = self.txt_ciphertext.get("1.0", tk.END).strip()
        if not encrypted_hex:
            messagebox.showwarning("Warning", "Please enter ciphertext.")
            return
            
        try:
            encrypted_data = binascii.unhexlify(encrypted_hex)
            
            if len(encrypted_data) < 96:
                raise ValueError("Invalid ciphertext length")
                
            ephemeral_x = encrypted_data[:32]
            ephemeral_y = encrypted_data[32:64]
            nonce = encrypted_data[64:80]
            tag = encrypted_data[80:96]
            ciphertext = encrypted_data[96:]
            
            # Reconstruct ephemeral public key
            ephemeral_pub_key = ECC.construct(curve='P-256', point_x=int.from_bytes(ephemeral_x, 'big'), point_y=int.from_bytes(ephemeral_y, 'big'))
            
            # Calculate shared secret
            shared_point = ephemeral_pub_key.pointQ * self.private_key.d
            shared_secret = int(shared_point.x).to_bytes(32, 'big')
            
            # Derive AES key
            aes_key = SHA256.new(shared_secret).digest()
            
            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plain_text = cipher.decrypt_and_verify(ciphertext, tag)
            
            self.txt_decrypted.delete("1.0", tk.END)
            self.txt_decrypted.insert(tk.END, plain_text.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Decryption failed: {str(e)}")

    def clear_text(self):
        self.txt_plaintext.delete("1.0", tk.END)
        self.txt_ciphertext.delete("1.0", tk.END)
        self.txt_decrypted.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ECCUI(root)
    root.mainloop()
