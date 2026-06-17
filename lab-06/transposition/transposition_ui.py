import tkinter as tk
from tkinter import messagebox
import math

def encryptMessage(key, message):
    ciphertext = [''] * key
    for col in range(key):
        pointer = col
        while pointer < len(message):
            ciphertext[col] += message[pointer]
            pointer += key
    return ''.join(ciphertext)

def decryptMessage(key, message):
    numOfColumns = math.ceil(len(message) / float(key))
    numOfRows = key
    numOfShadedBoxes = (numOfColumns * numOfRows) - len(message)
    plaintext = [''] * int(numOfColumns)
    col = 0
    row = 0
    for symbol in message:
        plaintext[col] += symbol
        col += 1
        if (col == numOfColumns) or (col == numOfColumns - 1 and row >= numOfRows - numOfShadedBoxes):
            col = 0
            row += 1
    return ''.join(plaintext)

def process(action):
    msg = text_input.get("1.0", tk.END).strip()
    key_str = entry_key.get().strip()
    
    if not msg:
        messagebox.showwarning("Cảnh báo", "Vui lòng nhập văn bản!")
        return
    if not key_str.isdigit():
        messagebox.showerror("Lỗi", "Khóa (Key) phải là một số nguyên dương!")
        return
        
    key = int(key_str)
    if key <= 0:
        messagebox.showerror("Lỗi", "Khóa phải lớn hơn 0!")
        return

    if action == "encrypt":
        result = encryptMessage(key, msg)
    else:
        result = decryptMessage(key, msg)
        
    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, result)

# UI setup
root = tk.Tk()
root.title("Transposition Cipher - Mã hóa & Giải mã")
root.geometry("500x420")
root.configure(padx=20, pady=20)

tk.Label(root, text="VĂN BẢN ĐẦU VÀO", font=("Arial", 10, "bold")).pack(anchor="w")
text_input = tk.Text(root, height=5, width=55, font=("Arial", 10))
text_input.pack(pady=5)

frame_key = tk.Frame(root)
frame_key.pack(pady=10, fill="x")
tk.Label(frame_key, text="Khóa (Số cột): ", font=("Arial", 10, "bold")).pack(side="left")
entry_key = tk.Entry(frame_key, font=("Arial", 10), width=10)
entry_key.pack(side="left")

frame_btns = tk.Frame(root)
frame_btns.pack(pady=10)
tk.Button(frame_btns, text="Mã hóa (Encrypt)", command=lambda: process("encrypt"), width=15, bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=10)
tk.Button(frame_btns, text="Giải mã (Decrypt)", command=lambda: process("decrypt"), width=15, bg="#2196F3", fg="white", font=("Arial", 10, "bold")).grid(row=0, column=1, padx=10)

tk.Label(root, text="KẾT QUẢ", font=("Arial", 10, "bold")).pack(anchor="w", pady=(10, 0))
text_output = tk.Text(root, height=5, width=55, font=("Arial", 10))
text_output.pack(pady=5)

if __name__ == "__main__":
    root.mainloop()
