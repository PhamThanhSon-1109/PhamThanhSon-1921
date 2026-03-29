# ================= CLIENT WITH UI (ALL-IN-ONE) =================
import tkinter as tk
from tkinter import scrolledtext
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# ================= SOCKET + CRYPTO =================
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Tạo key RSA cho client
client_key = RSA.generate(2048)

# Nhận public key từ server
server_public_key = RSA.import_key(client_socket.recv(2048))

# Gửi public key của client
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Nhận AES key đã mã hóa
encrypted_aes_key = client_socket.recv(2048)
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# ================= ENCRYPT / DECRYPT =================
def encrypt_message(message):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext


def decrypt_message(encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# ================= UI =================
root = tk.Tk()
root.title("🔐 Secure Chat Client")
root.geometry("520x620")
root.configure(bg="#1e1e1e")

# Tiêu đề
header = tk.Label(root, text="Secure Chat", bg="#1e1e1e", fg="#00ffcc", font=("Arial", 16, "bold"))
header.pack(pady=10)

# Khung chat
chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg="#2b2b2b", fg="white", font=("Arial", 11))
chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
chat_area.config(state='disabled')

# Frame nhập
entry_frame = tk.Frame(root, bg="#1e1e1e")
entry_frame.pack(fill=tk.X, padx=10, pady=5)

message_entry = tk.Entry(entry_frame, font=("Arial", 12), bg="#3c3f41", fg="white", insertbackground="white")
message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

# ================= DISPLAY =================
def append_message(sender, message):
    chat_area.config(state='normal')
    chat_area.insert(tk.END, f"{sender}: {message}\n")
    chat_area.config(state='disabled')
    chat_area.yview(tk.END)

# ================= SEND =================
def send_message():
    message = message_entry.get()
    if message:
        encrypted = encrypt_message(message)
        client_socket.send(encrypted)
        append_message("You", message)
        message_entry.delete(0, tk.END)
        if message == "exit":
            client_socket.close()
            root.quit()

send_button = tk.Button(entry_frame, text="Send", command=send_message, bg="#00cc99", fg="black", width=10)
send_button.pack(side=tk.RIGHT)

# ================= RECEIVE =================
def receive_messages():
    while True:
        try:
            encrypted = client_socket.recv(1024)
            if not encrypted:
                break
            message = decrypt_message(encrypted)
            append_message("Friend", message)
        except:
            break

threading.Thread(target=receive_messages, daemon=True).start()

# Enter để gửi
message_entry.bind("<Return>", lambda event: send_message())

root.mainloop()
