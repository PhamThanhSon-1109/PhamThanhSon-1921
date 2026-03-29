from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Initialize server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

# Generate RSA key pair
server_key = RSA.generate(2048)

# List of connected clients
clients = []

# ================= ENCRYPT =================
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# ================= DECRYPT =================
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# ================= HANDLE CLIENT =================
def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    try:
        # Gửi public key server
        client_socket.send(server_key.publickey().export_key(format='PEM'))

        # Nhận public key client
        client_received_key = RSA.import_key(client_socket.recv(2048))

        # Tạo AES key
        aes_key = get_random_bytes(16)

        # Mã hóa AES key bằng RSA
        cipher_rsa = PKCS1_OAEP.new(client_received_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        client_socket.send(encrypted_aes_key)

        # Lưu client
        clients.append((client_socket, aes_key))

        while True:
            try:
                encrypted_message = client_socket.recv(1024)

                # 🔥 FIX QUAN TRỌNG: client disconnect
                if not encrypted_message:
                    break

                decrypted_message = decrypt_message(aes_key, encrypted_message)
                print(f"Received from {client_address}: {decrypted_message}")

                # Broadcast
                for client, key in clients:
                    if client != client_socket:
                        try:
                            encrypted = encrypt_message(key, decrypted_message)
                            client.send(encrypted)
                        except:
                            pass  # tránh crash nếu client khác chết

                if decrypted_message == "exit":
                    break

            except Exception as e:
                print(f"Error with {client_address}: {e}")
                break

    except Exception as e:
        print(f"Setup error with {client_address}: {e}")

    finally:
        print(f"Connection with {client_address} closed")

        # Xóa client an toàn
        try:
            clients.remove((client_socket, aes_key))
        except:
            pass

        client_socket.close()

# ================= ACCEPT CLIENT =================
while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address),
        daemon=True   # 🔥 tránh treo chương trình
    )
    client_thread.start()