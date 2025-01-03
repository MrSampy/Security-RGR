import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Генерація симетричного ключа
def generate_session_key(premaster, client_random, server_random):
    concat_kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=None)
    return concat_kdf.derive(client_random + server_random + premaster)

# Шифрування повідомлень
def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv + encrypted_message

# Розшифрування повідомлень
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

def start_server():
    # Генерація ключів сервера
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Серіалізація відкритого ключа
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Налаштування сервера
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    print("Сервер запущено і чекає на клієнта...")

    conn, addr = server_socket.accept()
    print(f"Клієнт підключився: {addr}")

    # Отримання "Привіт від клієнта"
    client_hello = conn.recv(1024)
    client_random = client_hello[:16]
    print(f"Отримано привіт від клієнта: {client_hello[16:].decode('utf-8')}")

    # Відправлення "Привіт від сервера" та відкритого ключа
    server_random = os.urandom(16)
    server_hello = "Привіт від сервера".encode('utf-8') + server_random
    conn.send(server_hello)
    conn.send(public_key_pem)
    print("Відправлено привіт та відкритий ключ клієнту.")

    # Отримання зашифрованого premaster
    encrypted_premaster = conn.recv(1024)
    premaster = private_key.decrypt(
        encrypted_premaster,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Розшифровано premaster: {premaster.hex()}")

    # Генерація ключа сеансу
    session_key = generate_session_key(premaster, client_random, server_random)
    print("Згенеровано сеансовий ключ.")

    # Відправка готовності
    ready_message = encrypt_message(session_key, "Готовий")
    conn.send(ready_message)

    # Отримання готовності від клієнта
    client_ready_message = conn.recv(1024)
    client_ready = decrypt_message(session_key, client_ready_message).decode('utf-8')
    print(f"Клієнт повідомив: {client_ready}")

    # Захищений обмін даними
    print("Захищений канал встановлено. Чекаємо дані від клієнта...")
    encrypted_data = conn.recv(1024)
    received_message = decrypt_message(session_key, encrypted_data).decode('utf-8')
    print(f"Отримано повідомлення: {received_message}")

    # Відправка відповіді клієнту
    response_message = encrypt_message(session_key, "Повідомлення отримано.")
    conn.send(response_message)

    # Закриття з'єднання
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
