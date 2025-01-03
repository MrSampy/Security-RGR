import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
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
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + encrypted_message

# Розшифрування повідомлень
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

def start_client():
    # Підключення до сервера
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))
    print("Підключено до сервера.")

    # Надсилання "Привіт від клієнта"
    client_random = os.urandom(16)
    client_hello = client_random + 'Привіт від клієнта'.encode('utf-8')
    client_socket.send(client_hello)

    # Отримання "Привіт від сервера" та відкритого ключа
    server_hello = client_socket.recv(1024)
    server_random = server_hello[-16:]
    print(f"Отримано привіт від сервера: {server_hello[:-16].decode()}")
    public_key_pem = client_socket.recv(1024)

    # Завантаження відкритого ключа сервера
    server_public_key = load_pem_public_key(public_key_pem)
    print("Отримано відкритий ключ сервера.")

    # Генерація premaster та його шифрування
    premaster = os.urandom(16)
    encrypted_premaster = server_public_key.encrypt(
        premaster,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    client_socket.send(encrypted_premaster)
    print("Відправлено зашифрований premaster серверу.")

    # Генерація ключа сеансу
    session_key = generate_session_key(premaster, client_random, server_random)
    print("Згенеровано сеансовий ключ.")

    # Надсилання готовності
    ready_message = encrypt_message(session_key, "Готовий")
    client_socket.send(ready_message)

    # Отримання готовності від сервера
    server_ready_message = client_socket.recv(1024)
    server_ready = decrypt_message(session_key, server_ready_message).decode()
    print(f"Сервер повідомив: {server_ready}")

    # Захищений обмін даними
    print("Захищений канал встановлено.")
    message = "Це захищене повідомлення."
    encrypted_data = encrypt_message(session_key, message)
    client_socket.send(encrypted_data)

    # Отримання відповіді від сервера
    response_encrypted = client_socket.recv(1024)
    response_message = decrypt_message(session_key, response_encrypted).decode()
    print(f"Отримано відповідь від сервера: {response_message}")

    # Закриття з'єднання
    client_socket.close()

if __name__ == "__main__":
    start_client()