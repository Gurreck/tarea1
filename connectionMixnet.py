import socket
import struct
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Configuración de la conexión
MIXNET_HOST = "pets.ic-itcr.ac.cr"
MIXNET_PORT = 50027  # Puerto ficticio, actualizar con el real

# Cargar clave pública desde un archivo PEM
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Generar clave AES y IV aleatorios
def generate_aes_key():
    key = os.urandom(16)  # AES-128
    iv = os.urandom(16)   # IV para CBC
    return key, iv

# Cifrado AES con PKCS7 padding
def encrypt_aes(key, iv, plaintext):
    pad_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_length] * pad_length)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Cifrar clave AES e IV con RSA
def encrypt_rsa(public_key, key, iv):
    return public_key.encrypt(
        key + iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Cifrado en capas (Onion Encryption)
def onion_encrypt(dest, message, keys):
    plaintext = f"{dest},{message}".encode()
    
    for key in reversed(keys):  # Cifrar en orden mix-3 -> mix-2 -> mix-1
        aes_key, iv = generate_aes_key()
        plaintext = encrypt_aes(aes_key, iv, plaintext)
        plaintext = encrypt_rsa(key, aes_key, iv) + plaintext
    
    return plaintext

# Enviar mensaje al mixnet
def send_message(dest, message, keys):
    encrypted_payload = onion_encrypt(dest, message, keys)
    length_prefix = struct.pack('>I', len(encrypted_payload))  # 4 bytes big-endian
    
    # Crear conexión con el mixnet
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((MIXNET_HOST, MIXNET_PORT))
        sock.sendall(length_prefix + encrypted_payload)
        response = sock.recv(1)
        if response == b'\x06':
            print("Mensaje enviado con éxito.")
        elif response == b'\x15':
            print("Error en el envío del mensaje.")
        else:
            print("Respuesta desconocida del servidor.")

if __name__ == "__main__":
    keys = [
        load_public_key("public-key-mix-1.pem"),
        load_public_key("public-key-mix-2.pem"),
        load_public_key("public-key-mix-3.pem")
    ]
    send_message("Estudiante3", "Grupo 3", keys)