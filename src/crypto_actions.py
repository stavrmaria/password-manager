import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def calculate_master_key(auth_credentials):
    master_password, user_salt = auth_credentials
    iterations = 100000  # Number of iterations
    key_length = 32      # Desired key length in bytes
    master_key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), user_salt.encode(), iterations, key_length)
    return master_key

def encrypt(master_key, new_password):
    # Create an AES cipher object in CBC mode with the IV
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(master_key, AES.MODE_CBC, iv)

    # Pad the password to match the AES block size and encrypt it
    padded_password = pad(new_password.encode('utf-8'), AES.block_size)
    encrypted_password = iv + cipher.encrypt(padded_password)
    return base64.b64encode(encrypted_password)

def decrypt(master_key, encrypted_password):
    decoded_password = base64.b64decode(encrypted_password)
    # Extract IV and ciphertext
    iv = decoded_password[:AES.block_size]
    ciphertext = decoded_password[AES.block_size:]

    # Create an AES cipher object in CBC mode with the IV
    cipher = AES.new(master_key, AES.MODE_CBC, iv)
    decrypted_password = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_password.decode('utf-8')
