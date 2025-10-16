import base64

secret_string = "vJqfip28ioydips="

base64_secret_string = base64.b64decode(secret_string)


def decrypt(encrypted_bytes):
    print(encrypted_bytes)
    decrypted_bytes = bytearray(encrypted_bytes)  
    print(decrypted_bytes)
    for i in range(len(decrypted_bytes)):
        decrypted_bytes[i] = (~decrypted_bytes[i]) & 255
        decrypted_bytes[i] = decrypted_bytes[i] ^ 16
    return decrypted_bytes.decode('utf-8')

base64_clear_text = decrypt(base64_secret_string)

print(base64_clear_text)
