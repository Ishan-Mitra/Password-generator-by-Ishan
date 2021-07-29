from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Util.Padding import pad, unpad

def encrypt_text(message):
    key = sha256().digest()
    IVvar = b'\xc7\xd6\xac*\xe5\x91\xa78\xebu$\x99+\xb2H\xae'
    cipher = AES.new(key, AES.MODE_CBC, IVvar)
    mes_enc = cipher.encrypt(pad(pad(pad(pad(message, AES.block_size), AES.block_size), AES.block_size), AES.block_size))
    with open('libcrypto-1.1.dll', 'wb') as file:
        file.write(cipher.iv)
        print(cipher.iv)
        file.write(mes_enc)


def decrypt_text():
    key = sha256().digest()
    with open('libcrypto-1.1.dll','rb') as file:
        iv = file.read(16)
        text = file.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return unpad(unpad(unpad(unpad(cipher.decrypt(text), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()


if __name__ == '__main__':
    encrypt_text(bytes('I am t45t45y4an', 'utf-8'))
    print(decrypt_text())