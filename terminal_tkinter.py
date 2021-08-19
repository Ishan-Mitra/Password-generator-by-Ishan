from sqlite3 import connect as sql_connect
from sys import argv
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime

BASE_DIR = Path(argv[0]).resolve().parent

def connect():

    global cursor, db
    #db = sql_connect(f'{BASE_DIR}\\lib\\tcl\\msgs\\zn_ah.msg')
    db = sql_connect(f'{BASE_DIR}\\db.db')
    cursor = db.cursor()


    cursor.execute("PRAGMA key='test'")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL);
        """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        notes TEXT NOT NULL);
        """)


def decrypt_text(message):
    try:
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, b'\xc7\xd6\xac*\xe5\x91\xa78\xebu$\x99+\xb2H\xae')
        return unpad(unpad(unpad(unpad(cipher.decrypt(message), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()
    except Exception as E:
       raise E


def master_encrypt(message):
    try:
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
        pasdf = cursor.fetchone()
        password = bytes(decrypt_text(pasdf[1]), 'utf-8')
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, password[:16])
        return cipher.encrypt(pad(pad(pad(pad(message, AES.block_size), AES.block_size), AES.block_size), AES.block_size))
    except Exception as E:
        raise E

def master_decrypt(message):
    try:
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
        pasdf = cursor.fetchone()
        password = bytes(decrypt_text(pasdf[1]), 'utf-8')
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, password[:16])
        return unpad(unpad(unpad(unpad(cipher.decrypt(message), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()
    except Exception as E:
        raise E

connect()
enc_func = master_encrypt(b'hhh')
print(enc_func)
print("\n")
dec_func = master_decrypt(enc_func)
print(dec_func)
