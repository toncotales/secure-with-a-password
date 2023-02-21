# -*- coding: utf-8 -*-
""" secure with a password (SWAP)

    cryptographic algorithm, advanced encryption standard,
    cipher block chaining, password based key encryption
    on all electronic data

    :author: https://github.com/toncotales
"""
import argparse
import base64
import datetime
import pathlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__author__ = "Ton Cotales"


class SWAP:
    def __init__(self, password: str):
        # generate password based 16-bit key
        self.key = Logic.pbkdf(password, 16)

    def cipher(self, plaintext: str) -> str:
        """ returns the encrypted or ciphered text from the
           plaintext in a base64 format
        """
        encrypted_data = self._encrypt_(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decipher(self, ciphered_text: str) -> str:
        """ return the decrypted or deciphered text as plaintext
        """
        encrypted_data = base64.urlsafe_b64decode(ciphered_text.encode())
        return self._decrypt_(encrypted_data).decode()

    def file_encryption(self, file, makecopy=True) -> bool:
        """ a function that performs data encryption on a computer file
           returns True if the operation is successful otherwise False
        """
        return_code = bool()
        file = pathlib.Path(file)
        if file.exists():
            encrypted_bytes = self._encrypt_(file.read_bytes())
            if makecopy:
                copy_name = file.stem + "_xswap" + file.suffix
                copy_abs = str(file.absolute()).replace(file.name, copy_name)
                copy_file = pathlib.Path(copy_abs)
                if not copy_file.exists():
                    copy_file.write_bytes(encrypted_bytes)
            else:
                file.write_bytes(encrypted_bytes)
            return_code = True
        return return_code

    def file_decryption(self, xfile) -> bool:
        """ a function that performs data decryption to a relatively
           encrypted computer file and returns True if the operation
           is successful otherwise False
       """
        return_code = bool()
        xfile = pathlib.Path(xfile)
        if xfile.exists():
            decrypted_bytes = self._decrypt_(xfile.read_bytes())
            if not decrypted_bytes.decode().startswith("ERROR:"):
                xfile.write_bytes(decrypted_bytes)
                return_code = True
        return return_code

    def _encrypt_(self, data: bytes) -> bytes:
        """ the main encryption function using the advanced
           encryption standard (AES) and with the classic
           mode ciphertext block chaining (CBC)

           Ciphertext Block Chaining, defined in NIST SP 800-38A,
           section 6.2. It is a mode of operation where each
           plaintext block gets XOR-ed with the previous
           ciphertext block prior to encryption
        """
        cipher = AES.new(self.key, AES.MODE_CBC)
        encrypted_edata = cipher.encrypt(pad(data, AES.block_size))
        encrypted_edata = Logic.insertion(encrypted_edata, self.key, cipher.iv)
        return encrypted_edata

    def _decrypt_(self, encrypted_data: bytes, failsafe=False) -> bytes:
        """ the main decryption function with a so-called "fail-safe"
           feature that can decrypt any encrypted electronic data from
           the relative encryption function by using the cipher key
           extracted from the encrypted data
        """
        try:
            if failsafe:
                return Logic.failsafe_decryption(encrypted_data)

            data, key, iv = Logic.extraction(encrypted_data)

            if key == self.key:
                cipher = AES.new(self.key, AES.MODE_CBC, iv)
                data = unpad(cipher.decrypt(data), AES.block_size)
                return data
            else:
                raise Exception

        except (BaseException, Exception):
            return b'ERROR: Decryption failure'


class Logic:
    """ A system or mode of reasoning """

    @staticmethod
    def pbkdf(passphrase: str, length: int) -> bytes:
        """ password based key derivation function from
           the cryptography package/library
        """
        # Personal configurations
        dob = datetime.datetime(1991, 7, 18)
        iterations = datetime.datetime.toordinal(dob)
        timestamp = hex(int(dob.timestamp()))
        salt = base64.urlsafe_b64encode(timestamp.encode())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=length, salt=salt,
            iterations=iterations, backend=default_backend()
        )
        return kdf.derive(passphrase.encode())

    @staticmethod
    def insertion(data: bytes, key: bytes, iv: bytes) -> bytes:
        """ a function that will insert the 16 bit cipher key and
           16 bit cipher initialization vector into the encrypted
           bytes of data
        """
        index = len(data) // 3
        data = data[:index] + key + iv + data[index:]
        return data

    @staticmethod
    def extraction(token: bytes) -> tuple:
        """ a function that will extract the 16 bit cipher key and
           16 bit cipher initialization vector from the encrypted
           bytes of data
        """
        total_insert_size = 32
        index = (len(token) - total_insert_size) // 3
        kiv = token[index: index + total_insert_size]
        key, iv = kiv[:len(kiv) // 2], kiv[len(kiv) // 2:]
        data = token[:index] + token[index + total_insert_size:]
        return data, key, iv

    @staticmethod
    def failsafe_decryption(encrypted_data: bytes) -> bytes:
        """ a fail-safe feature that can decrypt the encrypted bytes
           of data done by the swap encryption. This feature works by
           extracting the inserted cipher key and cipher initialization
           vector and use it to derypt the encrypted bytes of data
        """
        data, key, iv = Logic.extraction(encrypted_data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted_data


if __name__ == "__main__":

    USAGE = """\n\
$ python swap.py password -e -t "hello world"\n\
$ python swap.py password -e -f file\n\
"""
    DESCRIPTION = "info: Encrypt and decrypt text data or file(s) with a password"

    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.usage = USAGE
    parser.add_argument("password", help="passphrase used for encryption or decryption")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("-e", "--encrypt", action="store_true", help="set to encryption mode")
    mode_group.add_argument("-d", "--decrypt", action="store_true", help="set to decryption mode")

    data_group = parser.add_mutually_exclusive_group()
    data_group.add_argument("-t", "--text", metavar="", help="plaintext to be encrypted or decrypted")
    data_group.add_argument("-f", "--filename", metavar="", help="file to be encrypted or decrypted")

    args = parser.parse_args()
    swap = SWAP(args.password)

    # ================ ENCRYPTION BLOCK ================
    if args.encrypt:
        if args.text:
            print(swap.cipher(args.text))
        else:
            rcode = swap.file_encryption(args.filename, makecopy=False)
            if rcode:
                print("File encrypted:", args.filename)
            else:
                print("Error: Encryption failed due to", args.filename)

    # ================ DECRYPTION BLOCK ================
    else:
        if args.text:
            print(swap.decipher(args.text))
        else:
            rcode = swap.file_decryption(args.filename)
            if rcode:
                print("File decrypted:", args.filename)
            else:
                print("Error: Decryption failure")
