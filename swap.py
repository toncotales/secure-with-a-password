"""
    secure with a password

    Encrypt and decrypt text data or file(s) with a password

    :author: Anthony Cotales
    :email: acotales@protonmail.com
"""
__author__ = "Anthony Cotales"

import argparse
import base64
import datetime
import pathlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def pbkdf(passphrase: str, length: int) -> bytes:
    """Password based key derivation function"""
    # Developer's personal configurations
    dob = datetime.datetime(1991, 7, 18)
    iterations = datetime.datetime.toordinal(dob)
    timestamp = hex(int(dob.timestamp()))
    salt = base64.urlsafe_b64encode(timestamp.encode())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=length, salt=salt,
        iterations=iterations, backend=default_backend()
    )
    return kdf.derive(passphrase.encode())


class SWAP:
    def __init__(self, password: str):
        self.key = pbkdf(password, 16)

    def encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        data = self.Logic.insertion(encrypted_data, self.key, cipher.iv)
        return data

    def decrypt(self, token: bytes) -> bytes:
        try:
            data, key, iv = self.Logic.extraction(token)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            data = unpad(cipher.decrypt(data), AES.block_size)
            return data
        except (BaseException, Exception):
            raise

    class Logic:
        """A system or mode of reasoning"""
        @staticmethod
        def insertion(data: bytes, key: bytes, iv: bytes) -> bytes:
            index = len(data) // 3
            data = data[:index] + key + iv + data[index:]
            return data

        @staticmethod
        def extraction(token: bytes) -> tuple:
            insert_size = 32
            index = (len(token) - insert_size) // 3
            kiv = token[index: index + insert_size]
            key, iv = kiv[:len(kiv) // 2], kiv[len(kiv) // 2:]
            data = token[:index] + token[index + insert_size:]
            return data, key, iv


if __name__ == "__main__":

    USAGE = """\n\
$ python swap.py password -e -t "hello world"\n\
$ python swap.py password -e -f file\n\
$ python swap.py password -e -f file -o newfile\n\
$ python swap.py password --decrypt --text "hello world"\n\
$ python swap.py password --decrypt --filename file\n\
$ python swap.py password --decrypt --filename file --output newfile\
    """
    DESCRIPTION = "info: Encrypt and decrypt text data or file(s) with a password"

    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.usage = USAGE
    parser.add_argument("password", help="passphrase used for encryption or decryption")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("-e", "--encrypt", action="store_true", help="set to encryption mode")
    mode_group.add_argument("-d", "--decrypt", action="store_true", help="set to decryption mode")

    data_group = parser.add_mutually_exclusive_group()
    data_group.add_argument("-t", "--text", metavar="", help="string or text to be encrypted or decrypted")
    data_group.add_argument("-f", "--filename", metavar="", help="file to be encrypted or decrypted")

    parser.add_argument("-o", "--output", metavar="", help="file destination after encryption or decryption")

    args = parser.parse_args()
    swap = SWAP(args.password)

    if args.encrypt:
        if args.text:
            output = swap.encrypt(args.text.encode())
            print(base64.urlsafe_b64encode(output).decode())
        else:
            filename = pathlib.Path(args.filename)
            if filename.is_file():
                file_data = swap.encrypt(filename.read_bytes())
                if args.output:
                    output_file = pathlib.Path(args.output)
                    output_file.write_bytes(file_data)
                    print(output_file.name)
                else:
                    filename.write_bytes(file_data)
            else:
                print(f"Error: The following argument is not a valid file: {args.filename}")
    else:
        if args.text:
            output = base64.urlsafe_b64decode(args.text)
            output = swap.decrypt(output).decode()
            print(output)
        else:
            filename = pathlib.Path(args.filename)
            if filename.is_file():
                try:
                    file_data = swap.decrypt(filename.read_bytes())
                except (BaseException, Exception):
                    print("Error: Password Mismatch")
                else:
                    if args.output:
                        output_file = pathlib.Path(args.output)
                        output_file.write_bytes(file_data)
                        print(output_file.name)
                    else:
                        filename.write_bytes(file_data)
            else:
                print(f"Error: The following argument is not a valid file: {args.filename}")
