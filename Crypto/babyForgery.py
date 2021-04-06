#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import string
import random
import socketserver
import signal
from hashlib import sha256

from ocb.aes import AES # https://github.com/kravietz/pyOCB
from ocb import OCB

FLAG = #####REDACTED#####

BLOCKSIZE = 16
MENU = br"""
[1] Encrypt
[2] Decrypt
[3] Get Flag
[4] Exit
"""

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline: msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def recvhex(self, prompt=b'> '):
        return bytes.fromhex(self.recv(prompt=prompt).decode('latin-1'))

    def proof_of_work(self):
        random.seed(os.urandom(128))
        proof = ''.join(random.choices(string.ascii_letters+string.digits, k=20))
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(str.encode("sha256(XXXX+%s) == %s" % (proof[4:], _hexdigest)))
        x = self.recv(prompt=b'Give me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def timeout_handler(self, signum, frame):
        self.send(b"\n\nTIMEOUT!!!\n")
        raise TimeoutError

    def encrypt(self, nonce, message, associate_data=b''):
        assert nonce not in self.NONCEs
        self.NONCEs.add(nonce)
        self.ocb.setNonce(nonce)
        tag, cipher = self.ocb.encrypt(bytearray(message), bytearray(associate_data))
        return (bytes(cipher), bytes(tag))
    
    def decrypt(self, nonce, cipher, tag, associate_data=b''):
        self.ocb.setNonce(nonce)
        authenticated, message = self.ocb.decrypt(
            *map(bytearray, (associate_data, cipher, tag))
        )
        if not authenticated:
            raise ValueError('REJECT')
        return bytes(message)

    def handle(self):
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(60)
        if not self.proof_of_work():
            return

        aes = AES(128)
        self.ocb = OCB(aes)
        KEY = os.urandom(BLOCKSIZE)
        self.ocb.setKey(KEY)
        self.NONCEs = set()

        while True:
            USERNAME = self.recv(prompt=b'Enter username > ')
            if len(USERNAME) > BLOCKSIZE:
                self.send(b"I can't remember long names")
                continue
            if USERNAME == b'Alice':
                self.send(b'Name already used')
                continue
            break

        signal.alarm(60)
        while True:
            self.send(MENU, newline=False)
            try:
                choice = int(self.recv(prompt=b'Enter option > '))

                if choice == 1:
                    nonce = self.recvhex(prompt=b'Enter nonce > ')
                    message = self.recvhex(prompt=b'Enter message > ')
                    associate_data = b'from ' + USERNAME
                    ciphertext, tag = self.encrypt(nonce, message, associate_data)
                    self.send(str.encode(f"ciphertext: {ciphertext.hex()}"))
                    self.send(str.encode(f"tag: {tag.hex()}"))

                elif choice == 2:
                    nonce = self.recvhex(prompt=b'Enter nonce > ')
                    ciphertext = self.recvhex(prompt=b'Enter ciphertext > ')
                    tag = self.recvhex(prompt=b'Enter tag > ')
                    associate_data = self.recvhex(prompt=b'Enter associate data > ')
                    message = self.decrypt(nonce, ciphertext, tag, associate_data)
                    self.send(str.encode(f"message: {message.hex()}"))

                elif choice == 3:
                    nonce = self.recvhex(prompt=b'Enter nonce > ')
                    ciphertext = self.recvhex(prompt=b'Enter ciphertext > ')
                    tag = self.recvhex(prompt=b'Enter tag > ')
                    associate_data = b'from Alice'
                    message = self.decrypt(nonce, ciphertext, tag, associate_data)
                    if message == b'please_give_me_the_flag':
                        self.send(FLAG)

                elif choice == 4:
                    break
                else:
                    break

            except:
                self.send(b'Error!')
                break
        signal.alarm(0)

        self.send(b'Bye!')
        self.request.close()

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10000
    print(HOST, PORT)
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()

