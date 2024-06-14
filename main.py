#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Message-Hasher (https://github.com/KafetzisThomas/Message-Hasher)
# Author / Project Owner: KafetzisThomas (https://github.com/KafetzisThomas)

import sys
import bcrypt
import hashlib


def hash_message(hash_algo, message):
    if hash_algo == "bcrypt": hashed_message = bcrypt.hashpw(message.encode(), bcrypt.gensalt(10))
    if hash_algo == "md5": hashed_message = hashlib.md5(message.encode()).hexdigest()
    if hash_algo == "sha1": hashed_message = hashlib.sha1(message.encode()).hexdigest()
    if hash_algo == "sha224": hashed_message = hashlib.sha224(message.encode()).hexdigest()
    if hash_algo == "sha256": hashed_message = hashlib.sha256(message.encode()).hexdigest()
    if hash_algo == "sha384": hashed_message = hashlib.sha384(message.encode()).hexdigest()
    if hash_algo == "sha512": hashed_message = hashlib.sha512(message.encode()).hexdigest()
    return message, hash_algo, hashed_message
    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("[!] Usage: python3 main.py <hash_algo> <message>")
        sys.exit()

    hash_algo_input = sys.argv[1]
    message_input = sys.argv[2]

    message, hash_algo, hashed_message = hash_message(hash_algo_input, message_input)
    print(f"Message: {message}\nHash algo: {hash_algo}\nHashed message: {hashed_message}")
