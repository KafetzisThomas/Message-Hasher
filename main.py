#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Message-Hasher (https://github.com/KafetzisThomas/Message-Hasher)
# Author / Project Owner: KafetzisThomas (https://github.com/KafetzisThomas)

import os
import sys
import bcrypt
import hashlib

# List of supported SHA hash algorithms
SHA_HASH_ALGORITHMS = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
]


def generate_salt(length=16):
    """Generate random salt"""
    return os.urandom(length)


def hash_message(hash_algo, message):
    """Hash message using specified algorithm with a salt"""
    salt = generate_salt()
    salted_message = message.encode("utf-8") + salt

    if hash_algo == "bcrypt":
        hashed_message = bcrypt.hashpw(message.encode(), bcrypt.gensalt(10))
    elif hash_algo in SHA_HASH_ALGORITHMS:
        hash_func = getattr(hashlib, hash_algo)
        hashed_message = hash_func(salted_message).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algo}")

    return salt, hashed_message


def verify_message(hash_algo, stored_hash, stored_salt, message_to_check):
    """Verify the provided message against the stored hash with salt."""
    salted_message = message_to_check.encode("utf-8") + stored_salt

    if hash_algo == "bcrypt":
        return bcrypt.checkpw(message_to_check.encode(), stored_hash)
    elif hash_algo in SHA_HASH_ALGORITHMS:
        hash_func = getattr(hashlib, hash_algo)
        hash_to_check = hash_func(salted_message).hexdigest()

    return hash_to_check == stored_hash


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("[!] Usage: python3 main.py <hash_algo> <message>")
        sys.exit()

    hash_algo_input = sys.argv[1]
    message_input = sys.argv[2]

    salt, hashed_message = hash_message(hash_algo_input, message_input)
    is_valid = verify_message(hash_algo_input, hashed_message, salt, message_input)

    print(f"Message: {message_input}")
    print(f"Hash Algorithm: {hash_algo_input}")
    print(f"Salt (hex): {salt.hex()}")
    print(f"Hashed Message: {hashed_message}")
    print(f"Message is valid: {is_valid}")
