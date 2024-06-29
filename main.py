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
    """Hash message using specified algorithm with a salt."""
    if hash_algo == "bcrypt":
        salt = bcrypt.gensalt(10)
        hashed_message = bcrypt.hashpw(message.encode(), salt)
        return salt, hashed_message
    else:
        salt = generate_salt()
        salted_message = message.encode("utf-8") + salt

        hash_func = getattr(hashlib, hash_algo)
        hashed_message = hash_func(message.encode()).hexdigest()
        hashed_message_salted = hash_func(salted_message).hexdigest()

        return salt, hashed_message, hashed_message_salted


def verify_message(hash_algo, stored_hash, stored_salt, message_to_check):
    """Verify the provided message against the stored hash with salt."""
    if hash_algo == "bcrypt":
        return bcrypt.checkpw(message_to_check.encode(), stored_hash)
    else:
        salted_message = message_to_check.encode("utf-8") + stored_salt
        hash_func = getattr(hashlib, hash_algo)
        hash_to_check = hash_func(salted_message).hexdigest()
        return hash_to_check == stored_hash


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("[!] Usage: python3 main.py <hash_algo> <message>")
        sys.exit()

    hash_algo_input = sys.argv[1].lower()
    message_input = sys.argv[2]
    hashed_message_salted = None

    if hash_algo_input == "bcrypt":
        salt, hashed_message = hash_message(hash_algo_input, message_input)
        is_valid = verify_message(hash_algo_input, hashed_message, None, message_input)
    elif hash_algo_input in SHA_HASH_ALGORITHMS:
        salt, hashed_message, hashed_message_salted = hash_message(
            hash_algo_input, message_input
        )
        is_valid = verify_message(
            hash_algo_input, hashed_message_salted, salt, message_input
        )
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algo_input}")

    print(f"Message: {message_input}")
    print(f"Hash Algorithm: {hash_algo_input}")
    print(f"Salt (hex): {salt.hex()}")
    print(f"Hashed Message: {hashed_message}")
    print(f"Hashed Message (+salt): {hashed_message_salted}")
    print(f"Message is valid: {is_valid}")
