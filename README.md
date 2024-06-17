<h1 align="center">Message-Hasher</h1>

__What Is This?__ - Allows you to hash strings with support for various hashing algorithms and salt inclusion.

__How to Download__: Open the terminal on your machine and type the following command:

```bash
git clone https://github.com/KafetzisThomas/Message-Hasher.git
```

# Usage Notes

```bash
➜ message_to_hash='secret_password'  # Example plain text
➜ hash_algo='bcrypt'  # Example supported hash algorithm

# Correct way
$ python main.py bcrypt '$hash_algo' '$message_to_hash'

# Output:
# Message: secret_password
# Hash Algorithm: bcrypt
# Salt (hex): 50ddbf97748e4652e1d66494bb1c4151
# Hashed Message: b'$2b$10$xiQbysCUh4Y6iq3FlE.XZ.VrInDnQ3MvEz5n1Aeb84DX1LxfLFSoO'
# Message is valid: True

# Incorrect ways
$ python3 main.py md4 '$message_to_hash'

# Output:
# ValueError: Unsupported hash algorithm: md4

$ python3 main.py

# Output:
# [!] Usage: python3 main.py <hash_algo> <message>
```
