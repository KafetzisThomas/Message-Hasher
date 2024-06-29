<h1 align="center">Message-Hasher</h1>

__What Is This?__ - Allows you to hash strings with support for various hashing algorithms and salt inclusion.

__How to Download__: Open the terminal on your machine and type the following command:

```bash
git clone https://github.com/KafetzisThomas/Message-Hasher.git
```

# Usage Notes

```bash
➜ hash_algo='sha256'  # Example supported hash algorithm
➜ message_to_hash='secret_password'  # Example plain text

# Correct way
$ python main.py '$hash_algo' '$message_to_hash'

# Output:
# Message: secret_password
# Hash Algorithm: sha256
# Salt (hex): b97d35d5e4850d6c95cdbf159884e09c
# Hashed Message: 8e67dd1355714239acde098b6f1cf906bde45be6db826dc2caca7536e07ae844
# Hashed Message (+salt): 46b9e120901d8e18e166135787072d6e29d488d0dcfd73100d6534429e03630d
# Message is valid: True

# Incorrect ways
$ python3 main.py md4 '$message_to_hash'

# Output:
# ValueError: Unsupported hash algorithm: md4

$ python3 main.py

# Output:
# [!] Usage: python3 main.py <hash_algo> <message>
```
