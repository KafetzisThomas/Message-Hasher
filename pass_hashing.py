#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Pass Hashing (https://github.com/KafetzisThomas/Pass-Hashing)
# Author / Project Owner: KafetzisThomas (https://github.com/KafetzisThomas)

import bcrypt, getpass

#Password Hashing Process
with open("master_pass.txt", "wb") as mp:
    password = getpass.getpass("\nPassword: ")
    password_encode = password.encode('utf-8')
    password_hashed = bcrypt.hashpw(password_encode, bcrypt.gensalt(10))

    mp.write(password_hashed)

print("\n* Your password is hashed!\nStored in the 'master_pass.txt' file.")
