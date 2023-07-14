#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Pass-Hashing (https://github.com/KafetzisThomas/Pass-Hashing)
# Author / Project Owner: KafetzisThomas (https://github.com/KafetzisThomas)

import bcrypt, getpass

def get_hashed_password(password):
  """Write a hashed string to a file"""
  with open("password.txt", "wb") as file:
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(10))
    file.write(hashed_password)

def read_hashed_password():
  """Return the hashed string from the file"""
  with open('password.txt', 'rb') as file:
    hash = file.readline()
  return hash

password = getpass.getpass("Password: ").encode('utf-8')
get_hashed_password(password)

password_hash = read_hashed_password()
print(password_hash)
