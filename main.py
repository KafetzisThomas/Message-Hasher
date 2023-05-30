#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Pass Hashing (https://github.com/KafetzisThomas/Pass-Hashing)
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
    for line in file:
      print(f"\nYour password has been hashed:\n* {line}")

password = getpass.getpass("Password: ").encode('utf-8')
get_hashed_password(password)
read_hashed_password()
