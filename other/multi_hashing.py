#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

# Project Title: Multi Hashing (https://github.com/KafetzisThomas/Pass-Hashing)
# Author / Project Owner: KafetzisThomas (https://github.com/KafetzisThomas)

import getpass, bcrypt, time, sys

def hashing_process():
    print("\n*Enter Ctrl+C to exit/cancel operation")
    print("\n1.Generate random hashes for a specific string.")
    print("2.Show all saved hashes from 'hashes.txt' file.")

    try:
        choice = int(input("\nChoice(1-2): "))
    except ValueError as err:
        print(err)
        hashing_process()
    except KeyboardInterrupt:
        sys.exit()

    hashed_passwords = []
    if choice == 1:
        try:
            password = getpass.getpass("\nPassword: ")
            while True:
                password_encode = password.encode('utf-8')
                hashed_password = bcrypt.hashpw(password_encode, bcrypt.gensalt(10))
                if bcrypt.checkpw(password_encode, hashed_password):
                    print(f"{hashed_password}: match")
                else:
                    print(f"{hashed_password}: does not match")
                hashed_passwords.append(hashed_password)
                f = open('hashes.txt', 'wb')
                for line in hashed_passwords:
                    f.write(line)
                    f.write("\n".encode('utf-8'))
                f.close()
        except KeyboardInterrupt:
            print("\nOperation canceled.")
            hashing_process()

    if choice == 2:
        f = open('hashes.txt', 'rb')
        for line in f:
            print(line)
        f.close()
        time.sleep(1.0)
        print("\n* Ignore the \(/n)\ at the end of each hash. It's not included in the actual file.")
        time.sleep(1.0)
        hashing_process()

hashing_process()
