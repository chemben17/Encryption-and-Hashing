#let's create a password encryption program
# This allows the user to keep a track of the SHA(Secure hash algorithm) of their files using SHA3. It shows the value before and after encoding
# we are using base64 module

import base64
import hashlib
import time as t

#  a function that allows the user's input display to be in intervals
def slowdownoutput(text, delay = 0.1) :
    for character in text:
        print(character, end='', flush=True)
        t.sleep(delay)
# this function decrypts the encrypted using base64 as well.
def decrypt_password(password):
    decod = base64.b64decode(password)
    decode = decod.decode()
    slowdownoutput("Decoding your encoded Password", 0.2)
    print()
    print(decode)
    # decodedPassword = decod.hexdigest()
    # print(decod)
    print("Now, let's verify the Hashed value of the decoded password, If it's the same with the inputed one")
    # well hashing a function it needs to be encoded() : converted to byte
    encodedPassword = decode.encode()
    # the encoded variable is then hashed
    hashedPassword = hashlib.sha256(encodedPassword)
    print(hashedPassword.hexdigest())

def encrypt_pass(password):
    print("Your input is", password, end='')

    response1 = input("Is that right? answer with y/n ")
    # a conditional that depends on the users response
    if response1 == "y" or "Y":
        slowdownoutput("Generating SHA256 of your password", 0.18)
        print()
        hashed = hashlib.sha256(password.encode())
        print("Please a take a note of this hashed value: ", hashed.hexdigest())
        awaiting = "Generating your encoded password"
        slowdownoutput(awaiting)
        print()
        encodedPassword = base64.b64encode(password.encode())
        print(encodedPassword)
        print("Let's verify the hashed value after been encoded")
        hashedPassword = hashlib.sha256(encodedPassword).hexdigest()
        print(hashedPassword)
        toDecrypt = input("DO you want to decrypt the Password? y/n ")
        if toDecrypt == "y" or "Y":
            # encodedPasswordLength = len(encodedPassword)
            # print(encodedPasswordLength)
            decrypt_password(encodedPassword)

    else:
        print("Program exited successfully.\n You can re-run.\n Thank you ")
        exit()

userPassword = input("Enter your password: ")


encrypt_pass(userPassword)
