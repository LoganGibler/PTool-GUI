from encodings import utf_8
import tkinter as tk
from tkinter import *
import random
import sys
import string
import re
from hashlib import md5, sha1, sha224, sha256, sha384, sha512 
import time
import socket
import math
from unicodedata import decimal
import sys
from functools import reduce
import base64

# global vars
special_characters = """!@#$%^&*()-+?_=,<>/"""
numberlist = string.digits
letterslist = string.ascii_letters
specialcharslist = ["!","@","#","$","%","&"]

root=Tk()

# main canvas
canvas = tk.Canvas(root, height=600, width=600, bg="black")
canvas.pack(fill="both", expand=True)

# functions
def grade():
    resultbox.delete(1.0, END)
    password = inputbox.get()
    pass_grade = 0
    uppercount = 0
    lowercount = 0
    specialcharcount = 0
    numbercount = 0
    length_grade = 0

    for letter in password:
        if letter in special_characters:
            continue
        if letter == letter.upper():
            uppercount = 1
        if letter == letter.lower():
            lowercount = 1
        if letter in numberlist:
            numbercount = 1
    if len(password) >= 8:
        length_grade = 1
    if len(password) >= 12:
        length_grade += 1
    
    if any(char in special_characters for char in password):
        specialcharcount = 1

    pass_grade = length_grade + specialcharcount + numbercount + uppercount + lowercount
  
    if pass_grade == 6:
        resultbox.insert(1.0, "PTools Password Grade:  Excellent")
        # print("PTools Password Grade:  Excellent")
    if pass_grade == 5:
        resultbox.insert(1.0, "PTools Password Grade:  Great")
        # print("PTools Password Grade:  Great")
    if pass_grade == 4:
        resultbox.insert(1.0, "PTools Password Grade:  Good")
        # print("PTools Password Grade:  Good")
    if pass_grade <= 3:
        resultbox.insert(1.0, "PTools Password Grade:  Bad")
        # print("PTools Password Grade:  Bad")

def generate():
    resultbox.delete(1.0, END)
    password = ""
    passwordlist = []

    numbers = random.choices(numberlist, k=random.randint(1,100))
    letters = random.choices(letterslist, k=random.randint(1,100))
    specialchar = random.choice(specialcharslist)

    scramble = []
    for num in numbers:
        scramble.append(num)
    for letter in letters:
        scramble.append(letter)

    scramble.append(specialchar)
    
    passwordlist += random.choices(scramble, k=random.randint(10,16))
   
    passwordlist.insert(random.randint(0,10), specialchar)

    random.shuffle(passwordlist)

    for character in passwordlist:
        password += character

    # print("Your generated password: ", password)
    resultbox.insert(1.0, password)

def hashtype():
    resultbox.delete(1.0, END)
    passHash = inputbox.get()

    if len(passHash) == 128:
        resultbox.insert(1.0, "Hash type: SHA512")
        # print("Hash type: SHA512")
    elif len(passHash) == 96:
        resultbox.insert(1.0, "Hash type: SHA384")
        # print("Hash type: SHA384")
    elif len(passHash) == 64:
        resultbox.insert(1.0, "Hash type: SHA256")
        # print("Hash type: SHA256")
    elif len(passHash) == 40:
        resultbox.insert(1.0, "Hash type: SHA1")
        # print("Hash type: SHA1")
    elif len(passHash) == 32:
        resultbox.insert(1.0, "Hash type: MD5")
        # print("Hash type: MD5")
    elif len(passHash) == 56:
        resultbox.insert(1.0, "Hash type: SHA224")
        # print("Hash type: SHA224")
    else:
        resultbox.insert(1.0, "Could not detect hash type. :(")
        # print("Could not detect hash type. :(")

def timecrack():
    resultbox.delete(1.0, END)
    passwd = inputbox.get()
    crack_speed = 20000000000 #default assumed rate 
    entropy = 0
    

    passwd_len = len(passwd)

    policies = { 'Uppercase characters': 0,
                 'Lowercase characters': 0,
                 'Special characters': 0,
                 'Numbers': 0
               }
    entropies = { 'Uppercase characters': 26,
                 'Lowercase characters': 26,
                 'Special characters': 33,
                 'Numbers': 10
               }
            
    for char in passwd:
        if re.match("[\[\] !\"#$%&'()*+,-./:;<=>?@\\^_`{|}~]", char):
            policies["Special characters"] += 1
        if re.match("[a-z]",char):
            policies["Lowercase characters"] += 1
        if re.match("[A-Z]",char):
            policies["Uppercase characters"] += 1
        if re.match("[0-9]",char):
            policies["Numbers"] += 1
    for policy in policies.keys():
    
        if policies[policy] > 0:
            entropy += entropies[policy]
   
    time_ = "minutes"
    speed = ((entropy**passwd_len) / crack_speed) / 60 # seconds in hour
    
    if speed > 60:
        speed = speed / 60
        time_ = "hour"

    if speed > 24:
        speed = speed / 24
        time_ = "days"

    if speed > 365:
        speed = speed / 365
        time_ = "years"

    if time_ == "years" and speed > 100:
        speed = speed / 100
        time_ = "centuries"

    if time_ == "centuries" and speed > 1000:
        speed = speed / 1000
        time_ = "millennia"

    if int(speed) < .01:
        resultbox.insert(1.0, "Time to crack password: {:,.9f} {}".format(speed, time_))
        # print("Time to crack password: {:,.9f} {}".format(speed, time_))
        
    if int(speed) > .01:
        resultbox.insert(1.0, "Time to crack password: {:,.9f} {}".format(speed, time_))
        # print("Time to crack password: {:,.2f} {}".format(speed, time_))

def hashpass():
    resultbox.delete(1.0, END)
    str = inputbox.get()
    result = sha1(str.encode())
    resultbox.insert(1.0, "SHA1   Hash: " + result.hexdigest() + "\n")
    # print("SHA1   Hash: " + result.hexdigest())
    result = sha224(str.encode())
    resultbox.insert(1.0, "SHA224 Hash: " + result.hexdigest() + "\n")
    
    result =sha256(str.encode())
    resultbox.insert(1.0, "SHA256 Hash: " + result.hexdigest() + "\n")
    # print("SHA256 Hash: " + result.hexdigest())
    str = str
    result = sha384(str.encode())
    resultbox.insert(1.0, "SHA384 Hash: " +result.hexdigest() + "\n")
    str = str
    result = md5(str.encode())
    resultbox.insert(1.0, "MD5 Hash: " + result.hexdigest() + "\n")
    # print("MD5 Hash: " + result.hexdigest())

def comparepassword():
    resultbox.delete(1.0, END)
    password = inputbox.get()
    wordlist = open("rockyou_clean.txt", "r", encoding="utf-8")
    count = 0
    for word in wordlist:
        word = word.strip()
        if word == password:
            resultbox.insert(1.0, "This password is leaked. Please use a different password.")
            count = 1
            break
    
    if count == 0:
        resultbox.insert(1.0, "This password is not leaked.")

    wordlist.close()

def crackhash():
    resultbox.delete(1.0, END)
    passHash = inputbox.get()
    wordList = open("rockyou_clean.txt","r", encoding="utf-8")
    count = 0

    if len(passHash) == 32:
        for word in wordList:
            word = word.strip()
            guess = md5(word.encode("utf-8"))
            if guess.hexdigest() == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 64:
        for word in wordList:
            word = word.strip()
            guess = sha256(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 40:
        for word in wordList:
            word = word.strip()
            guess = sha1(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 96:
        for word in wordList:
            word = word.strip()
            guess = sha384(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 56:
        for word in wordList:
            word = word.strip()
            guess = sha224(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 128:
        for word in wordList:
            word = word.strip()
            guess = sha512(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                resultbox.insert(1.0, "Password is: " + word)
                # print("Password is: " + word)
                count = 1
                break

    if count == 0:
        resultbox.insert(1.0, "Password not found")
        # print("Password not found")
    wordList.close()

def hex_encrypt():
    resultbox.delete(1.0, END)
    input_data = inputbox.get()
    result = []
    for character in input_data:
        modified_string = hex(ord(character)).replace("0x", "")
        if len(modified_string) == 1: modified_string = "0" + modified_string;
        result.append(modified_string)
        # print(result)
    resultbox.insert(1.0, result)

def hex_decrypt():
    resultbox.delete(1.0, END)
    input_data = inputbox.get()
    result = ""
    byte_array = bytearray.fromhex(input_data)
    result = byte_array.decode()
    resultbox.insert(1.0, result)

def decryptb64_data(input_data):
        decrypted_word = base64.b64decode(input_data)
        unbyted_word = decrypted_word.decode()
        # print(unbyted_word)
        return unbyted_word
# decrypt_data(data1)

def encryptb64_data():
    resultbox.delete(1.0, END)
    input_data = inputbox.get()
    byted_word = bytes(input_data, "utf-8")
    encrypted_word = base64.b64encode(byted_word)
    unbyted_b64 = encrypted_word.decode()
    resultbox.insert(1.0, unbyted_b64)
    

def decryption():
    resultbox.delete(1.0, END)
    input_data = inputbox.get()
    decrypted_data = ""
    if input_data[-1] == "=":
        decrypted_data = decryptb64_data(input_data)
        resultbox.insert(1.0, decrypted_data)
    elif len(input_data) % 4 != 1:
        decrypted_data = decryptb64_data(input_data)
        resultbox.insert(1.0, decrypted_data)
    
def binary_encrypt(input_data):
    formatted_binary = ""
    binary = ""
    byte_word = input_data.encode("utf-8")
    for character in byte_word:
        binary_num = bin(character)
        binary += binary_num
    for character in binary:
        if character != "b":
            formatted_binary += character

    return formatted_binary

def binary_decrypt(input_data):

    def BinaryToDecimal(binary):
        string = int(binary, 2)
        return string
    
    str_data = " "

    for i in range(0, len(input_data), 8):
        temp_data = input_data[i:i + 8]
        decimal_data = BinaryToDecimal(temp_data)
        str_data = str_data + chr(decimal_data) 
    
    return str_data

def binary_encoding():
    resultbox.delete(1.0, END)
    input_data = inputbox.get()
    if input_data[4] == "0" or input_data[4] == "1":
        result = binary_decrypt(input_data)
    else:
        result = binary_encrypt(input_data)

    resultbox.insert(1.0, result)

def input_clear(e):
    if inputbox.get() == "Insert password or hash here-":
        inputbox.delete(0,END)
# title
root.title("PTool") 
title = tk.Label(root, text="PTool", bg="black", fg="Blue", font=("Helvetica", 56))
title.pack()
titlewindow = canvas.create_window(300, 60, window=title)
# input box
inputbox=Entry(root, width=40, bg="white", font=("Helvetica", 14), bd=0)
inputbox.pack()
inputbox.insert(0, "Insert password or hash here-")
inputboxwindow = canvas.create_window(300, 120, window=inputbox)

# result box
resultbox = Text(root, width=65, height=17, font=("Helvetica", 12))
resultbox.pack()
resultboxwindow = canvas.create_window(300, 354, window=resultbox)

# buttons
checkbutton = Button(root, text = "Grade", font=("Helvetica"), bg="grey", command=grade)
checkbutton_window = canvas.create_window(317,150, window=checkbutton)

generatebutton = Button(root,text = "Generate", font=("Helvetica"), bg="grey", command=generate)
generatebutton_window = canvas.create_window(250,150, window=generatebutton)

checkhashbutton = Button(root, text = "Analyze Hash", font=("Helvetica"), bg="grey", command=hashtype)
checkhashbutton_window = canvas.create_window(161,150, window=checkhashbutton)

crackhashbutton = Button(root, text = "Crack Hash", font=("Helvetica",), bg="grey", command=crackhash)
crackhashbutton_window = canvas.create_window(394,150, window=crackhashbutton)

comparepassbutton = Button(root, text = "Vulnerability Check", font=("Helvetica", 12), bg="grey", command=comparepassword)
comparepassbutton_window = canvas.create_window(515,150, window=comparepassbutton)

timecrackbutton = Button(root, text = "Time2Crack", font = ("Helvetica", 12), bg="grey", command=timecrack)
timecrackbutton_window = canvas.create_window(57,150, window=timecrackbutton)

hashpassbutton = Button(root, text = "Hash Password", font = ("Helvetica", 12), bg="grey", command=hashpass)
hashpassbutton_window = canvas.create_window(68,182, window=hashpassbutton)

hex_encryptbutton = Button(root, text = "Encrypt2Hex", font = ("Helvetiva", 12), bg="grey", command=hex_encrypt)
hex_encryptbutton_window = canvas.create_window(181, 182, window=hex_encryptbutton)

hex_decryptbutton = Button(root, text = "DecryptHex2Text", font = ("Helvetiva", 12), bg="grey", command=hex_decrypt)
hex_decryptbutton_window = canvas.create_window(298, 182, window=hex_decryptbutton)

b64_encode_button = Button(root, text = "Base64ToText", font = ("Helvetiva", 12), bg="grey", command=decryption)
b64_encode_window = canvas.create_window(423, 182, window=b64_encode_button)

b64_decode_button = Button(root, text = "TextToBase64", font = ("Helvetiva", 12), bg="grey", command=encryptb64_data)
b64_decode_window = canvas.create_window(539, 182, window=b64_decode_button)

binary_encode_button = Button(root, text = "Binary", font = ("Helvetiva", 12), bg="grey", command=binary_encoding)
binary_encode_window = canvas.create_window(36, 527, window=binary_encode_button)

inputbox.bind("<Button-1>", input_clear)

root.mainloop()