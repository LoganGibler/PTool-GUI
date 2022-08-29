import tkinter as tk
from tkinter import *
import random
import sys
import string
import re
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
# import paramiko 
import time
import socket

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
    # if uppercount == 0:
    #         print("Password needs an uppercase letter :(")
    # if lowercount == 0:
    #         print("Password needs a lowercase letter :(")
    
    # if len(password) < 8:
    #     print("Ensure password is at least 8 characters long :(")
    # else:
    #     print("Password has sufficient length :)") #more specific, ie 8-11 characters weak, 12-14 moderate, 15+ strong

    
    if any(char in special_characters for char in password):
        specialcharcount = 1
        # print("Password has special characters :)")
    # else:
    #     # print("Needs at least 1-2 special characters")

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
        speed = speed/ 100
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
    file1 = open("LeakedPasswords.txt", "r")
    readfile = file1.read()
    if password in readfile:
        resultbox.insert(1.0, 'You chose -->',password + ".", '\nThis password is compromised. Please choose again.')
        # print('You chose -->',password + ".", '\nThis password is compromised. Please choose again.')
    else:
        resultbox.insert(1.0, 'You chose -->', password , '\nThis password was not found')
        # print('You chose -->', password , '\nThis password was not found')
    file1.close()

def crackhash():
    resultbox.delete(1.0, END)
    passHash = inputbox.get()
    wordList = open("LeakedPasswords.txt","r")
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

def input_clear(e):
    if inputbox.get() == "Insert password or hash here-":
        inputbox.delete(0,END)
# title
root.title("PTool") 
title = tk.Label(root, text="PTool", bg="black", fg="Blue", font=("Helvetica", 56))
title.pack()
titlewindow = canvas.create_window(300, 120, window=title)
# input box
inputbox=Entry(root, width=40, bg="white", font=("Helvetica", 14), bd=0)
inputbox.pack()
inputbox.insert(0, "Insert password or hash here-")
inputboxwindow = canvas.create_window(300, 200, window=inputbox)

# result box
resultbox = Text(root, width=65, height=17, font=("Helvetica", 12))
resultbox.pack()
resultboxwindow = canvas.create_window(300, 400, window=resultbox)

# buttons
checkbutton = Button(root, text="Grade", font=("Helvetica"), bg="grey", command=grade)
checkbutton_window = canvas.create_window(317,230, window=checkbutton)

generatebutton = Button(root,text="Generate", font=("Helvetica"), bg="grey", command=generate)
generatebutton_window = canvas.create_window(250,230, window=generatebutton)

checkhashbutton = Button(root,text="Analyze Hash", font=("Helvetica"), bg="grey", command=hashtype)
checkhashbutton_window = canvas.create_window(161,230, window=checkhashbutton)

crackhashbutton = Button(root,text="Crack Hash", font=("Helvetica",), bg="grey", command=crackhash)
crackhashbutton_window = canvas.create_window(394,230, window=crackhashbutton)

comparepassbutton = Button(root,text="Vulnerability Check", font=("Helvetica", 12), bg="grey", command=comparepassword)
comparepassbutton_window = canvas.create_window(515,230, window=comparepassbutton)


timecrackbutton = Button(root,text="Time2Crack", font=("Helvetica", 12), bg="grey", command=timecrack)
timecrackbutton_window = canvas.create_window(59,230, window=timecrackbutton)

hashpassbutton = Button(root,text="Hash Password", font=("Helvetica", 12), bg="grey", command=hashpass)
hashpassbutton_window = canvas.create_window(75,572, window=hashpassbutton)


inputbox.bind("<Button-1>", input_clear)

root.mainloop()