#! /usr/bin/env python3
import random
import sys
import string
import re
from hashlib import md5, sha1, sha224, sha256, sha384, sha512
# import paramiko 
import time
import socket
# from colorama import init, Fore
# (init)

# MAKE MAN PAGE, LIKE LEGIT OPTIONS MAN ex: -gc -c -g
#  STRETCH:  maybe script asks if u want the generated password checked
#encode
#passcrack
numberlist = string.digits
specialcharslist = ["!","@","#","$","%","&"]
letterslist = string.ascii_letters


def generator():
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

    print("Your generated password: ", password)
    return password
    # passcheckgenerator(password)


# this function may seem redundant, however the "passcheck()" function requires user input, 
# while we want this passcheckgenerator function to run automatically after our generator() function runs

def passcheckgenerator(password):
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
    if uppercount == 0:
            print("Password needs an uppercase letter")
    if lowercount == 0:
            print("Password needs a lowercase letter")
    
    if len(password) < 8:
        print("Ensure password is at least 8 characters long")
    else:
        print("Password has sufficient length ") #more specific, ie 8-11 characters weak, 12-14 moderate, 15+ strong

    
    if any(char in special_characters for char in password):
        specialcharcount = 1
        print("Password has special characters :)")
    else:
        print("Needs at least 1-2 special characters")

    pass_grade = length_grade + specialcharcount + numbercount + uppercount + lowercount

    if pass_grade == 6:
        print("PTools Password Grade:  Excellent")
    if pass_grade == 5:
        print("PTools Password Grade:  Great")
    if pass_grade == 4:
        print("PTools Password Grade:  Good")
    if pass_grade <= 3:
        print("PTools Password Grade:  Bad")

    option = input("Would you like to generate another password? y/n:")

    if option == "y":
        generator()
        
    elif option == "n":
        print("Thank you for using PTool!!!")
        
    else:
        option = input("Please type 'y' or 'n':")
        if option == "y":
            generator()
        elif option == "n":
            print("Thank you for using PTool!!!")

special_characters = """!@#$%^&*()-+?_=,<>/"""

def passcheck():
    password = input("Enter password to check: ")
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
    if uppercount == 0:
            print("Password needs an uppercase letter :(")
    if lowercount == 0:
            print("Password needs a lowercase letter :(")
    
    if len(password) < 8:
        print("Ensure password is at least 8 characters long :(")
    else:
        print("Password has sufficient length :)") #more specific, ie 8-11 characters weak, 12-14 moderate, 15+ strong

    
    if any(char in special_characters for char in password):
        specialcharcount = 1
        print("Password has special characters :)")
    else:
        print("Needs at least 1-2 special characters")

    pass_grade = length_grade + specialcharcount + numbercount + uppercount + lowercount
  
    if pass_grade == 6:
        print("PTools Password Grade:  Excellent")
    if pass_grade == 5:
        print("PTools Password Grade:  Great")
    if pass_grade == 4:
        print("PTools Password Grade:  Good")
    if pass_grade <= 3:
        print("PTools Password Grade:  Bad")
    
def compare():
    string1 = input("Enter password to search for: ")
    file1 = open("rockyou_clean.txt", "r")
    readfile = file1.read()
    if string1 in readfile:
        print('You chose -->',string1 + ".", '\nThis password is compromised. Please choose again.')
    else:
        print('You chose -->', string1 , '\nThis password was not found')
    file1.close()


def hashCrack():
    passHash = input("Enter password hash:")
    wordList = open("rockyou_clean.txt","r")
    count = 0

    if len(passHash) == 128:
        print("Hash type: SHA512")
    elif len(passHash) == 96:
        print("Hash type: SHA384")
    elif len(passHash) == 64:
        print("Hash type: SHA256")
    elif len(passHash) == 40:
        print("Hash type: SHA1")
    elif len(passHash) == 32:
        print("Hash type: MD5")
    elif len(passHash) == 56:
        print("Hash type: SHA224")
    else:
        print("Could not detect hash type. :(")

    if len(passHash) == 32:
        for word in wordList:
            word = word.strip()
            guess = md5(word.encode("utf-8"))
            if guess.hexdigest() == passHash:
                print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 64:
        for word in wordList:
            word = word.strip()
            guess = sha256(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 40:
        for word in wordList:
            word = word.strip()
            guess = sha1(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 96:
        for word in wordList:
            word = word.strip()
            guess = sha384(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 56:
        for word in wordList:
            word = word.strip()
            guess = sha224(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                print("Password is: " + word)
                count = 1
                break

    if len(passHash) == 128:
        for word in wordList:
            word = word.strip()
            guess = sha512(word.encode("utf-8")).hexdigest()
            if guess == passHash:
                print("Password is: " + word)
                count = 1
                break


    if count == 0:
        print("Password not found")

def timeCrack():
    crack_speed = 20000000000 #default assumed rate 
    entropy = 0
    passwd = input("Input Password:")

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
        print("Time to crack password: {:,.9f} {}".format(speed, time_))
        
    if int(speed) > .01:
        print("Time to crack password: {:,.2f} {}".format(speed, time_))
def hash_pw():
# initializing string
    str = input("Password to hash: ")
# encoding str using SHA1
    result = sha1(str.encode())
# printing the equivalent hexadecimal value.
    print("SHA1   Hash: " + result.hexdigest())
    #print(result.hexdigest())
# encoding str using SHA224()
    result = sha224(str.encode())
# printing the equivalent hexadecimal value.
    print("SHA224 Hash: " + result.hexdigest())
    #print(result.hexdigest())
# encoding str using SHA256()
    result =sha256(str.encode())
# printing the equivalent hexadecimal value.
    print("SHA256 Hash: " + result.hexdigest())
    #print(result.hexdigest())
# initializing string
    str = str
# encoding str using SHA384()
    result = sha384(str.encode())
# printing the equivalent hexadecimal value.
    # print("SHA384 Hash: " + result.hexdigest())
    #print(result.hexdigest())
# # initializing string
# str = str
# initializing string
    str = str
# encoding str using SHA512()
    result = md5(str.encode())
# printing the equivalent hexadecimal value.
    print("MD5 Hash: " + result.hexdigest())
    #print(result.hexdigest())

# def SSHCrack():
#     GREEN = Fore.GREEN

#     def connect(hostname,username,password):
#         client = paramiko.SSHClient()
#         client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#         try:
#             client.connect(hostname=hostname, username=username, password=password, timeout=100)
        
#         except socket.timeout:
#             print(f"Host:{hostname} is unreachable, timedout.")
#             returning = False
    
#         except paramiko.AuthenticationException:
#             print(f"testing:{password}")
#             returning = False
    
#         except paramiko.SSHException:
#             print(f"Quota exeeded, continuing in : 100 seconds")
#             time.sleep(100)
#             returning = connect(hostname,username,password)
    
#         else:
#             print(f"{Fore.GREEN}Password Found: " + password)
#             return 1

    # def Main():
    #     host = input("Enter Target IP: ")
    #     user = input("Enter Username: ")
    #     passlist = input("Enter Password List: ")
    #     with open(passlist, "r") as infile:
    #         start = time.time()
    #         for word in infile:
    #             word = word.strip()
    #             con = connect(host,user,word)
    #             if con == 1:
    #                 break
    #             else:
    #                 continue
    #         end = time.time()
    #         t_time = end - start
    #         print("Total runtime was: ", t_time, "second")    

    # Main()
def main():
    option = sys.argv[1]
    if option == "--g":
        generator()
    if option == "--c":
        passcheck()
    if option == "--gc":
        password = generator()
        passcheckgenerator(password)
    if option == "--cp":
        compare()
    if option == "--ch":
        hashCrack()
    if option =="--tc":
        timeCrack()
    if option =="--hp":
        hash_pw()
    # if option =="--sc":
    #     SSHCrack()


main()
