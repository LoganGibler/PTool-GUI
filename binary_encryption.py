import math
from unicodedata import decimal
import sys


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

    print(formatted_binary)


def binary_decrypt(input_data):

    def BinaryToDecimal(binary):
        string = int(binary, 2)
        return string
    
    str_data = " "

    for i in range(0, len(input_data), 8):
        temp_data = input_data[i:i + 8]
        decimal_data = BinaryToDecimal(temp_data)
        str_data = str_data + chr(decimal_data) 
    
    print(str_data)


input_data = "0110100001100101011011000110110001101111"

def binary_encoding(input_data):
    if input_data[4] == "0" or input_data[4] == "1":
        binary_decrypt(input_data)
    else:
        binary_encrypt(input_data) 


binary_encoding(input_data)