import base64
# word = "aaaaaaa"
data1 = "YWFhYWFhYWFh"
# "ZW5jcnlwdHRoaXMhYmFzZTY0IQ=="
# encrypts word function to base64
# def testcase(word):
#     modified_word = word.encode("utf-8")
#     # print(modified_word)
#     encrypted_word = base64.b64encode(modified_word)
#     # print(encrypted_word)
#     decrypted_word = base64.b64decode(encrypted_word)
#     # print(decrypted_word)
#     unbyted_word = decrypted_word.decode()
#     # print(unbyted_word)
# testcase(word)

# decrypts word function from base64
def decryptb64_data(data1):
    decrypted_word = base64.b64decode(data1)
    unbyted_word = decrypted_word.decode()
    # print(unbyted_word)
    return unbyted_word
# print(decryptb64_data(data1))
def encryptb64_data(word):
    byted_word = bytes(word, "utf-8")
    encrypted_word = base64.b64encode(byted_word)
    unbyted_b64 = encrypted_word.decode()
    # print(unbyted_b64)
    return unbyted_b64
# print(encryptb64_data(word))

# finds what kind of encryption, runs proper decryption alg
def decryption(data1):
    decrypted_data = ""
    if data1[-1] == "=":
        decrypted_data = decryptb64_data(data1)
        print(decrypted_data)
    elif len(data1) % 4 != 1:
        decrypted_data = decryptb64_data(data1)
        print(decrypted_data)
        
decryption(data1)