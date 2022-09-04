from functools import reduce


# input_value = "hello11"
input_value = "68656c6c6f3131"

def string_to_hex(input_value):
    result = []
    for character in input_value:
        modified_string = hex(ord(character)).replace("0x", "")
        if len(modified_string) == 1: modified_string = "0" + modified_string;
        result.append(modified_string)
        # print(result)

    return reduce(lambda i, j: i + j, result)

# print(string_to_hex(input_value))

def hex_to_string(input_data):
    result = ""
    byte_array = bytearray.fromhex(input_data)
    result = byte_array.decode()
    return result
    
print(hex_to_string("68656c6c6f3131"))