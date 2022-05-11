"""
Solution design:

Detailed solution provided in 'documentation.md'

Functions:
1.  brute_the_key:
    Checks all 255 ascii characters to identify the correct hex output for each known character (HTB{).
2.  process_each_character:
    Sends each of the known characters to the "brute_the_key" function.
3.  concatenate_keys:
    Joins each of the identified keys into one string(secret_key).
4.  decrypt_output:
    XOR the output with the secret_key to reveal the solution flag.


"""
# Output provided by HTB.  The decrypted version of this is the flag to provide submitted.
output = "134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9"

# The known characters from the HTB flag (HTB{) and the corresponding hex value.  These are also the first 8 characters of the 'output' string.
values_ascii = ['H', 'T', 'B', '{']
values_hex = ['0x13', '0x4a', '0xf6', '0xe1']

zipped_lists = list(zip(values_ascii, values_hex))

# dictionary to store the brute-forced keys. 
xor_brute_the_key = {}

# list to store the decrypted output
xor_decrypted_message = []

def brute_the_key(known_character, known_hex_output):
# using the known character and kex output check all 255 ascii characters to see if the result in the known hex output
# H ^ ascii_character = 0x13

    for potential_key in range(255):
        if ord(known_character) ^ potential_key == int(known_hex_output, 16):
            xor_brute_the_key.update({known_character:hex(potential_key)})


def process_each_character(list_data):
# send each character and its corresponding hex value to the 'brute_the_key' function.
    for character in list_data:
        brute_the_key(character[0], character[1])

def concatenate_keys(xor_dictionary):
# concatenate and trim the identified keys.
    key = []

    for keys in xor_dictionary:
        key.append(xor_dictionary[keys])
    
    for item in range(len(key)):
        key[item] = key[item][2:]

    secret_key = "".join(key)

    return secret_key

def solve_flag(output, key):

    output_bytes = bytes.fromhex(output)
    key_bytes = bytes.fromhex(key)  

    for item in range(len(output_bytes)):
        
        decrypted_item = output_bytes[item] ^ key_bytes[item % len(key_bytes)]
        xor_decrypted_message.append(chr(decrypted_item))


process_each_character(zipped_lists)

print(solve_flag(output, concatenate_keys(xor_brute_the_key)))

print("".join(xor_decrypted_message))
