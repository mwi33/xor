# Hack The Box Crypto Challenge

## Files

1.  challenge.py
2.  output.txt

### challenge.py

~~~ python
#!/usr/bin/python3
import os
flag = open('flag.txt', 'r').read().strip().encode()

class XOR:
    def __init__(self):
        self.key = os.urandom(4)
    def encrypt(self, data: bytes) -> bytes:
        xored = b''
        for i in range(len(data)):
            xored += bytes([data[i] ^ self.key[i % len(self.key)]])
        return xored
    def decrypt(self, data: bytes) -> bytes:
        return self.encrypt(data)

def main():
    global flag
    crypto = XOR()
    print ('Flag:', crypto.encrypt(flag).hex())

if __name__ == '__main__':
    main()
~~~

The challenge scripts contains a class (XOR) and a function (main), which instanciates an object (crypto).

The XOR class containes 3 methods, init, encrypt and decrypt.  The script imports the data from a external text file (flag.txt), which is the data that is encrypted with a xor cipher.  This is the encrypt method in the XOR class.

The __init__ method generates a random 4 byte key using the 'os.urandom()' library.  Everytime an XOR object is created a new, random 4 byte key is created to encrypt the data.

### output.txt

~~~ txt
Flag: 134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9
~~~

The data in the output.txt file is the product of the flag.txt data which has been encrypted with a random 4 byte key.

## The challenge

The challenge is to identify the random key that was used to encrypt the flag.txt data and create the string that is provided in the output.txt file.

flag.txt ^ os.urandom(4) = output.txt

## Solution

We know that all HTB challenges accept a flag in a standard format 'HTB{flag}.  We can use this to develop part of the solution algorithm.  The four characters that we know also correlates with the size of the random key (4).

We also know that result of the XOR encryption from the output.txt file.

The method of finding the key is to brute-force the key:

1. H ^ key = 13
2. T ^ key = 4a
3. B ^ key = f6
4. { ^ key = e1

the 'key' value is identified 

