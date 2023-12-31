from operator import mul
from operator import xor
from functools import reduce
from struct import unpack

def hash(d):
    # Define a little-endian format '>hhi'
    l = b'\x3e\x68\x68\x69'

    # Create a bytearray with four newline characters '\n\n\n\n'
    q = bytearray(b'\x0a'*4)
    
    # Convert the input string or bytes to a bytearray
    d = bytearray(d)

    # Define a non-printable byte sequence
    h = b'\x00\x0b\x01\x01\x00\x14\x2a\x2d'

    # Unpack the byte sequence 'h' using the format '>hhi' and reduce it using multiplication
    h = reduce(mul, unpack(l, h))

    # Define a big-endian format '>I'
    l = b'\x3e\x49'

    # Define a non-printable bytearray
    k = bytearray(b'\xc0\xf4\xb0\xb4')

    # XOR the elements of 'k' and 'q', then unpack the result using the format '>I' and reduce it using multiplication
    q = reduce(mul, unpack(l, bytes(map(xor, k, q))))

    # Get the length of the input bytearray 'd'
    k = len(d)

    # Initialize variables 'y' and 'j' based on 'h' and 'c'
    y, j, c = h^(h ^ (h & 0x0)), h, h ^ (h & 0x0)

    #Having y equal to the below causes the hash function to become a constant deadbeef
    #y, j, c = (h ^ (h & 0x0)), h, h ^ (h & 0x0)

    aConstant = c ^ 3735928571
    #DEAD BEFB

    bConstant = c ^ 3736977135
    count = 0

    # Perform a loop based on certain conditions
    while (y >> (aConstant)) < k:
        # Update 'j' using bitwise XOR and other operations
        # if count >= 1048574 * 1:
        #     print("Byte Array * CAFE BABE")
        #     print(d[y >> aConstant] * q)
        #     print("FACE * index")
        #     print(0xface * (y >> aConstant))
        #     print("The two previous XORed together")
        #     print(((d[y >> aConstant] * q) ^ (0xface * (y >> aConstant))))
        #     print("The j value before j operation")
        #     print(j)
        #     print("y >> aConstant")
        #     print(y >> aConstant)
        #     print("The current count")
        #     # print(count)
        #     print("\n")
            
        count += 1

        j = (j ^ (((65535) * (y % (bConstant) > 0)) & ((d[y >> aConstant] * q) ^ (0xface * (y >> aConstant))))) & (65535)
        
        # Update 'y' based on certain conditions
        y += (h ^ (h - 0xf + 0x2 * 7))
        # count += 1

    # print(count)
    # Return the final result as a hexadecimal string
    return format(j, 'x')

#c, h, j, are all DEAD BEEF prior to the first round of the while loop

#q is initialized as CAFE BABE


def main():
    result = hash(b"dome")
    # print(type(result))   str
    print(result)

if __name__ == "__main__":
    main()