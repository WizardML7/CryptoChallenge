from operator import mul
from operator import xor
from functools import reduce
from struct import unpack


def hash(d):
    #>hhi
    l = b'\x3e\x68\x68\x69'

    #\n\n\n\n
    q = bytearray(b'\x0a'*4)
    d = bytearray(d)

    #Non printable
    h = b'\x00\x0b\x01\x01\x00\x14\x2a\x2d'

    h = reduce(mul, unpack(l, h))

    #>I
    l = b'\x3e\x49'

    #Non printable
    k = bytearray(b'\xc0\xf4\xb0\xb4')

    c = h ^ (h & 0x0)

    q = reduce(mul, unpack(l, bytes(map(xor, k, q))))

    k = len(d)

    y, j = h ^ c, h
    
    while (y >> (c ^ 3735928571)) < k:
        j = j ^ (((2**(4*1 << 2) - 1) * (y % (c ^ 3736977135) > 0)) & ((d[y >> (c ^ 3735928571)] * q) ^ (0xface * (y >> (c ^ 3735928571))))) & (2**(4*1 << 2) - 1)
        y += (h ^ (h - 0xf + 0x2 * 7))
    return format(j, 'x')

def inverse_expression(j, y, d, q, aConstant, bConstant):
    intermediate_result = j ^ ((d[y >> aConstant] * q) ^ (0xface * (y >> aConstant)))
    j_inverse = intermediate_result ^ (0xface * (y >> aConstant)) ^ (d[y >> aConstant] * q)
    return j_inverse

# Example values (replace with actual values):
j_value =  3735889047# Your j value
y_value =  2# Your y value
d_array =  b"D"# Your d array (list or bytes)
q_value = 3405691582 # Your q value
aConstant = c ^ 3735928571
    #DEAD BEFB

bConstant = c ^ 3736977135

# Call the function
result = inverse_expression(j_value, y_value, d_array, q_value, aConstant, bConstant)

# Print the result
print("Inverse j:", result)

def main():
    print(hash(b"Dom"))

if __name__ == "__main__":
    main()