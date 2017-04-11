import itertools

# specifications
N = 8
mx = '11011000'  # m(x)=x^8+x^4+x^3+x+1: irreducible polynomial


# required functions
# a and b are strings and the output is a string
def GF256_add(a, b, mx):  # Return a + b. mx is the irreducible polynomial
    output = [0 for i in range(0, N)]
    for i in range(0, N):
        output[i] = int(a[i]) ^ int(b[i])

    return list_to_string(output)


# a is a string and the output is a string
def GF256_multi_x(a, mx):  # Multiplied by x. mx is the irreducible polynomial
    output = [0 for i in range(0, N)]
    a_list = list(a)
    if int(a_list[N - 1]) == 0:
        for i in range(N - 1, 0, -1):
            output[i] = int(a_list[i - 1])
        output[0] = 0
    else:
        for i in range(N - 1, 0, -1):
            output[i] = int(a_list[i - 1])
        output[0] = 0
        output = GF256_add(output, mx, mx)

    return list_to_string(output)


# a and b are strings and the output is a string
def GF256_multi(a, b, mx):  # General multiplication. mx is the irreducible polynomial
    output = '00000000'
    a_list = list(a)
    b_list = list(b)
    # iterate through b
    for i in range(0, N):
        temp = a
        if int(b_list[i]) != 0:
            for j in range(0, i):
                temp = GF256_multi_x(temp, mx)
            output = GF256_add(output, temp, mx)
        else:
            pass

    return output

# a is a string and the output is a string
def GF256_inv(a, mx):  # Returns the multiplicative inverse of a. mx is the irreducible polynomial.
    lst = list(itertools.product([0, 1], repeat = N))
    for poly in lst:
        poly = list_to_string(poly)
        temp = GF256_multi(a, poly, mx)
        num = shifting(temp)
        if num == 1:
            return poly
    return '00000000'


# extra functions
# bitlist is a string and the output is an integer
def shifting(bitlist):
    bitlist = list(bitlist)
    bitlist.reverse()
    out = 0
    for bit in bitlist:
        out = (out << 1) | int(bit)
    return out


def list_to_string(lst):
    output = ''
    for i in range(0, len(lst)):
        output += str(lst[i])
    return output


# input is a string and output is a string
def binary_to_hex(input):
    return str(hex(int(input[::-1], 2)))[2:].zfill(2)
