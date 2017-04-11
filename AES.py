import GF256_operations as GF

# PARAMETERS
key_size = 16  # bytes, 128 bits, 32 nibbles
plaintext_block_size = 16  # in bytes, 128 bits, 32 nibbles
round_key_size = 16  # bytes, 128 bits, 32 nibbles
expanded_key_size = 176  # bytes
Nr = 10  # num of rounds
Nb = 4  # 4 * 4 * 8 = 128 bits
Nk = 4  # 4 * 4 * 8 = 128 bits
C = [0, 1, 2, 3]  # cyclic shift offsets

# affine transformation parameters
affine_transformation_matrix = [[1, 0, 0, 0, 1, 1, 1, 1],
                                [1, 1, 0, 0, 0, 1, 1, 1],
                                [1, 1, 1, 0, 0, 0, 1, 1],
                                [1, 1, 1, 1, 0, 0, 0, 1],
                                [1, 1, 1, 1, 1, 0, 0, 0],
                                [0, 1, 1, 1, 1, 1, 0, 0],
                                [0, 0, 1, 1, 1, 1, 1, 0],
                                [0, 0, 0, 1, 1, 1, 1, 1]]

inverse_affine_transformation_matrix = [[0, 0, 1, 0, 0, 1, 0, 1],
                                        [1, 0, 0, 1, 0, 0, 1, 0],
                                        [0, 1, 0, 0, 1, 0, 0, 1],
                                        [1, 0, 1, 0, 0, 1, 0, 0],
                                        [0, 1, 0, 1, 0, 0, 1, 0],
                                        [0, 0, 1, 0, 1, 0, 0, 1],
                                        [1, 0, 0, 1, 0, 1, 0, 0],
                                        [0, 1, 0, 0, 1, 0, 1, 0]]

affine_transformation_add = [1, 1, 0, 0, 0, 1, 1, 0]

# MixColumn matrix
mix_column_matrix = [['01000000', '11000000', '10000000', '10000000'],
                     ['10000000', '01000000', '11000000', '10000000'],
                     ['10000000', '10000000', '01000000', '11000000'],
                     ['11000000', '10000000', '10000000', '01000000']]

inverse_mix_column_matrix = [['01110000', '11010000', '10110000', '10010000'],
                             ['10010000', '01110000', '11010000', '10110000'],
                             ['10110000', '10010000', '01110000', '11010000'],
                             ['11010000', '10110000', '10010000', '01110000']]

RC = ['10000000', '01000000', '00100000', '00010000', '00001000', '00000100', '00000010', '00000001', '11011000', '01101100']
# END

############################################################################################
# Encrypt and Decrypt functions
def AES_Encrypt(plaintext, key):  # plaintext : 128 bits, key : 128 bits

    print('Encrypting...')

    plaintext_str_b = bin(int(plaintext, 16))[2:].zfill(plaintext_block_size * 8)[::-1]
    key_str_b = bin(int(key, 16))[2:].zfill(key_size * 8)[::-1]

    # segment binary_string
    bytes_1d = [plaintext_str_b[i * 8 : i * 8 + 8] for i in range(0, plaintext_block_size)]  # 'bytes' contains 16 strings
    bytes_2d = [["" for i in range(0, 4)] for j in range(0, 4)]
    keys_1d = [key_str_b[i * 8 : i * 8 + 8] for i in range(0, plaintext_block_size)]
    keys_2d = [["" for i in range(0, 4)] for j in range(0, 4)]

    # transform 1d bytes to 2d bytes matrix (4 x 4)
    for i in range(0, 4):
        for j in range(0, 4):
            bytes_2d[i][j] = bytes_1d[i + j * 4]

    # transform 1d keys to 2d keys matrix (4 x 4)
    for i in range(0, 4):
        for j in range(0, 4):
            keys_2d[i][j] = keys_1d[i + j * 4]

    # 0th round : add round key
    for i in range(4):
        for j in range(4):
            bytes_2d[i][j] = xor_bytes(bytes_2d[i][j], keys_2d[i][j])

    expanded_key_3d = key_expansion(keys_2d)

    # go through Nr rounds
    for i in range(0, Nr):  # Nr = 0 ~ 9
        ######### 1. ByteSub
        for j in range(0, 4):
            for k in range(0, 4):
                bytes_2d[j][k] = ByteSub(bytes_2d[j][k])
        # print('Round', i + 1, ': after ByteSub')
        # print_2d_matrix(bytes_2d)

        ######### 2. ShiftRow
        for j in range(0, 4):
            bytes_2d[j] = bytes_2d[j][C[j]:] + bytes_2d[j][:C[j]]

        ######### 3. MixColumn (only for the first (Nr - 1) rounds)
        if i < Nr - 1:  # 0 ~ 8
            bytes_2d = MixColumn(bytes_2d)

        ######### 4. AddRoundKey
        for j in range(4):
            for k in range(4):
                bytes_2d[j][k] = xor_bytes(bytes_2d[j][k], expanded_key_3d[i + 1][j][k])
    # END for rounds

    ciphertext = ''
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            ciphertext += GF.binary_to_hex(bytes_2d[j][i])

    return ciphertext

############################################################################################
def AES_Decrypt(ciphertext,  key):

    print('Decrypting...')

    ciphertext_str_b = bin(int(ciphertext, 16))[2:].zfill(plaintext_block_size * 8)[::-1]
    key_str_b = bin(int(key, 16))[2:].zfill(key_size * 8)[::-1]

    # segment binary_string
    bytes_1d = [ciphertext_str_b[i * 8: i * 8 + 8] for i in
                range(0, plaintext_block_size)]  # 'bytes' contains 16 strings
    bytes_2d = [["" for i in range(0, 4)] for j in range(0, 4)]
    keys_1d = [key_str_b[i * 8: i * 8 + 8] for i in range(0, plaintext_block_size)]
    keys_2d = [["" for i in range(0, 4)] for j in range(0, 4)]

    # transform 1d bytes to 2d bytes matrix (4 x 4)
    for i in range(0, 4):
        for j in range(0, 4):
            bytes_2d[i][j] = bytes_1d[i + j * 4]

    # transform 1d keys to 2d keys matrix (4 x 4)
    for i in range(0, 4):
        for j in range(0, 4):
            keys_2d[i][j] = keys_1d[i + j * 4]

    expanded_key_3d = key_expansion(keys_2d)

    # 0th round : add the 11th round key
    for i in range(4):
        for j in range(4):
            bytes_2d[i][j] = xor_bytes(bytes_2d[i][j], expanded_key_3d[10][i][j])

    # go through Nr rounds
    for i in range(9, -1, -1):
        # 1. inverse shift rows
        for j in range(4):
            bytes_2d[j] = bytes_2d[j][4 - C[j]:] + bytes_2d[j][:4 - C[j]]

        # 2. inverse ByteSub
        for j in range(4):
            for k in range(4):
                bytes_2d[j][k] = inverse_ByteSub(bytes_2d[j][k])

        # 3. add round keys
        for j in range(4):
            for k in range(4):
                bytes_2d[j][k] = xor_bytes(bytes_2d[j][k], expanded_key_3d[i][j][k])

        # 4. inverse MixColumn (only for the first 9 iteration)
        if i > 0:
            bytes_2d = inverse_MixColumn(bytes_2d)
    # END for

    plaintext = ''
    for i in range(3, -1, -1):
        for j in range(3, -1, -1):
            plaintext += GF.binary_to_hex(bytes_2d[j][i])

    return plaintext


################# EXTRA FUNCTIONS ##################
#
def ByteSub(byte):  # ByteSub takes 8-bit "string" as its input and output a string
    temp = [0 for i in range(0, 8)]
    for i in range(0, 8):
        temp[i] = int(byte[i])

    # find inverse of byte
    inv = GF.GF256_inv(temp, GF.mx)
    output = [0 for i in range(0, GF.N)]
    # matrix multiplication
    for i in range(0, GF.N):
        flag = 0
        for j in range(0, GF.N):
            flag ^= (int(inv[j]) * affine_transformation_matrix[i][j])
        output[i] = flag
    for i in range(0, GF.N):
        output[i] = output[i] ^ affine_transformation_add[i]

    # convert a list to a string
    return GF.list_to_string(output)


# inverse byte substitution
def inverse_ByteSub(byte):
    temp = xor_bytes(byte, affine_transformation_add)

    output = [0 for i in range(0, GF.N)]
    # matrix multiplication
    for i in range(0, GF.N):
        flag = 0
        for j in range(0, GF.N):
            flag ^= (int(temp[j]) * inverse_affine_transformation_matrix[i][j])
        output[i] = flag
    # find inverse of output
    inv = GF.GF256_inv(output, GF.mx)

    # convert a list to a string
    return GF.list_to_string(inv)


# Mix Columns operation
def MixColumn(bytes_2d):
    output = [['' for i in range(0, 4)] for j in range(0, 4)]   # output is a 4 x 4 matrix that contains strings

    for i in range(0, 4):
        for j in range(0, 4):
            temp = '00000000'  # temp is a 8-bit string

            for k in range(0, 4):
                temp = GF.GF256_add(temp, GF.GF256_multi(mix_column_matrix[i][k], bytes_2d[k][j], GF.mx), GF.mx)

            output[i][j] = temp

    return output


# inverse MixColumn
def inverse_MixColumn(bytes_2d):
    output = [['' for i in range(0, 4)] for j in range(0, 4)]   # output is a 4 x 4 matrix that contains strings

    for i in range(0, 4):
        for j in range(0, 4):
            temp = '00000000'  # temp is a 8-bit string

            for k in range(0, 4):
                temp = GF.GF256_add(temp, GF.GF256_multi(inverse_mix_column_matrix[i][k], bytes_2d[k][j], GF.mx), GF.mx)

            output[i][j] = temp

    return output

# print matrices
def print_2d_matrix(matrix_2d):
    # print('bytes_2d : ')
    for i in range(0, 4):
        print(matrix_2d[i][0], matrix_2d[i][1], matrix_2d[i][2], matrix_2d[i][3])
    return


# lowest digit is on the left
def print_2d_matrix_hex(matrix_2d):
    # print('bytes_2d : ')
    for i in range(0, 4):
        print(GF.binary_to_hex(matrix_2d[i][0]), GF.binary_to_hex(matrix_2d[i][1]), GF.binary_to_hex(matrix_2d[i][2]), GF.binary_to_hex(matrix_2d[i][3]))
    return


# key expansion operation
def key_expansion(keys_2d):
    expanded_key_3d = [[['' for i in range(4)]for j in range(4)]for k in range(0, 11)]
    # initialize expanded_key_3d[0] to keys_2d
    for i in range(4):
        for j in range(4):
            expanded_key_3d[0][i][j] = keys_2d[i][j]

    # generate other keys
    for i in range(1, 11):
        # generate the rightmost column(a list of strings)
        rightmost_column = ['' for i in range(4)]
        # assign the last round to the current column
        for j in range(4):
            rightmost_column[j] = expanded_key_3d[i - 1][j][3]

        # 1. ROTATE column
        rightmost_column = rightmost_column[1:] + rightmost_column[:1]

        # 2. ByteSub
        for j in range(0, 4):
            rightmost_column[j] = ByteSub(rightmost_column[j])

        # 3. XOR with Rcon (actually only have to xor the first byte)
        rightmost_column[0] = xor_bytes(rightmost_column[0], RC[i - 1])

        # 4. ADD
        # first, create the leftmost column in the next round
        for j in range(4):
            expanded_key_3d[i][j][0] = xor_bytes(expanded_key_3d[i - 1][j][0], rightmost_column[j])
        # second
        for k in range(1, 4):
            for j in range(0, 4):
                expanded_key_3d[i][j][k] = xor_bytes(expanded_key_3d[i - 1][j][k], expanded_key_3d[i][j][k - 1])

    return expanded_key_3d


# a and b are string and the output is a string
def xor_bytes(a, b):
    output = [0 for i in range(8)]
    for i in range(8):
        output[i] = int(a[i]) ^ int(b[i])

    return GF.list_to_string(output)
