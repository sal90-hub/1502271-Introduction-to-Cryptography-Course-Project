Affine_Matrix = [
    [1, 0, 0, 0, 1, 1, 1, 1],
    [1, 1, 0, 0, 0, 1, 1, 1],
    [1, 1, 1, 0, 0, 0, 1, 1],
    [1, 1, 1, 1, 0, 0, 0, 1],
    [1, 1, 1, 1, 1, 0, 0, 0],
    [0, 1, 1, 1, 1, 1, 0, 0],
    [0, 0, 1, 1, 1, 1, 1, 0],
    [0, 0, 0, 1, 1, 1, 1, 1]
]
Inv_Affine_Matrix = [
    [0, 0, 1, 0, 0, 1, 0, 1],
    [1, 0, 0, 1, 0, 0, 1, 0],
    [0, 1, 0, 0, 1, 0, 0, 1],
    [1, 0, 1, 0, 0, 1, 0, 0],
    [0, 1, 0, 1, 0, 0, 1, 0],
    [0, 0, 1, 0, 1, 0, 0, 1],
    [1, 0, 0, 1, 0, 1, 0, 0],
    [0, 1, 0, 0, 1, 0, 1, 0]
]
#In the Key Schedule, the Round Constant is only XORed against the first byte of a word
Round_Coefficient = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

state = []
key = []
round_key = []
exp_keys = []

def RotWord(word):
    return word[1:] + word[:1]  # rotate left (first byte moves to end)

def SubWord(word):
    new_value = []  # store substituted bytes
    for byte in word:  # loop each byte
        sub_value = S_BOX[byte]  # replace using S-box
        new_value.append(sub_value)  # add to result, store substituted value in a new list
    return new_value  # return substituted word

def XORWord(word1, word2):
    r = []  # result list
    for i in range(4):  # loop over 4 bytes
        r.append(word1[i] ^ word2[i])  # XOR each byte
    return r  # return result

def g_func(word, round_number):
    word = RotWord(word)  # rotate word
    word = SubWord(word)  # substitute bytes
    #only modify the first byte of the word (32b) during the constant-addition step
    word = XORWord(word, Round_Coefficient[round_number])  # XOR with RCON
    return word  # return new word

def Key_Schedule(key_input):
    global exp_keys  # use global list
    exp_keys = []  # reset list

    for i in range(4):  # first 4 words
        word = []  # new word
        for j in range(4):  # 4 bytes per word
            word.append(key_input[j][i])  # column-wise fill
        exp_keys.append(word)  # store word

    for i in range(4, 44):  # generate rest words w4-w43
        temp = exp_keys[i - 1][:]  # copy previous word

        if i % 4 == 0:  # every 4th word
            #ensures that a change in just one bit of the original key results in massive, unpredictable changes in all future round keys (Diffusion)
            temp = g_func(temp, (i // 4) - 1)  # apply g function, we are selecting the correct RCON index

        new_word = XORWord(exp_keys[i - 4], temp)  # XOR result with word 4 positions before
        exp_keys.append(new_word)  # store new word

    return exp_keys  # return all keys

def text_to_mat(text):
    matrix = [[0]*4 for _ in range(4)]  # create empty 4x4 matrix
    k = 0  # index

    for j in range(4):  # columns
        for i in range(4):  # rows
            matrix[i][j] = ord(text[k])  # convert char to ASCII
            k += 1  # next char

    return matrix  # return matrix

#it converts the encrypted matrix into hexadecimal ciphertext
def matrix_to_text(matrix):
    text = ""  # empty string
    for j in range(4):  # columns
        for i in range(4):  # rows
            text += format(matrix[i][j], '02x')  # convert to hex
    return text  # return string

#converts ciphertext from hexadecimal into a matrix for decryption
def hex_to_mat(hex_text):
    matrix = [[0]*4 for _ in range(4)]  # empty matrix
    k = 0  # index

    for j in range(4):  # columns
        for i in range(4):  # rows
            hex_pair = hex_text[k:k+2]  # take 2 hex chars
            matrix[i][j] = int(hex_pair, 16)  # convert to int
            k += 2  # move forward

    return matrix  # return matrix

#decrypted mat -> normal text
def decryption_mat_to_text(state_input):
    text = ""  # empty string
    for j in range(4):  # columns
        for i in range(4):  # rows
            text += chr(state_input[i][j])  # convert to char
    return text  # return plaintext

#GF Multiplication - Keeps data within 8b
def GF_Multiplication(guess, byte):
    result = 0
    for i in range(8):

        if (byte & 1):
            result ^= guess #x xor 0 = x move to next bit

        Check_Overflow = guess & 0x80 #8th bit
        guess = (guess << 1) & 0xFF

        if (Check_Overflow):
            guess ^= 0x1b #xor with the AES irreducible polynomial x^8+x^4+x^3+x+1

        byte >>= 1
    return result

#Multiplicative Inverse xy = 1 - Provides nonlinearity
def Inv(byte):
    if (byte == 0):
        return 0
    for i in range(1, 256): # 256-1 = 255
        if GF_Multiplication(i, byte) == 1:
            return i
    return 0

def Generate_SBox():
    sbox = [0] * 256 #initialization
    for i in range(256): #0-255
        inverse = Inv(i)
        # Affine Mapping (Shifting/XOR) - Breaks remaining mathematical patterns
        sbox[i] = AffineMapping(inverse)
    return sbox

def AffineMapping(perbyte): #takes a byte
    b0 = (perbyte >> 0) & 1
    b1 = (perbyte >> 1) & 1
    b2 = (perbyte >> 2) & 1
    b3 = (perbyte >> 3) & 1
    b4 = (perbyte >> 4) & 1
    b5 = (perbyte >> 5) & 1
    b6 = (perbyte >> 6) & 1
    b7 = (perbyte >> 7) & 1
    row0_result = (1 * b0) ^ (0 * b1) ^ (0 * b2) ^ (0 * b3) ^ (1 * b4) ^ (1 * b5) ^ (1 * b6) ^ (1 * b7) ^ 1
    row1_result = (1 * b0) ^ (1 * b1) ^ (0 * b2) ^ (0 * b3) ^ (0 * b4) ^ (1 * b5) ^ (1 * b6) ^ (1 * b7) ^ 1
    row2_result = (1 * b0) ^ (1 * b1) ^ (1 * b2) ^ (0 * b3) ^ (0 * b4) ^ (0 * b5) ^ (1 * b6) ^ (1 * b7) ^ 0
    row3_result = (1 * b0) ^ (1 * b1) ^ (1 * b2) ^ (1 * b3) ^ (0 * b4) ^ (0 * b5) ^ (0 * b6) ^ (1 * b7) ^ 0
    row4_result = (1 * b0) ^ (1 * b1) ^ (1 * b2) ^ (1 * b3) ^ (1 * b4) ^ (0 * b5) ^ (0 * b6) ^ (0 * b7) ^ 0
    row5_result = (0 * b0) ^ (1 * b1) ^ (1 * b2) ^ (1 * b3) ^ (1 * b4) ^ (1 * b5) ^ (0 * b6) ^ (0 * b7) ^ 1
    row6_result = (0 * b0) ^ (0 * b1) ^ (1 * b2) ^ (1 * b3) ^ (1 * b4) ^ (1 * b5) ^ (1 * b6) ^ (0 * b7) ^ 1
    row7_result = (0 * b0) ^ (0 * b1) ^ (0 * b2) ^ (1 * b3) ^ (1 * b4) ^ (1 * b5) ^ (1 * b6) ^ (1 * b7) ^ 0
    result = (row0_result << 0) | (row1_result << 1) | (row2_result << 2) | (row3_result << 3) | \
             (row4_result << 4) | (row5_result << 5) | (row6_result << 6) | (row7_result << 7)
    return result

def Inv_AffineMapping(perbyte):
    b0 = (perbyte >> 0) & 1
    b1 = (perbyte >> 1) & 1
    b2 = (perbyte >> 2) & 1
    b3 = (perbyte >> 3) & 1
    b4 = (perbyte >> 4) & 1
    b5 = (perbyte >> 5) & 1
    b6 = (perbyte >> 6) & 1
    b7 = (perbyte >> 7) & 1

    row0_result = (0 * b0) ^ (0 * b1) ^ (1 * b2) ^ (0 * b3) ^ (0 * b4) ^ (1 * b5) ^ (0 * b6) ^ (1 * b7) ^ 1
    row1_result = (1 * b0) ^ (0 * b1) ^ (0 * b2) ^ (1 * b3) ^ (0 * b4) ^ (0 * b5) ^ (1 * b6) ^ (0 * b7) ^ 0
    row2_result = (0 * b0) ^ (1 * b1) ^ (0 * b2) ^ (0 * b3) ^ (1 * b4) ^ (0 * b5) ^ (0 * b6) ^ (1 * b7) ^ 1
    row3_result = (1 * b0) ^ (0 * b1) ^ (1 * b2) ^ (0 * b3) ^ (0 * b4) ^ (1 * b5) ^ (0 * b6) ^ (0 * b7) ^ 0
    row4_result = (0 * b0) ^ (1 * b1) ^ (0 * b2) ^ (1 * b3) ^ (0 * b4) ^ (0 * b5) ^ (1 * b6) ^ (0 * b7) ^ 0
    row5_result = (0 * b0) ^ (0 * b1) ^ (1 * b2) ^ (0 * b3) ^ (1 * b4) ^ (0 * b5) ^ (0 * b6) ^ (1 * b7) ^ 0
    row6_result = (1 * b0) ^ (0 * b1) ^ (0 * b2) ^ (1 * b3) ^ (0 * b4) ^ (1 * b5) ^ (0 * b6) ^ (0 * b7) ^ 0
    row7_result = (0 * b0) ^ (1 * b1) ^ (0 * b2) ^ (0 * b3) ^ (1 * b4) ^ (0 * b5) ^ (1 * b6) ^ (0 * b7) ^ 0

    result = (row0_result << 0) | (row1_result << 1) | (row2_result << 2) | (row3_result << 3) | \
             (row4_result << 4) | (row5_result << 5) | (row6_result << 6) | (row7_result << 7)
    return result

def Generate_inverse_SBox():
    iinverse_SBOX = [0] * 256 #initialization
    for i in range(256):
        value = Inv_AffineMapping(i)
        iinverse_SBOX[i] = Inv(value)
    return iinverse_SBOX

inverse_S_BOX = Generate_inverse_SBox()
S_BOX = Generate_SBox()

def SubBytes(state_input):
    for row in range(4):
        for col in range(4):
            val = state_input[row][col]
            state_input[row][col] = S_BOX[val]

def Inv_SubBytes(state_input):
    for row in range(4):
        for col in range(4):
            val = state_input[row][col]
            state_input[row][col] = inverse_S_BOX[val]

def AddRoundKey(state_input, round_key_input):
    for c in range(4):
        for r in range(4):
            state_input[r][c] ^= round_key_input[c][r]

def ShiftRows(state_input):
    new_matrix = [] #initialize a new matrix to store the shifted rows
    for i in range(4):

        row = state_input[i] #loop through each rows in our state matrix

        amount_shift = (4 - i) % 4 #calculate the required amount of shifting

        shifted_row = row[-amount_shift:] + row[:-amount_shift]
        #Right shift:
        #row 1 -> no shift
        #row 2 -> right shift by 3
        #row 3 -> right shift by 2
        #row 4 -> right shift by 1

        #rebuild the state matrix row-by-row
        new_matrix.append(shifted_row) #insert each new rows values back
    for row in range(4):
        for column in range(4):
            state_input[row][column] = new_matrix[row][column]

def Inv_ShiftRows(state_input):
    Inv_matrix = [] #initialize matrix that will store the operation of restoring our original matrix

    for i in range(4) :
        row = state_input[i] #loop through each row in the shifted state matrix

        shifts = (4 - i) % 4 #calculate the required amount of shifting

        shifted_row = row[shifts:] + row[:shifts]
        #Left shift:
        # Row 1 -> no shift
        # Row 2 -> left shift by 3
        # Row 3 -> left shift by 2
        # Row 4 -> left shift by 1

        #rebuild the state matrix row-by-row
        Inv_matrix.append(shifted_row) #insert the restored row to the inverse matrix
    for row in range(4):
        for column in range(4):
            state_input[row][column] = Inv_matrix[row][column]

def MixColumns(state_input):
    new_matrix = [] #Initialization

    for i in range(4):
        new_matrix.append([0,0,0,0]) #new rows initialized in the new matrix ([0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0])

    for col in range(4):
        #The 4-bytes form the current column of state matrix
        a = state_input[0][col]
        b = state_input[1][col]
        c = state_input[2][col]
        d = state_input[3][col]

        #compute new values formulas by multiplying each col of the state matrix with each row of the constant matrix
        #constant matrix [ [02 , 03 , 01 , 01] , [01 , 02 , 03 , 01] , [01 , 01 , 02 , 03] , [03 , 01 , 01 , 02 ] ]

        new_matrix[0][col] = GF_Multiplication(a , 2) ^ GF_Multiplication(b,3) ^ c ^ d    #new0 = (2xa) XOR (3xb) XOR c XOR d
        new_matrix[1][col] = a ^ GF_Multiplication( b , 2) ^ GF_Multiplication(c , 3) ^ d #new1 = a XOR (2xb) XOR (3xc) XOR d
        new_matrix[2][col] = a ^ b ^ GF_Multiplication(c , 2) ^ GF_Multiplication(d , 3)  #new2 = a XOR b XOR (2xc) XOR (3xd)
        new_matrix[3][col] = GF_Multiplication( a , 3) ^ b ^ c ^ GF_Multiplication(d, 2)  #new3 = (3xa) XOR b XOR C XOR (2xd)

    for row in range(4):
        for column in range(4):
            state_input[row][column] = new_matrix[row][column]

def Inv_MixColumns(state_input):
    new_matrix=[] #initialization

    for i in range(4):
        new_matrix.append([0,0,0,0]) #new rows initialized in the new matrix ([0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0])

    for col in range(4) : #loop through each column
        #The 4-bytes form the current column of state matrix
        a = state_input[0][col]
        b = state_input[1][col]
        c = state_input[2][col]
        d = state_input[3][col]

        #compute the formulas that will let us retrieve our original matrix , by multiplying each col of state matrix with each row of the constant matrix
        #constant matrix [ [0E , 0B , 0D , 09] , [09 , 0E , 0B , 0D] , [0D , 09 , 0E , 0B] , [0B , 0D , 09 , 0E ] ]
        new_matrix[0][col] = GF_Multiplication(a , 14) ^ GF_Multiplication(b,11) ^ GF_Multiplication(c ,13) ^ GF_Multiplication (d , 9)  #New0 = (14xa) XOR (11xb) XOR (cx13) XOR mul(d,9)
        new_matrix[1][col] = GF_Multiplication(a,9) ^ GF_Multiplication( b , 14) ^ GF_Multiplication(c , 11) ^ GF_Multiplication(d,13)   #New1 = (ax9) XOR (14xb) XOR (11xc) XOR (dx13)
        new_matrix[2][col] = GF_Multiplication(a,13) ^ GF_Multiplication(b,9) ^ GF_Multiplication(c , 14) ^ GF_Multiplication(d , 11)    #New2 = (13xa) XOR (9xb) XOR (14xc) XOR (11xd)
        new_matrix[3][col] = GF_Multiplication( a , 11) ^ GF_Multiplication(b,13) ^ GF_Multiplication(c,9) ^ GF_Multiplication(d, 14)    #New3 = (11xa) XOR (13xb) XOR (9xC) XOR (14xd)

    for row in range(4):
        for column in range(4):
            state_input[row][column] = new_matrix[row][column]

def AES_Encryption(state_input, key_input):
    global state, key, round_key, exp_keys

    state = state_input
    key = key_input
    exp_keys = Key_Schedule(key)   #generate all round keys from the original key

    #initial round
    initial_key = exp_keys[:4]
    #To prevent an attacker from seeing the raw results of the first SubBytes step
    AddRoundKey(state, initial_key) #Key Whitening

    for round_number in range(1,10):
        SubBytes(state)
        ShiftRows(state)
        MixColumns(state)

        round_key=[]
        for i in range(4):
            #round_key expects a 4x4 matrix
            round_key.append(exp_keys[round_number * 4 + i])

        AddRoundKey(state, round_key)
        """AddRoundKey step mixes the encryption key with the state using xor operation so that the encryption
              depends on the secret key and still can be reversed during decryption"""

    #round 10
    #last round no MixColumns
    SubBytes(state)
    ShiftRows(state)

    last_key=[]
    for i in range(40,44):
        last_key.append(exp_keys[i])

    AddRoundKey(state, last_key)

    return state

def AES_Decryption(state_input, key_input):
    global state, key, round_key, exp_keys

    state = state_input
    key = key_input
    exp_keys = Key_Schedule(key)   #generate all round keys from the original key

    #round 10
    #last round no MixColumns
    last_key = exp_keys[40:44]
    AddRoundKey(state, last_key)

    #We use range(9, 0, -1) to walk backwards through the keys
    for round_number in range(9, 0, -1):
        #Undo the Shifts and Substitutions
        Inv_ShiftRows(state)
        Inv_SubBytes(state)

        #Undo the AddRoundKey for this specific round
        round_key = []
        for i in range(4):
            round_key.append(exp_keys[round_number * 4 + i])
        AddRoundKey(state, round_key)

        #Undo the MixColumns
        Inv_MixColumns(state)

    #initial round
    Inv_ShiftRows(state)
    Inv_SubBytes(state)

    initial_key = exp_keys[:4]
    AddRoundKey(state, initial_key)

    return state

def main():
    global state, key, round_key, exp_keys

    Enc_or_Dec = int(input("AES Encryption(1) or Decryption(2)? "))
    if (Enc_or_Dec == 1):
        plaintext=input("Enter the plaintext: ")
        user_key=input("Enter a key: ")

        if len(plaintext)!=16:
            print("Plaintext must be 16 characters")
            return

        if len(user_key)!=16:
            print("Key must be 16 characters")
            return

        state = text_to_mat(plaintext) #convert plaintext from string to 4x4 matrix
        key = text_to_mat(user_key)

        cipher_state = AES_Encryption(state, key)

        ciphertext = matrix_to_text(cipher_state)

        print("The ciphertext is: ", ciphertext)
    else:
        ciphertext = input("Enter the ciphertext: ")
        user_key = input("Enter the key: ")
        if len(ciphertext) != 32:
            print("Plaintext must be 32 characters")
            return

        if len(user_key) != 16:
            print("Key must be 16 characters")
            return

        state = hex_to_mat(ciphertext)  #convert cipher from hexadecimal to 4x4 matrix
        key = text_to_mat(user_key)
        plaintext_state = AES_Decryption(state, key)

        plaintext = decryption_mat_to_text(plaintext_state)

        print("The plaintext is: ", plaintext)

if __name__ == "__main__":
    main()