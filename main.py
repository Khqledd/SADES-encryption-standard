
sbox = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

RCON = 0x80

IP     = [2, 6, 3, 1, 4, 8, 5, 7]
IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
EP     = [4, 1, 2, 3, 2, 3, 4, 1]
P4     = [2, 4, 3, 1]

S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


def to_bits(number, length):
    binary_string = format(number, f'0{length}b')
    return [int(b) for b in binary_string]

def to_number(bits):
    binary_string = ''.join(str(b) for b in bits)
    return int(binary_string, 2)

def apply_permutation(bits, table):
    return [bits[i - 1] for i in table]

def xor(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]


# KEY GENERATION
def rot_nib(byte):
    high = (byte >> 4) & 0xF
    low  =  byte       & 0xF
    return (low << 4) | high

def sub_nib(byte):
    high = sbox[(byte >> 4) & 0xF]
    low  = sbox[byte & 0xF]
    return (high << 4) | low

def generate_keys(master_key_hex):
    master_key = int(master_key_hex, 16)

    W0 = (master_key >> 8) & 0xFF  #first byte
    W1 =  master_key       & 0xFF  #second byte

    K1 = W0

    after_rot  = rot_nib(W1)
    after_sub  = sub_nib(after_rot)
    g_W1       = after_sub ^ RCON
    K2         = W0 ^ g_W1

    print("***** Key Generation *****")
    print(f"Master key = {master_key_hex.upper()}")
    print(f"W0 = {W0:02X},  W1 = {W1:02X}")
    print(f"RotNib(W1) = {after_rot:02X}")
    print(f"SubNib({after_rot:02X}) = {after_sub:02X}")
    print(f"XOR with RCON: {after_sub:02X} XOR {RCON:02X} = {g_W1:02X}")
    print(f"K2 = W0 XOR g(W1) = {W0:02X} XOR {g_W1:02X} = {K2:02X}")
    print(f"K1 = {K1:02X},  K2 = {K2:02X}")
    print()
    return K1, K2

#ENCRYPTION
def round_function(bits, subkey):
    L = bits[:4]
    R = bits[4:]

    R_EP  = apply_permutation(R, EP)
    subkey_bits = to_bits(subkey, 8)
    xored = xor(R_EP, subkey_bits)

    left_half  = xored[:4]
    right_half = xored[4:]

    s0_row = to_number([left_half[0], left_half[3]])
    s0_col = to_number([left_half[1], left_half[2]])
    s0_out = to_bits(S0[s0_row][s0_col], 2)

    s1_row = to_number([right_half[0], right_half[3]])
    s1_col = to_number([right_half[1], right_half[2]])
    s1_out = to_bits(S1[s1_row][s1_col], 2)

    p4_out = apply_permutation(s0_out + s1_out, P4)
    new_L  = xor(L, p4_out)

    return new_L + R

def encrypt(plaintext_hex, K1, K2):
    plaintext = int(plaintext_hex, 16)
    bits = to_bits(plaintext, 8)

    print("--- Encryption ---")
    print(f"Plaintext : {plaintext_hex.upper()} = {bits}")

    after_ip    = apply_permutation(bits, IP)
    after_fk1   = round_function(after_ip, K1)
    after_sw    = after_fk1[4:] + after_fk1[:4]
    after_fk2   = round_function(after_sw, K2)
    cipher_bits = apply_permutation(after_fk2, IP_inv)
    ciphertext  = to_number(cipher_bits)

    print(f"Ciphertext: {ciphertext:02X} = {cipher_bits}")
 
    return ciphertext

master_key = "A3A7"
plaintext  = "D4"

K1, K2 = generate_keys(master_key)
ciphertext = encrypt(plaintext, K1, K2)
