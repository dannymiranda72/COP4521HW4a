# DES.py
import random

# Define S-box, initial and final permutation tables, expansion, permutation and PC-2 tables
S_BOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FINAL_PERMUTATION = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

EXPANSION_PERMUTATION = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31,
    32, 1
]

PERMUTATION = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

def permute(block, permutation):
    """Permutes a block of data according to a given permutation table."""
    permuted_block = 0
    for i in permutation:
        bit = (block >> (64 - i)) & 1
        permuted_block = (permuted_block << 1) | bit
    return permuted_block


def expand(block, expansion_table):
    """Expands a block of data using the expansion table."""
    return permute(block, expansion_table)

def left_shift(bits, n):
    """Shifts bits to the left by n and wraps around."""
    shifted = ((bits << n) | (bits >> (28 - n))) & 0xFFFFFFF
    return shifted


def create_subkeys(key):
    """Creates 16 48-bit subkeys from the original 56-bit key."""
    # Split the key into two 28-bit halves
    left_key = (key >> 28) & 0xFFFFFFF
    right_key = key & 0xFFFFFFF
    subkeys = []

    for _ in range(16):
        # Perform a circular left shift by 1 bit on each half
        left_key = left_shift(left_key, 1)
        right_key = left_shift(right_key, 1)
        # Combine halves and apply PC-2 to get the 48-bit round key
        combined_key = (left_key << 28) | right_key
        round_key = permute(combined_key, PC2)
        subkeys.append(round_key)

    return subkeys


def xor(a, b):
    """XOR operation between two values."""
    return a ^ b

def s_box_substitution(bits):
    """Substitute bits using the provided S-box."""
    output = 0
    for i in range(8):  # Process 8 groups of 6 bits
        # Extract 6 bits for the current S-box. The blocks are 6 bits each.
        six_bits = (bits >> (6 * (7 - i))) & 0b111111  # Extract 6 bits
        # Determine row (first and last bits) and column (middle four bits)
        row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b1)
        col = (six_bits >> 1) & 0b1111
        # Substitute with the S-box value
        output <<= 4  # Make space for the next 4 bits
        output |= S_BOX[row][col]
    return output

def des_round(l_half, r_half, key):
    """Perform a single round of DES."""
    expanded_r_half = expand(r_half, EXPANSION_PERMUTATION)
    xor_with_key = xor(expanded_r_half, key)
    substituted = s_box_substitution(xor_with_key)
    permuted = permute(substituted, PERMUTATION)
    new_r_half = xor(l_half, permuted)
    return new_r_half, r_half

def des(data_blocks, key, encrypt=True):
    """Encrypt or decrypt a list of data blocks using DES."""
    subkeys = create_subkeys(key)
    if not encrypt:
        subkeys.reverse()

    result_blocks = []
    for data_block in data_blocks:
        block = permute(data_block, INITIAL_PERMUTATION)
        l_half = (block >> 32) & 0xFFFFFFFF
        r_half = block & 0xFFFFFFFF

        for round_key in subkeys:
            l_half, r_half = des_round(l_half, r_half, round_key)

        # Final permutation (swap the two halves and permute)
        final_block = permute((r_half << 32) | l_half, FINAL_PERMUTATION)
        result_blocks.append(final_block)

    return result_blocks

def text_to_bits(text):
    """Convert a string into a list of 64-bit integer representations, padding the last block if needed."""
    blocks = []
    for i in range(0, len(text), 8):
        block = text[i:i+8]
        # Add padding length byte to the last block if needed
        if i + 8 >= len(text):
            padding_length = 8 - len(block)
            block += padding_length * chr(padding_length)
        blocks.append(int(''.join(f"{ord(c):08b}" for c in block), 2))
    return blocks

def bits_to_string(blocks, is_encrypted=False):
    """Convert a list of 64-bit integers back to a string."""
    text = ''
    for block in blocks:
        for i in range(8):
            byte = (block >> (56 - 8 * i)) & 0xFF
            if is_encrypted:
                # Directly convert each byte to char, including non-printable characters
                text += chr(byte)
            else:
                # For decrypted text, exclude padding by checking for non-printable characters
                if byte != 0:
                    text += chr(byte)
    if not is_encrypted:
        # Remove the padding length byte (last character) if this is the decrypted text
        padding_length = ord(text[-1])
        text = text[:-padding_length] if padding_length <= 8 else text
    return text


def main():
    """Main function to run DES encryption and decryption based on user input."""
    while True:
        text = input("Enter text to encrypt ('Exit' to quit): ")
        if text.lower() == 'exit':
            break

        key = random.getrandbits(56)  # Generate a random 56-bit key

        # Encrypt
        encrypted_blocks = des(text_to_bits(text), key)
        encrypted_text = bits_to_string(encrypted_blocks, True)  # Convert blocks directly to a string for encryption
        print(f"Encrypted text: {encrypted_text}")

        # Decrypt
        decrypted_blocks = des(encrypted_blocks, key, encrypt=False)
        decrypted_text = bits_to_string(decrypted_blocks, False)  # Convert blocks to string and remove padding for decryption
        print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()
