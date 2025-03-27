

__all__ = [
    'AES',
    'INV_MIX_COLUMNS_MATRIX',
    'INV_SBOX',
    'MIX_COLUMNS_MATRIX',
    'RCON',
    'SBOX',
]


SBOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240,
    173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4,
    199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214,
    179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251,
    67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255,
    243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144,
    136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231,
    200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221,
    116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152,
    17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15,
    176, 84, 187, 22,
]

INV_SBOX = [SBOX.index(i) for i in range(256)]

RCON = [
    0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125,
    250, 239, 197, 145, 57,
]

MIX_COLUMNS_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

INV_MIX_COLUMNS_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]


def rotate(word):
    """
    Rotate a 4-byte word to the left by 1 byte.

    :param word: The 4-byte word to rotate.
    :return: The rotated word.
    """
    return word[1:] + word[:1]


def schedule_core(word, i):
    """
    Perform the core key expansion operation.

    :param word: The 4-byte word to expand.
    :param i: The round number.
    :return: The expanded word.
    """
    word = rotate(word)
    word = bytes([SBOX[b] for b in word])
    word = bytes([word[0] ^ RCON[i]]) + word[1:]
    return word


def expand_key(key):
    """
    Expand a 16, 24, or 32-byte key to a 176, 208, or 240-byte key.

    :param key: The key to expand.
    :return: The expanded key.
    """
    valid_key_sizes = (16, 24, 32)
    key_byte_length = len(key)
    if key_byte_length not in valid_key_sizes:
        raise ValueError(f"Invalid key size {key_byte_length}, must be one of {valid_key_sizes}")
    num_rounds = {16: 10, 24: 12, 32: 14}[key_byte_length]
    expanded_key = list(key)
    i = 1
    while len(expanded_key) < (num_rounds + 1) * key_byte_length:
        t = expanded_key[-4:]
        if len(expanded_key) % key_byte_length == 0:
            t = schedule_core(t, i)
            i += 1
        if key_byte_length == 32 and len(expanded_key) % key_byte_length == 16:
            t = bytes([SBOX[b] for b in t])
        for a in range(4):
            expanded_key.append(expanded_key[-key_byte_length] ^ t[a])
    return bytes(expanded_key)


class AES:

    def __init__(self, key: bytes):
        self.key = key

