try:
    from .rand import randint
except ImportError:
    from rand import randint


__all__ = [
    'AES',
    'INV_SBOX',
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


def rotate(word: list[int]) -> list[int]:
    """
    Rotate a 4-byte word to the left by 1 byte.

    :param word: The 4-byte word to rotate.
    :return: The rotated word.
    """
    return word[1:] + word[:1]


def gmul(a: int, b: int) -> int:
    """
    Multiply two elements of GF(2^8).

    :param a: The first element.
    :param b: The second element.
    :return: The product of the two elements.
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xff



def schedule_core(word: list[int], i: int) -> bytes:
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


def expand_key(key: bytes) -> bytes:
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
    lengths = {16: 176, 24: 208, 32: 240}
    return bytes(expanded_key)[:lengths[key_byte_length]]


def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    """
    XOR the state with the round key. Modifies the state in-place.

    :param state: The state matrix.
    :param round_key: The round key.
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

def sub_bytes(state: list[list[int]]) -> None:
    """
    Apply the S-box to each byte of the state. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]

def shift_rows(state: list[list[int]]) -> None:
    """
    Shift the rows of the state matrix. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]

def mix_columns(state: list[list[int]]) -> None:
    """
    Mix the columns of the state matrix. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(4):
        t = [
            gmul(state[0][i], 2) ^ gmul(state[1][i], 3) ^ state[2][i] ^ state[3][i],
            state[0][i] ^ gmul(state[1][i], 2) ^ gmul(state[2][i], 3) ^ state[3][i],
            state[0][i] ^ state[1][i] ^ gmul(state[2][i], 2) ^ gmul(state[3][i], 3),
            gmul(state[0][i], 3) ^ state[1][i] ^ state[2][i] ^ gmul(state[3][i], 2)
        ]
        for j in range(4):
            state[j][i] = t[j]

def inv_mix_columns(state: list[list[int]]) -> None:
    """
    Inverse of mix_columns. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(4):
        t = [
            gmul(state[0][i], 14) ^ gmul(state[1][i], 11) ^ gmul(state[2][i], 13) ^ gmul(state[3][i], 9),
            gmul(state[0][i], 9) ^ gmul(state[1][i], 14) ^ gmul(state[2][i], 11) ^ gmul(state[3][i], 13),
            gmul(state[0][i], 13) ^ gmul(state[1][i], 9) ^ gmul(state[2][i], 14) ^ gmul(state[3][i], 11),
            gmul(state[0][i], 11) ^ gmul(state[1][i], 13) ^ gmul(state[2][i], 9) ^ gmul(state[3][i], 14)
        ]
        for j in range(4):
            state[j][i] = t[j]

def inv_sub_bytes(state: list[list[int]]) -> None:
    """
    Inverse of sub_bytes. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_SBOX[state[i][j]]

def inv_shift_rows(state: list[list[int]]) -> None:
    """
    Inverse of shift_rows. Modifies the state in-place.

    :param state: The state matrix.
    """
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


class AES:

    def __init__(self, key: bytes = None):
        if key is None:
            key = bytes([randint(0, 255) for _ in range(32)])
        if len(key) not in [16, 24, 32]:
            raise ValueError('Key must be 16, 24, or 32 bytes long.')
        self.key = key
        self.key_schedule = expand_key(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt the plaintext using AES.
        :param plaintext: The plaintext to encrypt.
        :return: The encrypted ciphertext.
        """
        if len(plaintext) != 16:
            raise ValueError('Plaintext must be 16 bytes long.')
        state = [list(plaintext[i:i + 4]) for i in range(0, 16, 4)]
        round_keys = [self.key_schedule[i:i + 16] for i in range(0, len(self.key_schedule), 16)]
        round_keys = [[list(round_keys[i][j:j + 4]) for j in range(0, 16, 4)] for i in range(len(round_keys))]
        add_round_key(state, round_keys[0])
        for round_ in range(1, len(round_keys) - 1):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, round_keys[round_])
        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, round_keys[-1])
        return bytes([state[i][j] for i in range(4) for j in range(4)])

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt the ciphertext using AES.
        :param ciphertext: The ciphertext to decrypt.
        :return: The plaintext as bytes.
        """
        if len(ciphertext) != 16:
            raise ValueError('Ciphertext must be 16 bytes long.')
        state = [list(ciphertext[i:i + 4]) for i in range(0, 16, 4)]
        round_keys = [self.key_schedule[i:i + 16] for i in range(0, len(self.key_schedule), 16)]
        round_keys = [[list(round_keys[i][j:j + 4]) for j in range(0, 16, 4)] for i in range(len(round_keys))]
        add_round_key(state, round_keys[-1])
        inv_shift_rows(state)
        inv_sub_bytes(state)
        for round_ in range(len(round_keys)-2, 0, -1):
            add_round_key(state, round_keys[round_])
            inv_mix_columns(state)
            inv_shift_rows(state)
            inv_sub_bytes(state)
        add_round_key(state, round_keys[0])
        return bytes([state[i][j] for i in range(4) for j in range(4)])


if __name__ == '__main__':
    import unittest

    class TestAES(unittest.TestCase):
        def test_aes_key_expansion(self):
            # Test vectors from https://www.samiam.org/key-schedule.html
            test_vectors = [
                b'I \xe2\x99\xa5 RadioGatun\xda\xbd}v\x7f\x9d/\x17\x1b\xf4@Pz\x805>\x15+\xcf\xacj\xb6\xe0\xbbqB\xa0\xeb\x0b\xc2\x95\xd54\x01\xcc\x87^\xb7,</\xf5\x8c\xd7$7\x19\x02\xa6\xd5\xbb\xb1\xf8b\x97\x8d\xd7\x97\x1bZ\xf3\xa0\x02XV\xa2\xd1\xbc\xae\xc0F1yW]k\x8a\xf7_3\x1em\x12\xc2\xb0\xadT\xf3\xc9\xfa\t\x98C\rV\xab\x89\xdcp\xd89q$+\xf0\x8b-\xb3\xb3\x86{\x18M\xfd\xdd\xb5t\x8c\xf9\x9e\x84\x07\xd4-7\x81\xaf5Z\x84K/.\x08\xb2\xb1\xaa\x0ff\x9c\x9d\x8e\xc9\xa9uY\x98q[Q*\xc0\xf1^L\\l\xd0\x85\xf5',
                b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\xd6\xaat\xfd\xd2\xafr\xfa\xda\xa6x\xf1\xd6\xabv\xfe\xb6\x92\xcf\x0bd=\xbd\xf1\xbe\x9b\xc5\x00h0\xb3\xfe\xb6\xfftN\xd2\xc2\xc9\xbflY\x0c\xbf\x04i\xbfAG\xf7\xf7\xbc\x955>\x03\xf9l2\xbc\xfd\x05\x8d\xfd<\xaa\xa3\xe8\xa9\x9f\x9d\xebP\xf3\xafW\xad\xf6"\xaa^9\x0f}\xf7\xa6\x92\x96\xa7U=\xc1\n\xa3\x1fk\x14\xf9p\x1a\xe3_\xe2\x8cD\n\xdfMN\xa9\xc0&GC\x875\xa4\x1ce\xb9\xe0\x16\xba\xf4\xae\xbfz\xd2T\x992\xd1\xf0\x85Wh\x10\x93\xed\x9c\xbe,\x97N\x13\x11\x1d\x7f\xe3\x94J\x17\xf3\x07\xa7\x8bM+0\xc5',
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17XF\xf2\xf9\\C\xf4\xfeTJ\xfe\xf5XG\xf0\xfaHV\xe2\xe9\\C\xf4\xfe@\xf9I\xb3\x1c\xba\xbdMH\xf0C\xb8\x10\xb7\xb3BX\xe1Q\xab\x04\xa2\xa5U~\xff\xb5AbE\x08\x0c*\xb5K\xb4:\x02\xf8\xf6b\xe3\xa9]fA\x0c\x08\xf5\x01\x85r\x97D\x8d~\xbd\xf1\xc6\xca\x87\xf3><\xe5\x10\x97a\x83Q\x9bi4\x15|\x9e\xa3Q\xf1\xe0\x1e\xa07*\x99S\t\x16|C\x9ew\xff\x12\x05\x1e\xdd~\x0e\x88~/\xffh`\x8f\xc8B\xf9\xdc\xc1T\x85\x9f_#z\x8dZ=\xc0\xc0)R\xbe\xef\xd6:\xde`\x1ex'\xbc\xdf,\xa2#\x80\x0f\xd8\xae\xda2\xa4\x97\n3\x1ax\xdc\t\xc4\x18\xc2q\xe3\xa4\x1d]",
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\xa5s\xc2\x9f\xa1v\xc4\x98\xa9\x7f\xce\x93\xa5r\xc0\x9c\x16Q\xa8\xcd\x02D\xbe\xda\x1a]\xa4\xc1\x06@\xba\xde\xae\x87\xdf\xf0\x0f\xf1\x1bh\xa6\x8e\xd5\xfb\x03\xfc\x15gm\xe1\xf1Ho\xa5O\x92u\xf8\xebSs\xb8Q\x8d\xc6V\x82\x7f\xc9\xa7\x99\x17o)L\xecl\xd5Y\x8b=\xe2:uRGu\xe7'\xbf\x9e\xb4T\x07\xcf9\x0b\xdc\x90_\xc2{\tH\xadRE\xa4\xc1\x87\x1c/E\xf5\xa6`\x17\xb2\xd3\x870\rM3d\n\x82\n|\xcf\xf7\x1c\xbe\xb4\xfeT\x13\xe6\xbb\xf0\xd2a\xa7\xdf\xf0\x1a\xfa\xfe\xe7\xa8)y\xd7\xa5dJ\xb3\xaf\xe6@%A\xfeq\x9b\xf5\x00%\x88\x13\xbb\xd5Zr\x1c\nNZf\x99\xa9\xf2O\xe0~W+\xaa\xcd\xf8\xcd\xea$\xfcy\xcc\xbf\ty\xe97\x1a\xc2<mh\xde6",
            ]
            lengths = {176: 16, 208: 24, 240: 32}
            for i in test_vectors:
                self.assertEqual(expand_key(i[:lengths[len(i)]]), i)

        def test_aes_encrypt_decrypt(self):
            for _ in range(4):
                key = bytes([randint(0, 255) for _ in range(32)])
                message = bytes([randint(0, 255) for _ in range(16)])
                aes = AES(key)
                encrypted = aes.encrypt(message)
                decrypted = aes.decrypt(encrypted)
                self.assertEqual(message, decrypted)

    unittest.main()

