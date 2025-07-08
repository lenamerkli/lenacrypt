import math
import json
import warnings

try:
    from .rand import random_prime, randint
    from .prime import miller_rabin
except ImportError:
    from rand import random_prime, randint
    from prime import miller_rabin


__all__ = [
    'RSAkey',
    'RSApubkey',
]


class RSAkey:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d

    @classmethod
    def generate(
            cls, length: int = 4096, e: int = None, miller_rounds: int = 32, max_retries: int = 10000000
    ) -> 'RSAkey':
        """
        Generate a random RSA key.

        :param length: The length of the RSA modulus in bits.
        :param e: The public exponent. If None, a random prime is chosen.
        :param miller_rounds: The number of Miller-Rabin test rounds for primality testing.
        :param max_retries: The maximum number of retries to find a suitable prime.
        :return: An instance of RSAkey containing the generated RSA key.
        """
        p = random_prime(length // 2, miller_rounds, max_retries)
        q = None
        while q is None or q == p:
            q = random_prime(length // 2, miller_rounds, max_retries)
        n = p * q
        phi = (p - 1) * (q - 1)
        if e is None:
            e = random_prime(length // 2, miller_rounds, max_retries)
            while math.gcd(e, phi) != 1:
                e = random_prime(length // 2, miller_rounds, max_retries)
        elif math.gcd(e, phi) != 1:
            raise ValueError('e must be coprime with phi(n)')
        d = pow(e, -1, phi)
        return RSAkey(n, e, d)
        
    def __str__(self) -> str:
        return f"RSAkey(n={self.n}, e={self.e}, d={self.d})"
    
    def __repr__(self) -> str:
        return self.__str__()

    def __bytes__(self):
        return self.to_bytes()
    
    def __eq__(self, other) -> bool:
        return self.n == other.n and self.e == other.e and self.d == other.d
    
    def __ne__(self, other) -> bool:
        return not self == other
    
    def __hash__(self) -> int:
        return hash((self.n, self.e, self.d))
    
    def __dict__(self) -> dict:
        return {
            'n': self.n,
            'e': self.e,
            'd': self.d
        }

    def __len__(self) -> int:
        return math.ceil(math.log2(self.n))

    @classmethod
    def from_bytes(cls, b: bytes) -> 'RSAkey':
        """
        Deserialize an RSA key from bytes.

        :param b: The bytes to deserialize from.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        byte_values = b.split(b'\x00\xFF')
        int_values = [int.from_bytes(v.replace(b'\x00\x01', b'\x00'),
                                     'big', signed=False) for v in byte_values]
        if len(int_values) < 3:
            raise ValueError('Invalid RSA key bytes.')
        return RSAkey.from_list(int_values)

    def to_bytes(self) -> bytes:
        """
        Serialize an RSA key to bytes.

        :return: The serialized bytes.
        """
        return b'\x00\xFF'.join([
            self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big', signed=False).replace(b'\x00', b'\x00\x01'),
            self.e.to_bytes((self.e.bit_length() + 7) // 8, 'big', signed=False).replace(b'\x00', b'\x00\x01'),
            self.d.to_bytes((self.d.bit_length() + 7) // 8, 'big', signed=False).replace(b'\x00', b'\x00\x01')
        ])

    @classmethod
    def from_dict(cls, d: dict) -> 'RSAkey':
        """
        Deserialize an RSA key from a dictionary.

        :param d: The dictionary to deserialize from. It must contain the keys 'e', 'd', and 'n'.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        return RSAkey(**d)

    def to_dict(self):
        """
        Serialize an RSA key to a dictionary.

        :return: The serialized dictionary.
        """
        return {'e': self.e, 'd': self.d, 'n': self.n}

    @classmethod
    def from_json(cls, j: str) -> 'RSAkey':
        """
        Deserialize an RSA key from JSON.

        :param j: The JSON string to deserialize from.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        return RSAkey(**json.loads(j))

    def to_json(self, *args, **kwargs) -> str:
        """
        Serialize an RSA key to JSON.

        :return: The serialized JSON string.
        """
        return json.dumps(self.__dict__(), *args, **kwargs)

    @classmethod
    def from_list(cls, l: list[int]) -> 'RSAkey':
        """
        Deserialize an RSA key from a list of integers.

        :param l: The list of integers to deserialize from. It must contain at least 3 integers.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        if len(l) < 3:
            raise ValueError('Invalid RSA key list.')
        return RSAkey(l[0], l[1], l[2])

    def to_list(self) -> list[int]:
        """
        Serialize an RSA key to a list of integers.

        :return: The serialized list of integers.
        """
        return [self.e, self.d, self.n]

    def _encrypt(self, m: int) -> int:
        if m > self.n:
            raise ValueError('Message too large for encryption.')
        return pow(m, self.e, self.n)

    def _decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def simple_int_encrypt(self, m: int, disable_warning: bool = False) -> int:
        """
        NOT RECOMMENDED - Encrypts an integer.

        :param m: The message to encrypt as an integer. Needs to be larger than 1 and less than n.
        :param disable_warning: Disable the warning message that this function should not be used unless you know what you are doing.
        :return: The cipher as an integer.
        """
        if not disable_warning:
            warnings.warn('This function should not be used unless you know what you are doing.')
        return self._encrypt(m)

    def simple_int_decrypt(self, c: int) -> int:
        """
        NOT RECOMMENDED - Decrypts an integer.

        :param c: The cipher to decrypt as an integer.
        :return: The message as an integer.
        """
        return self._decrypt(c)

    def is_probably_valid(self, tests: int = 32, miller_rounds: int = 32, disable_warning: bool = False) -> bool:
        """
        Experimental function to check if an RSA key is probably valid.

        :param tests: The number of tests to run. Defaults to 32.
        :param miller_rounds: The number of Miller-Rabin rounds to perform. Defaults to 32.
        :param disable_warning: Disable the warning message that this function has a high false positive rate. Defaults to False.
        :return: True if the key is probably valid, False otherwise.
        """
        if not disable_warning:
            warnings.warn('This function has a high false positive rate.')
        if not (
            isinstance(self.e, int) and
            isinstance(self.d, int) and
            isinstance(self.n, int) and
            math.gcd(self.e, self.d) == 1 and
            self.e > 1 and
            self.d > 1 and
            self.n > 2
        ):
            return False
        for i in range(tests):
            m = randint(2, self.n // 2 - 1)
            c = self._encrypt(m)
            if self._decrypt(c) != m:
                return False
        return True


class RSApubkey(RSAkey):
    def __init__(self, n: int, e: int):
        super().__init__(n, e, 0)

    @classmethod
    def generate(
            cls, length: int = 4096, e: int = None, miller_rounds: int = 32, max_retries: int = 10000000
    ) -> 'RSAkey':
        """
        NOT POSSIBLE with a public key. Use `RSAkey.generate(**kwargs)` instead. Raises a syntax error.

        :param length: not used
        :param e: not used
        :param miller_rounds: not used
        :param max_retries: not used
        :return: a syntax error
        """
        raise SyntaxError('Generating only the public key part is not supported.')

    def __str__(self) -> str:
        return f"RSApubkey(n={self.n}, e={self.e})"

    def __repr__(self) -> str:
        return self.__str__()

    def __bytes__(self):
        return self.to_bytes()

    def __eq__(self, other) -> bool:
        return self.n == other.n and self.e == other.e

    def __ne__(self, other) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def from_bytes(cls, b: bytes) -> 'RSApubkey':
        """
        Deserialize an RSA key from bytes.

        :param b: The bytes to deserialize from.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        byte_values = b.split(b'\x00\xFF')
        int_values = [int.from_bytes(v.replace(b'\x00\x01', b'\x00'),
                                     'big', signed=False) for v in byte_values]
        if len(int_values) < 2:
            raise ValueError('Invalid RSA public key bytes.')
        return RSApubkey.from_list(int_values)

    def to_bytes(self) -> bytes:
        """
        Serialize an RSA key to bytes.

        :return: The serialized bytes.
        """
        return b'\x00\xFF'.join([
            self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big', signed=False).replace(b'\x00', b'\x00\x01'),
            self.e.to_bytes((self.e.bit_length() + 7) // 8, 'big', signed=False).replace(b'\x00', b'\x00\x01'),
        ])

    @classmethod
    def from_dict(cls, d: dict) -> 'RSApubkey':
        """
        Deserialize an RSA key from a dictionary.

        :param d: The dictionary to deserialize from. It must contain the keys 'e', 'd', and 'n'.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        return cls(d['n'], d['e'])

    def to_dict(self):
        """
        Serialize an RSA key to a dictionary.

        :return: The serialized dictionary.
        """
        return {'e': self.e, 'n': self.n}

    @classmethod
    def from_json(cls, j: str) -> 'RSApubkey':
        """
        Deserialize an RSA key from JSON.

        :param j: The JSON string to deserialize from.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        return cls(**json.loads(j))

    def to_json(self, *args, **kwargs) -> str:
        """
        Serialize an RSA key to JSON.

        :return: The serialized JSON string.
        """
        return json.dumps(self.__dict__(), *args, **kwargs)

    @classmethod
    def from_list(cls, l: list[int]) -> 'RSApubkey':
        """
        Deserialize an RSA key from a list of integers.

        :param l: The list of integers to deserialize from. It must contain at least 3 integers.
        :return: An instance of RSAkey containing the deserialized RSA key.
        """
        return cls(l[0], l[1])

    def to_list(self) -> list[int]:
        """
        Serialize an RSA key to a list of integers.

        :return: The serialized list of integers.
        """
        return [self.e, self.n]

    def _decrypt(self, c: int) -> int:
        raise SyntaxError('Cannot decrypt with a public key.')

    def simple_int_decrypt(self, c: int) -> int:
        """
        NOT POSSIBLE with a public key. Raises a syntax error.

        :param c: not used
        :return: a syntax error
        """
        return self._decrypt(c)

    def is_probably_valid(self, tests: int = 32, miller_rounds: int = 32, disable_warning: bool = False) -> bool:
        """
        Experimental function to check if an RSA key is probably valid.

        :param tests: The number of tests to run. Defaults to 32.
        :param miller_rounds: The number of Miller-Rabin rounds to perform. Defaults to 32.
        :param disable_warning: Disable the warning message that this function has a high false positive rate. Defaults to False.
        :return: True if the key is probably valid, False otherwise.
        """
        if not disable_warning:
            warnings.warn('This function has a high false positive rate.')
        return (
            isinstance(self.e, int) and
            isinstance(self.n, int) and
            miller_rabin(self.e, miller_rounds) and
            miller_rabin(self.n, miller_rounds) and
            math.gcd(self.e, self.n) == 1 and
            math.gcd(self.e, self.n - 1) == 1 and
            self.e > 1 and
            self.n > 2
        )


if __name__ == '__main__':
    import unittest

    class TestRSA(unittest.TestCase):
        def test_rsa_generate(self):
            for _ in range(4):
                key = RSAkey.generate()
                self.assertTrue(key.is_probably_valid())

        def test_rsa_encrypt_decrypt(self):
            for _ in range(4):
                key = RSAkey.generate()
                message = randint(2, key.n // 2 - 1)
                encrypted = key._encrypt(message)
                decrypted = key._decrypt(encrypted)
                self.assertEqual(message, decrypted)

    unittest.main()
