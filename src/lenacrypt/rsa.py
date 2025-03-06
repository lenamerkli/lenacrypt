import math
import json

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
        byte_values = b.split(b'\x00\xFF')
        int_values = [int.from_bytes(v.replace(b'\x00\x00', b'\x00'),
                                     'big', signed=False) for v in byte_values]
        if len(int_values) < 3:
            raise ValueError('Invalid RSA key bytes.')
        return RSAkey.from_list(int_values)

    def to_bytes(self) -> bytes:
        return b'\x00'.join([
            self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big', signed=False),
            self.e.to_bytes((self.e.bit_length() + 7) // 8, 'big', signed=False),
            self.d.to_bytes((self.d.bit_length() + 7) // 8, 'big', signed=False)
        ])

    @classmethod
    def from_dict(cls, d: dict) -> 'RSAkey':
        return RSAkey(**d)

    def to_dict(self):
        return {'e': self.e, 'd': self.d, 'n': self.n}

    @classmethod
    def from_json(cls, j: str) -> 'RSAkey':
        return RSAkey(**json.loads(j))

    def to_json(self, *args, **kwargs) -> str:
        return json.dumps(self.__dict__(), *args, **kwargs)

    @classmethod
    def from_list(cls, l: list[int]) -> 'RSAkey':
        return RSAkey(l[0], l[1], l[2])

    def to_list(self) -> list[int]:
        return [self.e, self.d, self.n]

    def _encrypt(self, m: int) -> int:
        if m > self.n:
            raise ValueError('Message too large for encryption.')
        return pow(m, self.e, self.n)

    def _decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def is_probably_valid(self, tests: int = 32, miller_rounds: int = 32) -> bool:
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

    def __str__(self) -> str:
        return f"RSApubkey(n={self.n}, e={self.e})"

    def __eq__(self, other) -> bool:
        return self.n == other.n and self.e == other.e

    def __hash__(self) -> int:
        return hash((self.n, self.e))

    @classmethod
    def from_bytes(cls, b: bytes) -> 'RSAkey':
        byte_values = b.split(b'\x00\xFF')
        int_values = [int.from_bytes(v.replace(b'\x00\x00', b'\x00'),
                                     'big', signed=False) for v in byte_values]
        if len(int_values) < 2:
            raise ValueError('Invalid RSA public key bytes.')
        return RSAkey.from_list(int_values)

    def to_bytes(self) -> bytes:
        return b'\x00'.join([
            self.n.to_bytes((self.n.bit_length() + 7) // 8, 'big', signed=False),
            self.e.to_bytes((self.e.bit_length() + 7) // 8, 'big', signed=False),
        ])

    @classmethod
    def from_dict(cls, d: dict) -> 'RSApubkey':
        return cls(d['n'], d['e'])

    def to_dict(self):
        return {'e': self.e, 'n': self.n}

    @classmethod
    def from_json(cls, j: str) -> 'RSApubkey':
        return cls(**json.loads(j))

    def to_json(self, *args, **kwargs) -> str:
        return json.dumps(self.__dict__(), *args, **kwargs)

    @classmethod
    def from_list(cls, l: list[int]) -> 'RSApubkey':
        return cls(l[0], l[1])

    def to_list(self) -> list[int]:
        return [self.e, self.n]

    def _decrypt(self, c: int) -> int:
        raise NotImplementedError('Cannot decrypt with a public key.')

    def is_probably_valid(self, tests: int = 32, miller_rounds: int = 32) -> bool:
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
