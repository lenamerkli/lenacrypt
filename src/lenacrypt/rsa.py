import math
import json
from .rand import random_prime


__all__ = [
    'RSAkey'
]


class RSAkey:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d

    @classmethod
    def generate(cls, length: int = 4096, miller_rounds: int = 32, max_retries: int = 10000000) -> 'RSAkey':
        p = random_prime(length // 2, miller_rounds, max_retries)
        q = p
        while q == p:
            q = random_prime(length // 2, miller_rounds, max_retries)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random_prime(length // 2, miller_rounds, max_retries)
        while math.gcd(e, phi) != 1:
            e = random_prime(length // 2, miller_rounds, max_retries)
        d = pow(e, -1, phi)
        return RSAkey(n, e, d)
        
    def __str__(self) -> str:
        return f"RSAkey(n={self.n}, e={self.e}, d={self.d})"
    
    def __repr__(self) -> str:
        return f"RSAkey(n={self.n}, e={self.e}, d={self.d})"
    
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
    def from_dict(cls, d: dict) -> 'RSAkey':
        return RSAkey(**d)

    def to_dict(self):
        return {'e': self.e, 'd': self.d, 'n': self.n}

    @classmethod
    def from_json(cls, j: str) -> 'RSAkey':
        return RSAkey(**json.loads(j))

    def to_json(self, *args, **kwargs) -> str:
        return json.dumps(self.__dict__(), *args, **kwargs)

    def to_list(self) -> list:
        return [self.e, self.d, self.n]
