import math
import json


__all__ = [
    'RSAkey'
]


class RSAkey:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d
        
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
        return math.ceil(math.log2(max(self.n, self.e, self.d)))

    @classmethod
    def from_dict(cls, d: dict) -> 'RSAkey':
        return RSAkey(**d)

    @classmethod
    def from_json(cls, j: str) -> 'RSAkey':
        return RSAkey(**json.loads(j))

    def to_json(self) -> str:
        return json.dumps(self.__dict__())

    @classmethod
    def generate(cls, length: int) -> 'RSAkey':
        pass

