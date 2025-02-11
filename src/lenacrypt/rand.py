import secrets
from .prime import miller_rabin


__all__ = [
    'randint',
    'random_prime',
]


def random_prime(length: int, miller_rounds: int = 20, max_retries: int = 10000000) -> int:
    """
    Generate a random prime number.
    :param length: The length of the prime in bits.
    :param miller_rounds: The number of Miller-Rabin rounds to perform.
    :param max_retries: The maximum number of retries.
    :return: A random prime number within the given constraints.
    """
    if length < 4:
        raise ValueError('Length must be at least 4.')
    for try_ in range(max_retries):
        p = randint(2 ** (length - 2), 2 ** (length - 1) - 1)
        p = p * 2 + 1
        if miller_rabin(p, miller_rounds):
            return p
    raise ValueError('Could not find a random prime within the retry limit.')


def randint(a: int, b: int) -> int:
    """
    Return a random integer N such that a <= N <= b.
    :param a: The lower bound.
    :param b: The upper bound.
    :return: A random integer N such that a <= N <= b.
    """
    return secrets.randbelow(b - a + 1) + a
