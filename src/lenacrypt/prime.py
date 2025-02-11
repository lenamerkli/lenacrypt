import secrets


__all__ = [
    'miller_rabin',
    'PRIMES',
]
PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
]


def miller_rabin(p: int, rounds: int = 32) -> bool:
    """
    The Miller-Rabin primality test.
    :param p: The number to test for primality.
    :param rounds: The number of Miller-Rabin rounds to perform.
    :return:
    """
    if p < 2:
        return False
    for n in PRIMES:
        if p == n:
            return True
        if p % n == 0:
            return False
    p_1 = p - 1
    s = 0
    while p_1 & 1 == 0:
        s += 1
        p_1 //= 2
    d = p_1
    for _ in range(rounds):
        x = pow(secrets.randbelow(p - 1) + 1, d, p)
        if x == 1 or x == p - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return False
    return True
