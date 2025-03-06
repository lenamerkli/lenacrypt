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


if __name__ == '__main__':
    import unittest

    class TestPrime(unittest.TestCase):
        def test_primes(self):
            primes = [
                1479359201407731598997386799412769042285061448224443042084839529319001295607376503682877117743149963,
                8376394777949597152583527676137891057759384549234669575483791200228332803057459654823496932607622753,
                8443636327279220362478632103721074702146624377842499534232626312279174405121140569569659013374772081,
                5799088141750404034558633959710977277792343469924900503456645060299778374216037912920547664423460887,
            ]
            for p in primes:
                self.assertTrue(miller_rabin(p))

        def test_composites(self):
            composites = [
                6678696802781409044007131651738623988971507158184484357741459971124863948859448671589038514345611353,
                4066887234741263942674223838531897534512148310506110621848250836663613352893795060079026124032174537,
                8599082044762712703592119057139557922817673338344758767667318668032212006024518007758214021465728252,
                9240337836686008780893850661586714247747531219504598307449556452475303960384731839508904955334531871,
            ]
            for p in composites:
                self.assertFalse(miller_rabin(p))

        def test_edge_cases(self):
            self.assertFalse(miller_rabin(0))
            self.assertFalse(miller_rabin(1))
            self.assertTrue(miller_rabin(2))

    unittest.main()
