import typing as t
from serialize import serialize
from hashlib import sha3_256 as _sha3_256, sha3_384 as _sha3_384, sha3_512 as _sha3_512


def sha3_256(data: t.Any) -> bytes:
    if not isinstance(data, bytes):
        data = serialize(data)
    return _sha3_256(data).digest()


def sha3_384(data: t.Any) -> bytes:
    if not isinstance(data, bytes):
        data = serialize(data)
    return _sha3_384(data).digest()


def sha3_512(data: t.Any) -> bytes:
    if not isinstance(data, bytes):
        data = serialize(data)
    return _sha3_512(data).digest()


if __name__ == '__main__':
    pass
    # import unittest
    # import hashlib
    # from rand import randbytes, randint

    # class TestSHA3(unittest.TestCase):
    #     def test_sha3_256(self):
    #         for i in range(16):
    #             data = randbytes(randint(0, 1024))
    #             with self.subTest(data=data):
    #                 self.assertEqual(hashlib.sha3_256(data).digest(), sha3_256(data))

    #     def test_sha3_512(self):
    #         for i in range(16):
    #             data = randbytes(randint(0, 1024))
    #             with self.subTest(data=data):
    #                 self.assertEqual(hashlib.sha3_512(data).digest(), sha3_512(data))

    #     def test_sha3_384(self):
    #         for i in range(16):
    #             data = randbytes(randint(0, 1024))
    #             with self.subTest(data=data):
    #                 self.assertEqual(hashlib.sha3_384(data).digest(), sha3_384(data))

    # unittest.main()
