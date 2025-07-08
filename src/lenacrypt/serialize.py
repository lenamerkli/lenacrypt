import typing as t
from rsa import RSAkey, RSApubkey
from aes import AES, AesExt


__all__ = [
    'serialize',
    'deserialize',
    'SUPPORTED_TYPES',
]


SUPPORTED_TYPES = [
    str, bytes, int, bool, float, list, None, tuple, dict
]


def serialize(obj: t.Any, value_only: bool = False, **kwargs) -> bytes:
    """
    Serialize an object to bytes. SUPPORTED_TYPES contains the full list of supported types.
    :param obj: The object to serialize.
    :param value_only: If True, only the value is returned (without the type).
    :param kwargs: Additional keyword arguments.
    :return: The serialized bytes.
    """
    type_: str
    value: bytes
    if isinstance(obj, str):
        encoding = 'utf-8'
        if 'encoding' in kwargs:
            encoding = kwargs['encoding']
        type_ = 'str:' + encoding
        value = obj.encode(encoding)
    elif isinstance(obj, bytes):
        type_ = 'bytes'
        value = obj
    elif isinstance(obj, int):
        byte_order = 'big'
        if 'byte_order' in kwargs:
            byte_order = kwargs['byte_order']
        value = obj.to_bytes((obj.bit_length() + 7) // 8, byte_order)
        type_ = 'int:' + byte_order
    elif isinstance(obj, bool):
        type_ = 'bool'
        if obj:
            value = b'\x01'
        else:
            value = b'\x00'
    elif isinstance(obj, float):
        type_ = 'float'
        value = str(obj).encode('utf-8')
    elif isinstance(obj, list):
        type_ = 'list'
        value = b'\x00\xFF'.join([serialize(o).replace(b'\x00', b'\x00\x01') for o in obj])
    elif obj is None:
        type_ = 'None'
        value = b''
    elif isinstance(obj, tuple):
        type_ = 'tuple'
        value = serialize(list(obj)).split(b'\x00', 1)[1]
    elif isinstance(obj, dict):
        type_ = 'dict'
        value = serialize(list(obj.items())).split(b'\x00', 1)[1]
    elif isinstance(obj, RSApubkey):
        type_ = 'RSApubkey'
        value = obj.to_bytes()
    elif isinstance(obj, RSAkey):
        type_ = 'RSAkey'
        value = obj.to_bytes()
    elif isinstance(obj, AesExt):
        type_ = 'AesExt'
        value = obj.key
    elif isinstance(obj, AES):
        type_ = 'AES'
        value = obj.key
    elif value_only:
        return repr(obj).encode('utf-8')
    else:
        raise NotImplementedError(f'Unsupported type: {type(obj)}')
    if value_only:
        return value
    return type_.encode('utf-8') + b'\x00' + value


def deserialize(b: bytes) -> t.Any:
    """
    Deserialize bytes to an object. SUPPORTED_TYPES contains the full list of supported types.
    :param b: The bytes to deserialize.
    :return: The deserialized object.
    """
    type_end = b.index(b'\x00')
    type_ = b[:type_end].decode('utf-8')
    value = b[type_end + 1:]
    if type_.startswith('str:'):
        encoding = type_.split(':')[1]
        return value.decode(encoding)
    elif type_ == 'bytes':
        return value
    elif type_.startswith('int:'):
        byte_order = type_.split(':')[1]
        if byte_order not in ('big', 'little'):
            raise ValueError(f'Unsupported byte order: {byte_order}')
        return int.from_bytes(value, byte_order)  # noqa
    elif type_ == 'bool':
        return value != b'\x00'
    elif type_ == 'float':
        return float(value.decode('utf-8'))
    elif type_ == 'list':
        if not value:
            return []
        return [deserialize(part.replace(b'\x00\x01', b'\x00')) for part in value.split(b'\x00\xFF')]
    elif type_ == 'None':
        return None
    elif type_ == 'tuple':
        if not value:
            return tuple()
        return tuple(deserialize(b'list\x00' + value))
    elif type_ == 'dict':
        if not value:
            return dict()
        return dict(deserialize(b'list\x00' + value))
    elif type_ == 'RSApubkey':
        return RSApubkey.from_bytes(value)
    elif type_ == 'RSAkey':
        return RSAkey.from_bytes(value)
    elif type_ == 'AesExt':
        return AesExt(value)
    elif type_ == 'AES':
        return AES(value)
    else:
        raise NotImplementedError(f'Unsupported type: {type_}')


if __name__ == '__main__':
    import unittest

    class TestSerialize(unittest.TestCase):
        def test_basic_types(self):
            test_objects = [
                'Hello, world!',
                b'Hello, world!',
                42,
                True,
                False,
                0b01010101,
                3.14159,
                '',
                b'',
                0,
                None,
            ]
            for obj in test_objects:
                with self.subTest(obj=obj):
                    serialized = serialize(obj)
                    deserialized = deserialize(serialized)
                    self.assertEqual(obj, deserialized)

        def test_list_serialization(self):
            test_lists = [
                [],
                [1, 2, 3],
                ['a', 'b', 'c'],
                [b'hello', b'world'],
                [1, 'two', 3.0, False],
                ['nested', [1, 2, [3, 4]]],
                [b'with\x00null', b'bytes'],
                ['', b'', 0, False],
            ]
            for lst in test_lists:
                with self.subTest(lst=lst):
                    serialized = serialize(lst)
                    deserialized = deserialize(serialized)
                    self.assertEqual(lst, deserialized)

        def test_tuple_serialization(self):
            test_tuples = [
                (),
                (1, 2, 3),
                ('a', 'b', 'c'),
                (b'hello', b'world'),
                (1, 'two', 3.0, False),
                ('nested', (1, 2, (3, 4))),
                (b'with\x00null', b'bytes'),
                ('', b'', 0, False),
            ]
            for tpl in test_tuples:
                with self.subTest(tpl=tpl):
                    serialized = serialize(tpl)
                    deserialized = deserialize(serialized)
                    self.assertEqual(tpl, deserialized)

        def test_dict_serialization(self):
            test_dicts = [
                {},
                {'a': 1, 'b': 2, 'c': 3},
                {'a': 'a', 'b': 'b', 'c': 'c'},
                {'a': b'hello', 'b': b'world'},
                {'a': 1, 'b': 'two', 'c': 3.0, 'd': False},
                {'a': 'nested', 'b': (1, 2, (3, 4))},
                {'a': b'with\x00null', 'b': b'bytes'},
                {'a': '', 'b': b'', 'c': 0, 'd': False},
            ]
            for dct in test_dicts:
                with self.subTest(dct=dct):
                    serialized = serialize(dct)
                    deserialized = deserialize(serialized)
                    self.assertEqual(dct, deserialized)

        def test_rsa_serialization(self):
            test_rsa = [
                RSApubkey.from_list([123, 456]),
                RSAkey.from_list([123, 456, 789]),
            ]
            for rsa in test_rsa:
                with self.subTest(rsa=rsa):
                    serialized = serialize(rsa)
                    deserialized = deserialize(serialized)
                    self.assertEqual(rsa, deserialized)

        def test_aes_serialization(self):
            test_aes = [
                AesExt(b'123456789012345678901234567890123456789012345678'),
                AES(b'12345678901234567890123456789012'),
            ]
            for aes in test_aes:
                with self.subTest(aes=aes):
                    serialized = serialize(aes)
                    deserialized = deserialize(serialized)
                    self.assertEqual(aes, deserialized)

    unittest.main()
