import typing as t


__all__ = [
    'serialize',
    'deserialize',
    'SUPPORTED_TYPES',
]


SUPPORTED_TYPES = [
    str, bytes, int, bool,
]


def serialize(obj: t.Any, value_only: bool = False, **kwargs) -> bytes:
    """
    Serialize an object to bytes. Currently supports the following types:
    - str
    - bytes
    - int
    - bool
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
    elif value_only:
        return repr(obj).encode('utf-8')
    else:
        raise NotImplementedError(f'Unsupported type: {type(obj)}')
    if value_only:
        return value
    return type_.encode('utf-8') + b'\x00' + value


def deserialize(b: bytes, value_only: bool = False) -> t.Any:
    """
    Deserialize bytes to an object. Supports the same types as serialize().
    :param b: The bytes to deserialize.
    :param value_only: If True, only the value is returned (without the type).
    :return: The deserialized object.
    """
    if value_only:
        return b.decode('utf-8')
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
    else:
        raise NotImplementedError(f'Unsupported type: {type_}')


if __name__ == '__main__':
    import unittest

    class TestSerialize(unittest.TestCase):
        def test_serialization(self):
            test_objects = [
                'Hello, world!',
                b'Hello, world!',
                42,
                True,
                False,
                0b01010101,
            ]
            for obj in test_objects:
                serialized = serialize(obj)
                deserialized = deserialize(serialized)
                self.assertEqual(obj, deserialized)

    unittest.main()
