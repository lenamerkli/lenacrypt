import typing as t


def serialize(obj: t.Any, value_only: bool = False, **kwargs) -> bytes:
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
        type_ = 'int'
        byte_order = 'big'
        if 'byte_order' in kwargs:
            byte_order = kwargs['byte_order']
        value = obj.to_bytes((obj.bit_length() + 7) // 8, byte_order)
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

