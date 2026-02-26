''' internal serialization utilities '''

import struct
from typing import BinaryIO, Union, Any

def read(f: BinaryIO, size: int) -> bytes:
	r = f.read(size)
	assert len(r) == size, f'expected {size} bytes, got {len(r)}'
	return r

def read_struct(f: BinaryIO, fmt: Union[str, struct.Struct]):
	if not isinstance(fmt, struct.Struct):
		fmt = struct.Struct('=' + fmt)
	return fmt.unpack(read(f, fmt.size))

def encode_struct(fmt: str, *val: Any):
	return struct.pack('=' + fmt, *val)

# strings

def read_char16(f: BinaryIO):
	''' read a NUL-terminated CHAR16 string '''
	str = bytearray()
	while (char := read(f, 2)) != b'\0\0':
		str.extend(char)
	return str.decode('utf-16')

def encode_char16(x: str):
	assert all(map(ord, x)), f'string cannot contain NUL'
	return str.encode('utf-16', x + '\0')[2:] # strip BOM

# bitfields

def mask(size: int, offset: int = 0):
	return (~((~0) << size)) << offset

def extract_mask(x: int, mask: int):
	return x & ~mask, (x & mask)

def extract_field(x: int, field: tuple[int, int]):
	x, value = extract_mask(x, mask(*field))
	return x, value >> field[1]

def join_field(x: int, field: tuple[int, int], value: int):
	m = mask(*field)
	value <<= field[1]
	assert not ((x & m) | (value & ~m))
	return x | value
