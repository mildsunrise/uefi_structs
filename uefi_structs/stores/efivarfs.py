'''
exposes EFI variables of the current system through [efivarfs](https://docs.kernel.org/filesystems/efivarfs.html)
'''

import os
import re
from typing import Optional
from uuid import UUID
from ..variables import VariableStore, VariableKey, Variable
from ..utils import read_struct, encode_struct

__all__ = ['Efivarfs']

class Efivarfs(VariableStore):
	def __init__(self, path: str = '/sys/firmware/efi/efivars', dir_fd: Optional[int] = None):
		''' opens an efivarfs by its mountpoint. note that beyond opening the directory,
			no verification is done that it points to an actual efivarfs mount. even if
			this succeeds, root may be needed to read some of the variables and to write most. '''
		self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY, dir_fd=dir_fd)

	def open(self, key: VariableKey, flags: int) -> int:
		return os.open(self._format_filename(key), flags, dir_fd=self.fd)

	def __iter__(self):
		return map(Efivarfs._parse_filename, os.listdir(self.fd))
	def __len__(self):
		return len(os.listdir(self.fd))

	def __getitem__(self, key: VariableKey) -> Variable:
		try:
			fd = self.open(key, os.O_RDONLY)
		except FileNotFoundError as exc:
			raise KeyError from exc
		with open(fd, 'rb') as f:
			attrs, = read_struct(f, 'I')
			return Variable(Variable.Attributes(attrs), f.read())

	def __setitem__(self, key: VariableKey, value: Variable):
		with open(self.open(key, os.O_WRONLY | os.O_TRUNC | os.O_CREAT), 'wb') as f:
			f.write(encode_struct('I', value.attributes))
			f.write(value.data)

	def __delitem__(self, key: VariableKey):
		os.unlink(Efivarfs._format_filename(key), dir_fd=self.fd)

	def __contains__(self, key: object):
		assert isinstance(key, VariableKey), f'{key} is not a VariableKey'
		return os.access(Efivarfs._format_filename(key), os.F_OK, dir_fd=self.fd)

	# utilities

	@staticmethod
	def _format_filename(key: VariableKey) -> str:
		return f'{key.name}-{key.vendor_guid}'

	_FILENAME_PATTERN = re.compile(r'(.*)-([\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12})')

	@staticmethod
	def _parse_filename(key: str) -> VariableKey:
		m = Efivarfs._FILENAME_PATTERN.fullmatch(key)
		assert m, f'invalid filename {key!r}'
		name, vendor_guid = m.groups()
		return VariableKey(UUID(vendor_guid), name)
