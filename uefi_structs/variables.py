'''
General definitions and utilities for EFI variables.
https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html#variable-services
'''

from collections.abc import MutableMapping
from uuid import UUID
import io
from typing import NamedTuple, Self, BinaryIO, TypeAlias, Any, get_origin, get_args
from enum import IntFlag
from abc import ABC, abstractmethod

class VariableKey(NamedTuple):
	''' a key by which an EFI variable is identified '''
	vendor_guid: UUID
	name: str

class Variable(NamedTuple):
	''' contents of a stored EFI variable '''

	class Attributes(IntFlag):
		NON_VOLATILE =                           0x00000001
		BOOTSERVICE_ACCESS =                     0x00000002
		RUNTIME_ACCESS =                         0x00000004
		HARDWARE_ERROR_RECORD =                  0x00000008
		''' This attribute is identified by the mnemonic 'HR' in the UEFI specification.'''
		AUTHENTICATED_WRITE_ACCESS =             0x00000010
		''' NOTE: deprecated and should be considered reserved.'''
		TIME_BASED_AUTHENTICATED_WRITE_ACCESS =  0x00000020
		APPEND_WRITE =                           0x00000040
		ENHANCED_AUTHENTICATED_ACCESS =          0x00000080

	attributes: Attributes
	data: bytes

	def parse[C: VariableData](self, cls: type[C]) -> 'ParsedVariable[C]':
		''' convenience method that parses the data in a `Variable` '''
		result = cls.decode(f := io.BytesIO(self.data))
		assert not (rest := f.read()), f'trailing garbage: {rest!r}'
		return ParsedVariable(self.attributes, result)

class VariableData(ABC):
	''' abstract base class for classes that parse the data of a certain kind of variable '''

	@classmethod
	@abstractmethod
	def decode(cls, f: BinaryIO) -> Self:
		''' decode / validate data read from the passed stream, returning the parsed data.
			note that this method doesn't check for the absence of trailing data, unlike Variable.parse(). '''
		...

	@abstractmethod
	def encode(self, f: BinaryIO):
		''' encode the data of this variable into the passed stream '''
		...

class ParsedVariable[C: VariableData](NamedTuple):
	attributes: Variable.Attributes
	data: C

	def format(self) -> Variable:
		''' convenience method that prepares self as an encoded `Variable` '''
		self.data.encode(f := io.BytesIO())
		return Variable(self.attributes, f.getvalue())

VariableStore: TypeAlias = MutableMapping[VariableKey, Variable]
''' dict-like object that models the EFI variable service '''

class VendorStoreView(MutableMapping[str, Variable]):
	''' convenience class that acts as a filter on an EFI variable store, exposing only the variables of a given vendor GUID '''

	def __init__(self, store: VariableStore, vendor_guid: UUID):
		self.store = store
		self.vendor = vendor_guid
	def _key(self, key: str) -> VariableKey:
		return VariableKey(self.vendor, key)
	def __iter__(self):
		return (key.name for key in self.store if key.vendor_guid == self.vendor)
	def __len__(self):
		return sum(1 for _ in self)
	def __getitem__(self, key: str) -> Variable:
		return self.store[self._key(key)]
	def __setitem__(self, key: str, value: Variable):
		self.store[self._key(key)] = value
	def __delitem__(self, key: str) -> None:
		del self.store[self._key(key)]
	def __contains__(self, key: object) -> bool:
		assert isinstance(key, str)
		return self._key(key) in self.store

class TypedStoreViewMeta(type):
	def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]):
		annotations: dict[str, type] = namespace.get('__annotations__', {})
		for name, annotation in annotations.items():
			if prop := cls.process_annotation(name, annotation):
				namespace[name] = prop
		return super().__new__(cls, name, bases, namespace)

	@classmethod
	def process_annotation(cls, name: str, annotation: type):
		if annotation is Variable:
			return cls.generic_prop(name)
		if not (get_origin(annotation) is ParsedVariable):
			return
		v_cls, = get_args(annotation)
		assert issubclass(v_cls, VariableData)
		def fget(self: TypedStoreView):
			attr = self.store.get(name)
			if attr == None: raise KeyError(name)
			return attr.parse(v_cls)
		def fset(self: TypedStoreView, value: Any):
			assert isinstance(value, ParsedVariable) and isinstance(value.data, v_cls) # pyright: ignore
			self.store[name] = value.format()
		def fdel(self: TypedStoreView):
			del self.store[name]
		return property(fget, fset, fdel)

	@classmethod
	def generic_prop(cls, name: str):
		def fget(self: TypedStoreView):
			return self.store[name]
		def fset(self: TypedStoreView, value: Any):
			self.store[name] = value
		def fdel(self: TypedStoreView):
			del self.store[name]
		return property(fget, fset, fdel)

class TypedStoreView(metaclass=TypedStoreViewMeta):
	''' convenience class that exposes a parsed view of a `VendorStoreView`
		by auto-creating properties on `ParsedVariable` or `Variable` annotations. '''

	def __init__(self, store: MutableMapping[str, Variable]):
		self.store = store
