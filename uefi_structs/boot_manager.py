'''
Decodes/encodes structs controlling the behavior of the boot manager.
https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html
'''

from enum import unique, IntEnum, IntFlag
from dataclasses import dataclass
from typing import Union, BinaryIO
import struct
import re
from uuid import UUID
from collections.abc import MutableMapping
from .utils import *
from .variables import VariableStore, VendorStoreView, VariableData, ParsedVariable, TypedStoreView, Variable
from .device_path import DevicePath
import io

__all__ = [
	'StoreView', 'GLOBAL_VARIABLE',
	'OptKey', 'OptKeyStoreView', 'OptOrder',
	'LoadOption', 'BootOptionSupport', 'KeyOption',
]

GLOBAL_VARIABLE = UUID('8be4df61-93ca-11d2-aa0d-00e098032b8c')
'''
https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html#globally-defined-variables

vendor_guid for variables that have architecturally defined meanings
'''

@dataclass
class LoadOption(VariableData):
	'''
	https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html#load-options

	resides in a `Boot####`, `Driver####`, `SysPrep####`, `OsRecovery####` or `PlatformRecovery####` variable where #### is replaced by a unique option number in printable hexadecimal representation using the digits 0-9, and the upper case versions of the characters A-F (0000-FFFF).
	'''

	class FlagAttributes(IntFlag):
		ACTIVE = 0x00000001
		''' If set, the boot manager will attempt to boot automatically using the device path information in the load option.
			This provides an easy way to disable or enable load options without needing to delete and re-add them. '''
		FORCE_RECONNECT = 0x00000002
		''' If set, all of the UEFI drivers in the system will be disconnected and reconnected after the last Driver#### load option is processed.
			This allows a UEFI driver loaded with a Driver#### load option to override a UEFI driver that was loaded prior to the execution of the UEFI Boot Manager. '''
		HIDDEN = 0x00000008
		''' If set, the load option will not appear in the menu (if any) provided by the boot manager for load option selection '''

	@unique
	class Category(IntEnum):
		''' provides details to the boot manager to describe how it should group the Boot#### load options.
			This field is ignored for variables of the form Driver#### , SysPrep####, or OsRecovery####.
			Boot options with reserved category values, will be ignored by the boot manager. 5 bits. '''
		BOOT = 0
		''' the boot option is meant to be part of the normal boot processing. '''
		APP = 1
		''' the boot option is an executable which is not part of the normal boot processing but can be optionally chosen for execution if boot menu is provided, or via Hot Keys.
			See **Launching Boot#### Load Options Using Hot Keys** in the UEFI spec for details. '''

		@classmethod
		def get(cls, x: int):
			try:
				return cls(x)
			except ValueError:
				return x

	_CATEGORY_FIELD = 5, 8

	# attributes
	attributes: FlagAttributes
	category: Union[Category, int]

	description: str
	''' user readable description for the load option. Cannot contain NUL characters. '''
	file_path_list: bytes
	''' A packed array of UEFI device paths. The first element of the array is a device path that describes the device and location of the Image for this load option.
		The FilePathList[0] is specific to the device type. Other device paths may optionally exist in the FilePathList, but their usage is OSV specific.
		Each element in the array is variable length, and ends at the device path end structure. Maximum length 0xFFFF. '''
	optional_data: bytes
	''' binary data buffer that is passed to the loaded image.
		If the field is zero bytes long, a NULL pointer is passed to the loaded image. '''

	@property
	def file_paths(self) -> tuple['DevicePath', ...]:
		f = io.BytesIO(self.file_path_list)
		paths: list[DevicePath] = []
		while f.tell() != len(self.file_path_list):
			paths.append(DevicePath.decode(f))
		assert len(paths) >= 1, f'at least 1 path must be present'
		return tuple(paths)

	@file_paths.setter
	def file_paths(self, paths: tuple['DevicePath', ...]):
		assert len(paths) >= 1, f'at least 1 path must be present'
		f = io.BytesIO()
		for path in paths:
			path.encode(f)
		self.file_path_list = f.getvalue()

	@classmethod
	def decode(cls, f: BinaryIO):
		attrs, = read_struct(f, 'I')
		attrs, category = extract_field(attrs, cls._CATEGORY_FIELD)
		attrs = cls.FlagAttributes(attrs)
		category = cls.Category.get(category)

		fpl_len, = read_struct(f, 'H')
		description = read_char16(f)
		fpl = read(f, fpl_len)
		optional_data = f.read()
		return cls(attrs, category, description, fpl, optional_data)

	def encode(self, f: BinaryIO):
		attrs = join_field(self.attributes, self._CATEGORY_FIELD, self.category)
		f.write(encode_struct('IH', attrs, len(self.file_path_list)))
		f.write(encode_char16(self.description))
		f.write(self.file_path_list)
		f.write(self.optional_data)

@dataclass
class BootOptionSupport(VariableData):
	'''
	https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html#boot-manager-capabilities

	The boot manager can report its capabilities through the global variable `BootOptionSupport`.
	If the global variable is not present, then an installer or application must act as if a value of 0 was returned.
	'''

	class Flags(IntFlag):
		KEY = 0x00000001
		''' the boot manager supports launching of Boot#### load options using key presses '''
		APP = 0x00000002
		''' the boot manager supports boot options with `LoadOption.Category.APP` '''
		SYSPREP = 0x00000010
		''' the boot manager supports boot options of form `SysPrep####` '''

	_COUNT_FIELD = 2, 8

	flags: Flags

	count: int
	''' (0..3) maximum number of key presses which the boot manager supports in `KeyOption.keys`.
		This value is only valid if `BootOptionSupport.Flags.KEY` is set. Key sequences with more keys specified are ignored. '''

	@classmethod
	def decode(cls, f: BinaryIO):
		value, = read_struct(f, 'I')
		value, count = extract_field(value, cls._COUNT_FIELD)
		return cls(cls.Flags(value), count)

	def encode(self, f: BinaryIO):
		value = join_field(self.flags, self._COUNT_FIELD, self.count)
		f.write(encode_struct('I', value))

@dataclass
class KeyOption(VariableData):
	'''
	https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html#launching-boot-load-options-using-hot-keys

	The boot manager may support launching a `Boot####` load option using a special key press.
	If so, the boot manager reports this capability by setting `BootOptionSupport.Flags.KEY` in the BootOptionSupport global variable.

	A boot manager which supports key press launch reads the current key information from the console.
	Then, if there was a key press, it compares the key returned against zero or more `Key####` global variables.
	If it finds a match, it verifies that the `Boot####` load option specified is valid and, if so, attempts to launch it immediately.
	The #### in the `Key####` is a printable hexadecimal number (‘0’-‘9’, ‘A’-‘F’) with leading zeroes. The order which the `Key####` variables are checked is implementation-specific.

	The boot manager may ignore `Key####` variables where the hot keys specified overlap with those used for internal boot manager functions.
	It is recommended that the boot manager delete these keys.
	'''
	_REVISION = 0

	class Flags(IntFlag):
		ShiftPressed = 1 << 8
		''' either the left or right Shift keys must be pressed (1) or must not be pressed (0). '''
		ControlPressed = 1 << 9
		''' either the left or right Control keys must be pressed (1) or must not be pressed (0). '''
		AltPressed = 1 << 10
		''' either the left or right Alt keys must be pressed (1) or must not be pressed (0). '''
		LogoPressed = 1 << 11
		''' either the left or right Logo keys must be pressed (1) or must not be pressed (0). '''
		MenuPressed = 1 << 12
		''' the Menu key must be pressed (1) or must not be pressed (0). '''
		SysReqPressed = 1 << 13
		''' the SysReq key must be pressed (1) or must not be pressed (0). '''

	@dataclass(frozen=True)
	class InputKey:
		''' technically part of `EFI_SIMPLE_TEXT_INPUT_PROTOCOL`, but implemented here for convenience '''
		scan_code: int
		''' 16-bit EFI scan code defined in **EFI Scan Codes for EFI_SIMPLE_TEXT_INPUT_PROTOCOL**. '''
		unicode_char: str
		''' actual printable character, or `'\0'` if the key does not represent a printable character (control key, function key, etc.). '''

		@staticmethod
		def decode(f: BinaryIO):
			scan_code, unicode_char = read_struct(f, 'HH')
			return KeyOption.InputKey(scan_code, chr(unicode_char))

		def encode(self, f: BinaryIO):
			f.write(encode_struct('HH', self.scan_code, ord(self.unicode_char)))

	_REVISION_FIELD = 8, 0
	_INPUT_KEY_COUNT_FIELD = 2, 30

	flags: Flags

	boot_option_crc: int
	''' The CRC-32 which should match the CRC-32 of the entire `LoadOption` to which `boot_option` refers.
		If the CRC-32s do not match this value, then this key option is ignored. '''

	boot_option: int
	''' The `Boot####` option which will be invoked if this key is pressed and the boot option is active (`LoadOption.AttributeFlags.ACTIVE` is set). '''

	keys: tuple[InputKey, ...]
	''' (0..3 items) The key codes to compare against those returned by the `EFI_SIMPLE_TEXT_INPUT` and `EFI_SIMPLE_TEXT_INPUT_EX` protocols.
		If empty, then only the shift state is considered.
		If nonempty, then the boot option will only be launched if all of the specified keys are pressed with the same shift state. '''

	@classmethod
	def decode(cls, f: BinaryIO):
		data, boot_option_crc, boot_option = read_struct(f, 'IIH')
		data, revision = extract_field(data, cls._REVISION_FIELD)
		data, key_count = extract_field(data, cls._INPUT_KEY_COUNT_FIELD)
		assert revision == cls._REVISION, f'unsupported revision {revision}'
		keys = tuple(cls.InputKey.decode(f) for _ in range(key_count))
		return cls(KeyOption.Flags(data), boot_option_crc, boot_option, keys)

	def encode(self, f: BinaryIO):
		data = join_field(self.flags, self._REVISION_FIELD, self._REVISION)
		data = join_field(data, self._INPUT_KEY_COUNT_FIELD, len(self.keys))
		f.write(encode_struct('IIH', data, self.boot_option_crc, self.boot_option))
		for key in self.keys:
			key.encode(f)

class OptKey(int, VariableData):
	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(read_struct(f, 'H')[0])
	def encode(self, f: BinaryIO):
		f.write(encode_struct('H', self))
	def __repr__(self):
		return self.__format__('04X')

def read_opts(f: BinaryIO):
	while c := f.read(2):
		yield OptKey(struct.unpack('=H', c)[0])

class OptOrder(tuple[OptKey, ...], VariableData):
	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(read_opts(f))
	def encode(self, f: BinaryIO):
		for opt in self:
			opt.encode(f)

class OptKeyStoreView[C: VariableData](MutableMapping[OptKey, ParsedVariable[C]]):
	''' filters a variable store for keys of name `<prefix>####` and parses the values
		with the provided class. this is internal, you might want to use `StoreView` instead. '''

	def __init__(self, store: MutableMapping[str, Variable], prefix: str, cls: type[C]) -> None:
		self.store = store
		self.prefix = prefix
		self._id_pattern = re.compile(re.escape(prefix) + r'([\dA-F]{4})')
		self.cls = cls

	def _key(self, key: int) -> str:
		assert key == (key & 0xFFFF), f'invalid hex key {key!r}'
		return f'{self.prefix}{key:04X}'

	def __iter__(self):
		return (OptKey(m.group(1), 16) for key in self.store
			if (m := self._id_pattern.fullmatch(key)))
	def __len__(self):
		return sum(1 for _ in self)
	def __getitem__(self, key: int) -> ParsedVariable[C]:
		return self.store[self._key(key)].parse(self.cls)
	def __setitem__(self, key: int, value: ParsedVariable[C]):
		self.store[self._key(key)] = value.format()
	def __delitem__(self, key: int) -> None:
		del self.store[self._key(key)]
	def __contains__(self, key: object) -> bool:
		assert isinstance(key, int)
		return self._key(key) in self.store

	def find_free_key(self) -> OptKey:
		''' find first free key. note that this assumes no concurrent modifications to the underlying store '''
		if (key := next((n for n in range(0x10000) if n not in self), None)) != None:
			return OptKey(key)
		raise ValueError('no free keys')

	def append(self, var: ParsedVariable[C]) -> OptKey:
		''' inserts the passed variable into the first free key, returning it.
		 	note that the same warning as find_free_key applies; an existing boot entry may be modified in case of a race. '''
		self[key := self.find_free_key()] = var
		return key

class StoreView(TypedStoreView):
	''' filters an EFI variable store for globally defined variables, and exposes a parsed view of those. '''

	def __init__(self, store: VariableStore) -> None:
		super().__init__(VendorStoreView(store, GLOBAL_VARIABLE))

		self.Boot = OptKeyStoreView(self.store, 'Boot', LoadOption)
		''' Boot load options '''
		self.Driver = OptKeyStoreView(self.store, 'Driver', LoadOption)
		''' Driver load options '''
		self.SysPrep = OptKeyStoreView(self.store, 'SysPrep', LoadOption)
		''' System Prep application load options '''
		self.OsRecovery = OptKeyStoreView(self.store, 'OsRecovery', LoadOption)
		self.PlatformRecovery = OptKeyStoreView(self.store, 'PlatformRecovery', LoadOption)
		''' Platform-specified recovery options. These variables are only modified by firmware and are read-only to the OS. '''
		self.Key = OptKeyStoreView(self.store, 'Key', KeyOption)
		''' Describes hot key relationship with a Boot#### load option. '''

	BootOrder: ParsedVariable[OptOrder]
	''' The ordered boot option load list. '''
	DriverOrder: ParsedVariable[OptOrder]
	''' The ordered driver load option list. '''
	SysPrepOrder: ParsedVariable[OptOrder]
	''' The ordered System Prep Application load option list. '''
	OsRecoveryOrder: ParsedVariable[OptOrder]
	''' OS-specified recovery options. '''

	BootCurrent: ParsedVariable[OptKey]
	''' The boot option that was selected for the current boot. '''
	BootNext: ParsedVariable[OptKey]
	''' The boot option for the next boot only. '''
	BootOptionSupport: ParsedVariable[BootOptionSupport]
	''' The types of boot options supported by the boot manager. Should be treated as read-only. '''

	ConIn: ParsedVariable[DevicePath]
	''' The device path of the default input console. '''
	ConInDev: ParsedVariable[DevicePath]
	''' The device path of all possible console input devices. '''
	ConOut: ParsedVariable[DevicePath]
	''' The device path of the default output console. '''
	ConOutDev: ParsedVariable[DevicePath]
	''' The device path of all possible console output devices. '''
	ErrOut: ParsedVariable[DevicePath]
	''' The device path of the default error output device. '''
	ErrOutDev: ParsedVariable[DevicePath]
	''' The device path of all possible error output devices. '''

	# FIXME: parse these:

	AuditMode: Variable
	''' Whether the system is operating in Audit Mode (1) or not (0). All other values are reserved.
		Should be treated as read-only except when DeployedMode is 0.
		Always becomes read-only after ExitBootServices() is called. '''

	CryptoIndications: Variable
	''' Allows the OS to request the crypto algorithm to BIOS. '''
	CryptoIndicationsSupported: Variable
	''' Allows the firmware to indicate supported crypto algorithm to OS. '''
	CryptoIndicationsActivated: Variable
	''' Allows the firmware to indicate activated crypto algorithm to OS. '''

	dbDefault: Variable
	''' The OEM’s default secure boot signature store. Should be treated as read-only. '''
	dbrDefault: Variable
	''' The OEM’s default OS Recovery signature store. Should be treated as read-only. '''
	dbtDefault: Variable
	''' The OEM’s default secure boot timestamp signature store. Should be treated as read-only. '''
	dbxDefault: Variable
	''' The OEM’s default secure boot blacklist signature store. Should be treated as read-only. '''
	DeployedMode: Variable
	''' Whether the system is operating in Deployed Mode (1) or not (0). All other values are reserved. Should be treated as read-only when its value is 1. Always becomes read-only after ExitBootServices() is called. '''
	devAuthBoot: Variable
	''' Whether the platform firmware is operating in device authentication boot mode (1) or not (0). All other values are reserved. Should be treated as read-only. '''
	devdbDefault: Variable
	''' The OEM’s default device authentication signature store. Should be treated as read-only. '''

	HwErrRecSupport: Variable
	''' Identifies the level of hardware error record persistence support implemented by the platform. This variable is only modified by firmware and is read-only to the OS. '''
	KEK: Variable
	''' The Key Exchange Key Signature Database. '''
	KEKDefault: Variable
	''' The OEM’s default Key Exchange Key Signature Database. Should be treated as read-only. '''
	OsIndications: Variable
	''' Allows the OS to request the firmware to enable certain features and to take certain actions. '''
	OsIndicationsSupported: Variable
	''' Allows the firmware to indicate supported features and actions to the OS. '''
	PK: Variable
	''' The public Platform Key. '''
	PKDefault: Variable
	''' The OEM’s default public Platform Key. Should be treated as read-only. '''
	SignatureSupport: Variable
	''' Array of GUIDs representing the type of signatures supported by the platform firmware. Should be treated as read-only. '''
	SecureBoot: Variable
	''' Whether the platform firmware is operating in Secure boot mode (1) or not (0). All other values are reserved. Should be treated as read-only. '''
	SetupMode: Variable
	''' Whether the system should require authentication on SetVariable() requests to Secure Boot policy variables (0) or not (1). Should be treated as read-only.
		The system is in “Setup Mode” when SetupMode==1, AuditMode==0, and DeployedMode==0. '''
	Timeout: Variable
	''' The firmware’s boot managers timeout, in seconds, before initiating the default boot selection. '''
	VendorKeys: Variable
	''' Whether the system is configured to use only vendor-provided keys or not. Should be treated as read-only. '''

	Lang: Variable
	''' The language code that the system is configured for. This value is deprecated. '''
	LangCodes: Variable
	''' The language codes that the firmware supports. This value is deprecated. '''
	PlatformLangCodes: Variable
	''' The language codes that the firmware supports. '''
	PlatformLang: Variable
	''' The language code that the system is configured for. '''
