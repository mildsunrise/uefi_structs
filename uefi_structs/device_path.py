'''
Decodes/encodes UEFI device paths.
https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html
'''

from typing import Any, ClassVar, Iterable, Optional, Self, Type, TypeAlias, Union, BinaryIO
from dataclasses import dataclass
from enum import IntEnum
import abc
import io
from uuid import UUID
from .variables import VariableData
from .utils import *

# __all__ = [
# 	'DevicePathType', 'DevicePathNode', 'read_path', 'write_path', 'DevicePath',
# ]

class DevicePathType(IntEnum):
	HARDWARE = 0x01
	''' Hardware Device Path '''
	ACPI = 0x02
	''' ACPI Device Path '''
	MESSAGING = 0x03
	''' Messaging Device Path '''
	MEDIA = 0x04
	''' Media Device Path '''
	BOOT_SPEC = 0x05
	''' BIOS Boot Specification Device Path '''
	END = 0x7F
	''' End of Hardware Device Path '''

	@classmethod
	def get(cls, x: int):
		try:
			return cls(x)
		except ValueError:
			return x

@dataclass(frozen=True)
class DevicePathNode:
	'''
	https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#generic-device-path-structures
	'''
	type: Union[DevicePathType, int]
	sub_type: int
	data: bytes

	@staticmethod
	def decode(f: BinaryIO):
		type, sub_type, len = read_struct(f, 'BBH')
		assert len >= 4, f'invalid length {len}'
		data = read(f, len - 4)
		return DevicePathNode(DevicePathType.get(type), sub_type, data)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('BBH', self.type, self.sub_type, 4 + len(self.data)))
		f.write(self.data)

	@property
	def parsed_type(self):
		return PARSERS.get((self.type, self.sub_type))

	def parse[T: DevicePathNodeData](self, base: Type[T]) -> Optional[T]:
		if (cls := self.parsed_type) and issubclass(cls, base):
			result = cls.decode(f := io.BytesIO(self.data))
			assert not (rest := f.read()), f'trailing garbage: {rest!r}'
			return result

	@property
	def parsed(self):
		if result := self.parse(DevicePathNodeData):
			return result
		raise NotImplemented

class DevicePath(tuple[DevicePathNode, ...], VariableData):
	''' a device path is a series of device path nodes, terminated by an END_PATH node '''

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(read_path(f))

	def encode(self, f: BinaryIO):
		write_path(self, f)

def read_path(f: BinaryIO):
	while not (node := DevicePathNode.decode(f)).parse(EndPath):
		yield node

def write_path(path: Iterable['DevicePathNode'], f: BinaryIO):
	for node in path:
		assert not node.parse(EndPath), f'path cannot contain END node'
		node.encode(f)
	EndPath().format().encode(f)


# Parsing machinery...

class DevicePathNodeDataMeta(abc.ABCMeta):
	def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any], partial: bool = False):
		if partial: return super().__new__(cls, name, bases, namespace)
		result = super().__new__(cls, name, bases, namespace)
		assert issubclass(result, DevicePathNodeData)
		assert isinstance(type := result.TYPE, int) and type == (type & 0xFF)
		assert isinstance(sub_type := result.SUB_TYPE, int) and sub_type == (sub_type & 0xFF)
		assert PARSERS.setdefault((type, sub_type), result) is result, f'parser for {(type, sub_type)} already registered'
		return result

class DevicePathNodeData(metaclass=DevicePathNodeDataMeta, partial=True):
	TYPE: ClassVar[Union[DevicePathType, int]]
	SUB_TYPE: ClassVar[int]
	SHORT_NAME: ClassVar[Optional[str]] = None

	@classmethod
	@abc.abstractmethod
	def decode(cls, f: BinaryIO) -> Self:
		...

	@abc.abstractmethod
	def encode(self, f: BinaryIO):
		...

	def format(self) -> DevicePathNode:
		self.encode(f := io.BytesIO())
		return DevicePathNode(self.TYPE, self.SUB_TYPE, f.getvalue())

PARSERS: dict[tuple[int, int], type[DevicePathNodeData]] = {}


# END type

class EndPathNode(DevicePathNodeData, partial=True):
	TYPE = DevicePathType.END
	@classmethod
	def decode(cls, f: BinaryIO): return cls()
	def encode(self, f: BinaryIO): pass

@dataclass
class EndPathInstance(EndPathNode):
	''' terminates one Device Path instance and denotes the start of another.
		This is only required when an environment variable represents multiple devices. An example of this would be the ConsoleOut environment variable that consists of both a VGA console and serial output console. This variable would describe a console output stream that is sent to both VGA and serial concurrently and thus has a Device Path that contains two complete Device Paths. '''
	SUB_TYPE = 0x01

@dataclass
class EndPath(EndPathNode):
	''' terminates an entire Device Path. Software searches for this sub-type to find the end of a Device Path. All Device Paths must end with this sub-type. '''
	SUB_TYPE = 0xFF


# HARDWARE type

class HardwarePathNode(DevicePathNodeData, partial=True):
	TYPE = DevicePathType.HARDWARE

@dataclass(frozen=True)
class PciHardware(HardwarePathNode):
	'''
	path to the PCI configuration space address for a PCI device. There is one PCI Device Path entry for each device and function number that defines the path from the root PCI bus to the device

	The PCI Device Path entry must be preceded by an ACPI Device Path entry that uniquely identifies the PCI root bus. The programming of root PCI bridges is not defined by any PCI specification and this is why an ACPI Device Path entry is required.
	'''
	SUB_TYPE = 1
	SHORT_NAME = 'PCI'

	device: int
	function: int
	@classmethod
	def decode(cls, f: BinaryIO):
		function, device = read_struct(f, 'BB')
		return cls(device, function)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('BB', self.function, self.device))

@dataclass(frozen=True)
class PccardHardware(HardwarePathNode):
	SUB_TYPE = 2
	SHORT_NAME = 'PCCARD'

	function: int
	''' Function Number (0 = First Function) '''

	@classmethod
	def decode(cls, f: BinaryIO):
		function, = read_struct(f, 'B')
		return cls(function)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('B', self.function))

@dataclass(frozen=True)
class MemoryMappedHardware(HardwarePathNode):
	SUB_TYPE = 3
	SHORT_NAME = 'MMIO'

	memory_type: int
	''' EFI_MEMORY_TYPE. Type EFI_MEMORY_TYPE is defined in the **EFI_BOOT_SERVICES.AllocatePages()** function description. '''

	start_addr: int
	end_addr: int

	@classmethod
	def decode(cls, f: BinaryIO):
		memory_type, start_addr, end_addr = read_struct(f, 'IQQ')
		return cls(memory_type, start_addr, end_addr)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('IQQ', self.memory_type, self.start_addr, self.end_addr))

@dataclass(frozen=True)
class VendorHardware(HardwarePathNode):
	SUB_TYPE = 4

	vendor_guid: UUID
	vendor_data: bytes

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(UUID(bytes_le=read(f, 16)), f.read())
	def encode(self, f: BinaryIO):
		f.write(self.vendor_guid.bytes_le)
		f.write(self.vendor_data)

@dataclass(frozen=True)
class ControllerHardware(HardwarePathNode):
	SUB_TYPE = 5

	controller_number: int

	@classmethod
	def decode(cls, f: BinaryIO):
		controller_number, = read_struct(f, 'I')
		return cls(controller_number)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('I', self.controller_number))

@dataclass(frozen=True)
class BmcHardware(HardwarePathNode):
	SUB_TYPE = 6
	SHORT_NAME = 'BCM'

	class InterfaceType(IntEnum):
		''' The Baseboard Management Controller (BMC) host interface type '''
		UNKNOWN = 0x00
		KCS = 0x01
		''' Keyboard Controller Style '''
		SMIC = 0x02
		''' Server Management Interface Chip '''
		BT = 0x03
		''' Block Transfer '''

		@classmethod
		def get(cls, x: int):
			try:
				return cls(x)
			except ValueError:
				return x

	interface: InterfaceType
	base_addr: int
	''' Base address (either memory-mapped or I/O) of the BMC.
		If the least-significant bit of the field is a 1, the address is in I/O space; otherwise, the address is memory-mapped.
		Refer to the IPMI Interface Specification for usage details. '''

	@classmethod
	def decode(cls, f: BinaryIO):
		interface, base_addr = read_struct(f, 'BQ')
		return cls(cls.InterfaceType(interface), base_addr)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('BQ', self.interface, self.base_addr))


# MESSAGING type

class MessagingPathNode(DevicePathNodeData, partial=True):
	TYPE = DevicePathType.MESSAGING

@dataclass(frozen=True)
class AtapiMessaging(MessagingPathNode):
	SUB_TYPE = 1
	SHORT_NAME = 'ATAPI'

	primary_secondary: int
	''' Set to zero for primary or one for secondary '''

	master_slave: int
	''' Set to zero for master or one for slave mode '''

	lun: int
	''' Logical Unit Number '''

	@classmethod
	def decode(cls, f: BinaryIO):
		primary_secondary, master_slave, lun = read_struct(f, 'BBH')
		return cls(primary_secondary, master_slave, lun)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('BBH', self.primary_secondary, self.master_slave, self.lun))

@dataclass(frozen=True)
class ScsiMessaging(MessagingPathNode):
	SUB_TYPE = 2
	SHORT_NAME = 'SCSI'

	pun: int
	''' Target ID on the SCSI bus (PUN) '''

	lun: int
	''' Logical Unit Number (LUN) '''

	@classmethod
	def decode(cls, f: BinaryIO):
		pun, lun = read_struct(f, 'HH')
		return cls(pun, lun)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('HH', self.pun, self.lun))

@dataclass(frozen=True)
class UsbMessaging(MessagingPathNode):
	SUB_TYPE = 5
	SHORT_NAME = 'USB'

	port: int
	''' USB parent port number '''

	interface: int
	''' USB interface number '''

	@classmethod
	def decode(cls, f: BinaryIO):
		port, interface = read_struct(f, 'BB')
		return cls(port, interface)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('BB', self.port, self.interface))

@dataclass(frozen=True)
class SataMessaging(MessagingPathNode):
	SUB_TYPE = 18
	SHORT_NAME = 'SATA'

	hba_port: int
	''' The HBA port number that facilitates the connection to the device or a port multiplier. The value 0xFFFF is reserved. '''

	port_mult_port: int
	''' The Port multiplier port number that facilitates the connection to the device. Must be set to 0xFFFF if the device is directly connected to the HBA. '''

	lun: int
	''' Logical Unit Number '''

	@classmethod
	def decode(cls, f: BinaryIO):
		hba_port, port_mult_port, lun = read_struct(f, 'HHH')
		return cls(hba_port, port_mult_port, lun)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('HHH', self.hba_port, self.port_mult_port, self.lun))

@dataclass(frozen=True)
class LunMessaging(MessagingPathNode):
	'''
	For some classes of devices, such as USB Mass Storage, it is necessary to specify the Logical Unit Number (LUN), since a single device may have multiple logical units.
	In order to boot from one of these logical units of the device, the Device Logical Unit device node is appended to the device path.
	'''
	SUB_TYPE = 17
	SHORT_NAME = 'LUN'

	lun: int
	''' Logical Unit Number '''

	@classmethod
	def decode(cls, f: BinaryIO):
		lun, = read_struct(f, 'B')
		return cls(lun)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('B', self.lun))

@dataclass(frozen=True)
class NvmeMessaging(MessagingPathNode):
	SUB_TYPE = 23
	SHORT_NAME = 'NVMe'

	nsid: int
	''' Namespace identifier (NSID). The values of 0 and 0xFFFFFFFF are invalid. '''

	eui64: int
	''' the IEEE Extended Unique Identifier (EUI-64). Devices without an EUI-64 value must initialize this field with a value of 0. '''

	@classmethod
	def decode(cls, f: BinaryIO):
		nsid, eui64 = read_struct(f, 'IQ')
		return cls(nsid, eui64)

	def encode(self, f: BinaryIO):
		f.write(encode_struct('IQ', self.nsid, self.eui64))

@dataclass(frozen=True)
class VendorMessaging(MessagingPathNode):
	SUB_TYPE = 10

	vendor_guid: UUID
	vendor_data: bytes

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(UUID(bytes_le=read(f, 16)), f.read())
	def encode(self, f: BinaryIO):
		f.write(self.vendor_guid.bytes_le)
		f.write(self.vendor_data)

@dataclass(frozen=True)
class UriMessaging(MessagingPathNode):
	SUB_TYPE = 24
	SHORT_NAME = 'URI'

	uri: str

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(f.read().decode('utf-8'))
	def encode(self, f: BinaryIO):
		f.write(self.uri.encode('utf-8'))


# MEDIA type

class MediaPathNode(DevicePathNodeData, partial=True):
	TYPE = DevicePathType.MEDIA

class PartitionFormat(IntEnum):
	MBR = 0x01
	''' PC-AT compatible legacy MBR (Legacy MBR). Partition Start and Partition Size come from PartitionStartingLBA and PartitionSizeInLBA for the partition. '''
	GPT = 0x02
	''' GUID Partition Table '''

	@classmethod
	def get(cls, x: int):
		try:
			return cls(x)
		except ValueError:
			return x

class PartitionSignatureType(IntEnum):
	''' Type of Disk Signature: (Unused values reserved) '''
	NONE = 0x00
	''' No Disk Signature. '''
	MBR = 0x01
	''' 32-bit signature from address 0x1b8 of the type 0x01 MBR. '''
	GUID = 0x02

	@classmethod
	def get(cls, x: int):
		try:
			return cls(x)
		except ValueError:
			return x

@dataclass(frozen=True)
class MbrSignature:
	''' 32-bit signature from address 0x1b8 of the type 0x01 MBR. '''
	sig: int

PartitionSignature: TypeAlias = Union[None, MbrSignature, UUID, tuple[int, bytes]]
''' Signature unique to this partition:
	- `None` -> signature_type NONE
	- `MbrSignature` -> signature_type MBR
	- `UUID` -> signature_type GUID
	- `(signature_type, 16 bytes of signature)` -> other signature_types '''

@dataclass(frozen=True)
class HardDriveMedia(MediaPathNode):
	'''
	The Hard Drive Media Device Path is used to represent a partition on a hard drive.
	Each partition has at least Hard Drive Device Path node, each describing an entry in a partition table.
	EFI supports MBR and GPT partitioning formats.
	Partitions are numbered according to their entry in their respective partition table, starting with 1.
	Partitions are addressed in EFI starting at LBA zero.
	A partition number of zero can be used to represent the raw hard drive or a raw extended partition.

	The partition format is stored in the Device Path to allow new partition formats to be supported in the future.
	The Hard Drive Device Path also contains a Disk Signature and a Disk Signature Type.
	The disk signature is maintained by the OS and only used by EFI to partition Device Path nodes.
	The disk signature enables the OS to find disks even after they have been physically moved in a system.

	**Load Option Processing** defines special rules for processing the Hard Drive Media Device Path.
	These special rules enable a disk’s location to change and still have the system boot from the disk.
	'''
	SUB_TYPE = 1
	SHORT_NAME = 'HD'

	partition_number: int
	''' Describes the entry in a partition table, starting with entry 1.
		Partition number zero represents the entire device.
		Valid partition numbers for a MBR partition are [1, 4].
		Valid partition numbers for a GPT partition are [1, NumberOfPar titionEntries]. '''

	partition_start: int
	''' Starting LBA of the partition on the hard drive '''

	partition_size: int
	''' Size of the partition in units of Logical Blocks '''

	partition_signature: PartitionSignature

	partition_format: Union[PartitionFormat, int]

	@classmethod
	def decode(cls, f: BinaryIO):
		partition_number, partition_start, partition_size, partition_signature, partition_format, signature_type = read_struct(f, 'IQQ16sBB')
		return cls(partition_number, partition_start, partition_size, cls.parse_signature(signature_type, partition_signature), PartitionFormat.get(partition_format))

	def encode(self, f: BinaryIO):
		partition_signature, signature_type = self.format_signature(self.partition_signature)
		f.write(encode_struct('IQQ16sBB', self.partition_number, self.partition_start, self.partition_size, partition_signature, self.partition_format, signature_type))

	@staticmethod
	def parse_signature(type: Union[PartitionSignatureType, int], signature: bytes) -> PartitionSignature:
		if type == PartitionSignatureType.NONE:
			assert signature == b'\0' * 16, f'signature must be zeros: {signature!r}'
			return None
		if type == PartitionSignatureType.MBR:
			assert signature[4:] == b'\0' * 12, f'signature must be 4 bytes and then zeros: {signature!r}'
			return MbrSignature(struct.unpack('=I', signature[:4])[0])
		if type == PartitionSignatureType.GUID:
			return UUID(bytes_le=signature)
		return PartitionSignatureType.get(type), signature

	@staticmethod
	def format_signature(signature: PartitionSignature) -> tuple[int, bytes]:
		if signature == None:
			return PartitionSignatureType.NONE, b'\0' * 16
		if isinstance(signature, MbrSignature):
			return PartitionSignatureType.MBR, struct.pack('=I', signature.sig) + b'\0' * 12
		if isinstance(signature, UUID):
			return PartitionSignatureType.GUID, signature.bytes_le
		return signature

@dataclass(frozen=True)
class CdRomMedia(MediaPathNode):
	'''
	The CD-ROM Media Device Path is used to define a system partition that exists on a CD-ROM.
	The CD-ROM is assumed to contain an ISO-9660 file system and follow the CD-ROM “El Torito” format.
	The Boot Entry number from the Boot Catalog is how the “El Torito” specification defines the existence of bootable entities on a CD-ROM.
	In EFI the bootable entity is an EFI System Partition that is pointed to by the Boot Entry.
	'''
	SUB_TYPE = 2
	SHORT_NAME = 'CDROM'

	boot_entry: int
	''' Boot Entry number from the Boot Catalog. The Initial/Default entry is defined as zero. '''

	partition_start: int
	''' Starting RBA of the partition on the medium. CD-ROMs use Relative logical Block Addressing. '''

	partition_size: int
	''' Size of the partition in units of Blocks, also called Sectors. '''

@dataclass(frozen=True)
class VendorMedia(MediaPathNode):
	SUB_TYPE = 3

	vendor_guid: UUID
	vendor_data: bytes

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(UUID(bytes_le=read(f, 16)), f.read())
	def encode(self, f: BinaryIO):
		f.write(self.vendor_guid.bytes_le)
		f.write(self.vendor_data)

@dataclass(frozen=True)
class FilePathMedia(MediaPathNode):
	'''
	A NULL-terminated Path string including directory and file names.
	The length of this string n can be determined by subtracting 4 from the Length entry.
	A device path may contain one or more of these nodes.
	Each node can optionally add a “" separator to the beginning and/or the end of the Path Name string.
	The complete path to a file can be found by logically concatenating all the Path Name strings in the File Path Media Device Path nodes.
	This is typically used to describe the directory path in one node, and the filename in another node.
	'''
	SUB_TYPE = 4
	SHORT_NAME = 'File'

	path: str

	@classmethod
	def decode(cls, f: BinaryIO):
		return cls(read_char16(f))
	def encode(self, f: BinaryIO):
		f.write(encode_char16(self.path))
