from typing import Any, Callable, Iterable, Optional
import itertools
import sys
from enum import Enum, IntFlag
from uefi_structs.stores.efivarfs import Efivarfs
import uefi_structs.boot_manager as bm
import uefi_structs.device_path as dp
from uefi_structs.utils import extract_mask

colorize = sys.stdout.buffer.isatty()
bytes_per_line = 24

def pad_iter[T](iterable: Iterable[T], size: int, default: T=None) -> Iterable[T]:
	iterator = iter(iterable)
	for _ in range(size):
		yield next(iterator, default)

def split_in_groups[T](iterable: Iterable[T], size: int) -> Iterable[list[T]]:
	iterator = iter(iterable)
	while (group := list(itertools.islice(iterator, size))):
		yield group

def ansi_sgr(*args: Any):
	seq = '\x1b[' + ';'.join(map(str, args)) + 'm'
	def fn(_content: Any):
		content = str(_content)
		if not colorize: return content
		if not content.endswith('\x1b[m'):
			content += '\x1b[m'
		return seq + content
	return fn
ansi_bold = ansi_sgr(1)
ansi_dim = ansi_sgr(2)
ansi_fg0 = ansi_sgr(30)
ansi_fg1 = ansi_sgr(31)
ansi_fg2 = ansi_sgr(32)
ansi_fg3 = ansi_sgr(33)
ansi_fg4 = ansi_sgr(34)
ansi_fg5 = ansi_sgr(35)
ansi_fg6 = ansi_sgr(36)
ansi_fg7 = ansi_sgr(37)

def print_hex_dump(data: bytes, prefix: str):
	colorize_byte: Callable[[str, int], str] = lambda x, r: \
		ansi_dim(ansi_fg2(x)) if r == 0 else \
		ansi_fg3(x) if chr(r).isascii() and chr(r).isprintable() else \
		ansi_fg2(x)
	format_hex: Callable[[Optional[int]], str] = lambda x: colorize_byte(f'{x:02x}', x) if x != None else '  '
	format_char: Callable[[str], str] = lambda x: colorize_byte(x if x.isascii() and (x.isprintable() or x == ' ') else '.', ord(x))

	def format_line(line: Iterable[int]):
		groups = split_in_groups(pad_iter(line, bytes_per_line), 4)
		hex_part = '  '.join(' '.join(map(format_hex, group)) for group in groups)
		char_part = ''.join(format_char(x) for x in map(chr, line))
		return hex_part + '   ' + char_part

	for line in split_in_groups(data, bytes_per_line):
		print(prefix + format_line(line))

def fmt_enum(x: int):
	return x.name if isinstance(x, Enum) else f'<{x}>'
def fmt_flags(x: IntFlag):
	for v in type(x):
		if x & v == v:
			yield v.name if v.name else f'<{x:#x}>'
		x &= ~v
	if x:
		yield f'<{x:#x}>'

def fmt_boot_opt(key: bm.OptKey):
	opt = store.Boot.get(key)
	return f'{ansi_fg5(key)} {ansi_bold(repr(opt.data.description)) if opt else '<not found>'}'

def print_dev_path(path: dp.DevicePath, prefix: str = ''):
	for node in path:
		if m := node.parse(dp.DevicePathNodeData):
			text = str(m)
		else:
			text = f'{fmt_enum(node.type)}, {node.sub_type!r}, {node.data!r}'
		print(prefix + ansi_fg3('⤷ ') + (text))

def print_load_option(key: bm.OptKey, var: bm.ParsedVariable[bm.LoadOption]):
	_efi_attrs, data = var # FIXME: print EFI attributes
	attrs, active = extract_mask(data.attributes, bm.LoadOption.FlagAttributes.ACTIVE)

	items: list[str] = []
	if data.category != bm.LoadOption.Category.BOOT:
		items.append(f'category={fmt_enum(data.category)}')
	items.extend(fmt_flags(attrs)) # pyright: ignore

	bullet = f'[{'*' if active else ' '}]'
	bullet = (ansi_fg2 if active else ansi_fg1)(bullet)
	print(bullet + f' {ansi_fg5(key)} {ansi_bold(repr(data.description))}'
		+ ansi_fg4(f' ({", ".join(items)})' if attrs else ''))

	image, *extra_paths = data.file_paths
	print_dev_path(image, '  ')
	if extra_paths:
		for i, path in enumerate(extra_paths):
			print(f'  Additional path {i+1}:')
			print_dev_path(path, '    ')
	if data.optional_data:
		print(f'  Optional data:')
		print_hex_dump(data.optional_data, '    ')


store = bm.StoreView(Efivarfs())

print(f'BootCurrent: {fmt_boot_opt(store.BootCurrent.data)}')
try:
	boot_next = store.BootNext
except KeyError:
	boot_next = None
print(f'BootNext: {fmt_boot_opt(boot_next.data) if boot_next else ansi_dim('<not set>')}')
print('\nBootOrder:')
for opt in store.BootOrder.data:
	print(f'  - {fmt_boot_opt(opt)}')

print('\nBOOT OPTIONS:\n')
for key, var in sorted(store.Boot.items()):
	print_load_option(key, var)
	print()

# for name in 'ConIn', 'ConInDev', 'ConOut', 'ConOutDev', 'ErrOut', 'ErrOutDev':
# 	try:
# 		value = getattr(store, name)
# 	except KeyError:
# 		continue
# 	print(f'{name}:')
# 	print_dev_path(value.data, '  ')
