"""Locate compatible x64 capability matchers by structure and call relationships."""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, asdict
import hashlib
from pathlib import Path
import re
import struct

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


class UnsupportedImplementation(ValueError):
    """The image did not satisfy the supported implementation contract."""


@dataclass(frozen=True)
class Target:
    rva: int
    signature: str


@dataclass(frozen=True)
class Profile:
    sha256: str
    version: str
    matcher: Target
    presenter: Target | None
    max_quality: int = 4
    quality_offset: int = 4
    codec_offset: int = 12
    result_offset: int = 24

    def to_dict(self):
        return asdict(self)


class Image:
    def __init__(self, data: bytes):
        self.data = data
        try:
            self.pe = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError as error:
            raise UnsupportedImplementation('Not a valid PE executable.') from error
        if self.pe.FILE_HEADER.Machine != 0x8664 or self.pe.OPTIONAL_HEADER.Magic != 0x20b:
            raise UnsupportedImplementation('Only Windows x64 PE images are supported.')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.executable = [s for s in self.pe.sections if s.Characteristics & 0x20000000]
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if not directory.Size or directory.Size % 12:
            raise UnsupportedImplementation('Missing or malformed x64 unwind directory.')
        raw = self.pe.get_data(directory.VirtualAddress, directory.Size)
        if len(raw) != directory.Size:
            raise UnsupportedImplementation('Truncated unwind directory.')
        self.functions = sorted((a, b) for a, b, _ in struct.iter_unpack('<III', raw) if a < b)
        self.begins = [a for a, _ in self.functions]
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True

    def read(self, rva, size):
        return self.pe.get_data(rva, size)

    def containing(self, rva):
        i = bisect_right(self.begins, rva) - 1
        if i >= 0 and self.functions[i][0] <= rva < self.functions[i][1]:
            return self.functions[i]
        return None

    def code(self, begin, end):
        return list(self.decoder.disasm(self.read(begin, end-begin), self.base+begin))

    def resolve_jump(self, rva):
        seen = set()
        for _ in range(8):
            if rva in seen:
                return None
            seen.add(rva)
            code = self.code(rva, rva+16)
            if not code:
                return None
            ins = code[0]
            if ins.mnemonic == 'jmp' and ins.operands[0].type == X86_OP_IMM:
                rva = ins.operands[0].imm - self.base
            else:
                return rva
        return None

    def target(self, rva):
        return Target(rva, self.read(rva, 32).hex())

    def leaf_code(self, rva):
        if not any(s.VirtualAddress <= rva < s.VirtualAddress+s.SizeOfRawData for s in self.executable):
            return []
        # Volatile-register leaf functions need no x64 unwind entry.
        code = self.code(rva, rva+1024)
        for i, ins in enumerate(code):
            if ins.mnemonic == 'ret':
                return code[:i+1]
            if ins.mnemonic == 'int3':
                return []
        return []

    def string_references(self, value):
        offsets = []
        start = 0
        while (pos := self.data.find(value, start)) >= 0:
            offsets.append(self.pe.get_rva_from_offset(pos))
            start = pos+len(value)
        targets = set(offsets)
        for section in self.executable:
            code = section.get_data()
            for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
                i = match.start()
                if i+7 > len(code):
                    continue
                target = section.VirtualAddress+i+7+struct.unpack_from('<i', code, i+3)[0]
                if target in targets:
                    yield section.VirtualAddress+i


def register(ins, operand):
    return ins.reg_name(operand.reg) if operand.type == X86_OP_REG else None


def register_family(name):
    for full, aliases in {'rax': ('rax', 'eax', 'ax', 'al', 'ah'), 'rbx': ('rbx', 'ebx', 'bx', 'bl', 'bh'),
                          'rcx': ('rcx', 'ecx', 'cx', 'cl', 'ch'), 'rdx': ('rdx', 'edx', 'dx', 'dl', 'dh')}.items():
        if name in aliases:
            return full
    return re.sub(r'^(r\d+)[dwb]$', r'\1', name or '')


def memory(ins, operand, base=None, offset=None):
    return (operand.type == X86_OP_MEM and not operand.mem.index
            and (base is None or ins.reg_name(operand.mem.base) == base)
            and (offset is None or operand.mem.disp == offset))


def has_immediate(code, mnemonic, value):
    return any(ins.mnemonic == mnemonic and any(op.type == X86_OP_IMM and (op.imm & 0xffffffff) == value for op in ins.operands) for ins in code)


def compatible_leaf(code):
    """Verify the 28-byte vector entry and both codec output records."""
    strides = [ins for ins in code if ins.mnemonic == 'add' and len(ins.operands) == 2
               and ins.operands[0].type == X86_OP_REG and ins.operands[1].type == X86_OP_IMM
               and ins.operands[1].imm == 28]
    for stride in strides:
        source = register(stride, stride.operands[0])
        copied = {}
        for i, ins in enumerate(code[:-1]):
            if ins.mnemonic not in ('mov', 'movzx') or len(ins.operands) != 2:
                continue
            dest, origin = ins.operands
            if not memory(ins, origin, source) or dest.type != X86_OP_REG:
                continue
            offset = origin.mem.disp
            for store in code[i+1:i+3]:
                if store.mnemonic != 'mov' or len(store.operands) != 2:
                    continue
                left, right = store.operands
                expected_size = 1 if offset == 8 else 4
                if (memory(store, left, offset=offset) and left.size == origin.size == expected_size
                        and register_family(register(store, right)) == register_family(register(ins, dest))):
                    target = store.reg_name(left.mem.base)
                    copied.setdefault(target, set()).add(offset)
        fields = {0, 4, 8, 12, 16, 20, 24}
        # Codec may be loaded once and stored in either branch after comparisons.
        codec_registers = {register_family(register(ins, ins.operands[0])) for ins in code
                           if ins.mnemonic == 'mov' and len(ins.operands) == 2
                           and memory(ins, ins.operands[1], source, 12) and ins.operands[1].size == 4}
        for ins in code:
            if (ins.mnemonic == 'mov' and len(ins.operands) == 2
                    and memory(ins, ins.operands[0], offset=12) and ins.operands[0].size == 4
                    and register_family(register(ins, ins.operands[1])) in codec_registers):
                copied.setdefault(ins.reg_name(ins.operands[0].mem.base), set()).add(12)
        if sum(fields <= offsets for offsets in copied.values()) >= 2 and has_immediate(code, 'cmp', 1) and has_immediate(code, 'cmp', 2):
            return True
    return False


def compatible_matcher(image, begin, end):
    if not 128 <= end-begin <= 4096:
        return False
    code = image.code(begin, end)
    # Identify the hidden structure-return argument without fixing a register.
    outputs = [register(ins, ins.operands[0]) for ins in code[:64]
               if ins.mnemonic == 'mov' and len(ins.operands) == 2
               and register(ins, ins.operands[1]) == 'rdx'
               and ins.operands[0].type == X86_OP_REG]
    for output in outputs:
        stores = {}
        returns_output = False
        for ins in code:
            if ins.mnemonic != 'mov' or len(ins.operands) != 2:
                continue
            dest, source = ins.operands
            if memory(ins, dest, output):
                stores.setdefault(dest.mem.disp, []).append((dest.size, source))
            if register(ins, dest) == 'rax' and register(ins, source) == output:
                returns_output = True
        default_error = any(size == 4 and op.type == X86_OP_IMM and (op.imm & 0xffffffff) == 0xfffffffd for size, op in stores.get(24, []))
        default_record = any(size == 8 and op.type == X86_OP_IMM and op.imm == 1 for size, op in stores.get(0, []))
        default_codec = any(size == 8 and op.type == X86_OP_IMM and op.imm == 2 for size, op in stores.get(12, []))
        result_stores = sum(size == 4 and op.type == X86_OP_REG for size, op in stores.get(24, []))
        if not (returns_output and default_error and default_record and default_codec and result_stores >= 2 and has_immediate(code, 'cmp', 5)):
            continue
        if sum(ins.mnemonic == 'jge' for ins in code) < 2:
            continue
        if not any(ins.mnemonic in ('mov', 'movzx') and len(ins.operands) == 2 and register(ins, ins.operands[1]) == 'r8d' for ins in code[:64]):
            continue
        if not any(ins.mnemonic == 'movzx' and len(ins.operands) == 2 and register(ins, ins.operands[1]) == 'r9b' for ins in code[:64]):
            continue
        for ins in code:
            if ins.mnemonic == 'call' and ins.operands[0].type == X86_OP_IMM:
                leaf = image.resolve_jump(ins.operands[0].imm-image.base)
                if leaf is None:
                    continue
                if compatible_leaf(image.leaf_code(leaf)):
                    return True
    return False


def discover_bytes(data: bytes) -> Profile:
    image = Image(data)
    if not all(value in data for value in [b'VideoQuality_Bluray\x10\x04', b'CodecType_H264\x10\x01', b'CodecType_H265\x10\x02']):
        raise UnsupportedImplementation('The expected quality and codec enum definitions were not found.')
    candidates = set()
    # The anchor only narrows candidates. Instruction and callee validation decide compatibility.
    for section in image.executable:
        for match in re.finditer(rb'\xc7[\x40-\x47]\x18\xfd\xff\xff\xff', section.get_data()):
            bounds = image.containing(section.VirtualAddress+match.start())
            if bounds and compatible_matcher(image, *bounds):
                candidates.add(bounds[0])
    if len(candidates) != 1:
        raise UnsupportedImplementation(f'Expected one validated capability matcher; found {len(candidates)}.')
    presenter_candidates = set()
    for rva in image.string_references(b'change quality failed\0'):
        bounds = image.containing(rva)
        if not bounds or bounds[1]-bounds[0] > 8192:
            continue
        code = image.code(*bounds)
        if has_immediate(code, 'mov', 21) and any(ins.mnemonic == 'mov' and ins.op_str == 'edi, r8d' for ins in code[:64]):
            presenter_candidates.add(bounds[0])
    presenter = image.target(next(iter(presenter_candidates))) if len(presenter_candidates) == 1 else None
    version = 'unknown'
    image.pe.parse_data_directories(directories=[2])
    for group in getattr(image.pe, 'FileInfo', []):
        for info in group:
            for table in getattr(info, 'StringTable', []):
                value = table.entries.get(b'FileVersion')
                if value:
                    version = value.decode(errors='replace')
    return Profile(hashlib.sha256(data).hexdigest(), version, image.target(next(iter(candidates))), presenter)


def discover(path: Path) -> Profile:
    return discover_bytes(Path(path).read_bytes())
