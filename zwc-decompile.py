#!/usr/bin/env python3
"""
zwc-decompile.py - static zsh .zwc parser and source reconstructor.

Target: zsh 5.9 wordcode/dump format. The decoder will also attempt
compatible files sharing the same FD_MAGIC, but emits a version warning.

This tool DOES NOT invoke zsh, source the input, or execute recovered code.

The textual reconstruction engine is a clean-room Python port of the layout
and traversal described by zsh 5.9's Src/parse.c, Src/zsh.h and Src/text.c
(getpermtext()/gettext2()).  zsh is distributed under a permissive license;
see the upstream source for copyright and license terms.

The output is a semantic reconstruction, not the original source:
comments and original whitespace are not stored in wordcode and cannot be
recovered exactly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Set, Union

# ---- ZWC container ---------------------------------------------------------

FD_PRELEN = 12
FD_MAGIC = 0x04050607
FDF_MAP = 1
FDF_OTHER = 2

# ---- Wordcode -------------------------------------------------------------

WC_CODEBITS = 5
WC_END = 0
WC_LIST = 1
WC_SUBLIST = 2
WC_PIPE = 3
WC_REDIR = 4
WC_ASSIGN = 5
WC_SIMPLE = 6
WC_TYPESET = 7
WC_SUBSH = 8
WC_CURSH = 9
WC_TIMED = 10
WC_FUNCDEF = 11
WC_FOR = 12
WC_SELECT = 13
WC_WHILE = 14
WC_REPEAT = 15
WC_CASE = 16
WC_IF = 17
WC_COND = 18
WC_ARITH = 19
WC_AUTOFN = 20
WC_TRY = 21
WC_COUNT = 22

WC_NAMES = {
    WC_END: "WC_END", WC_LIST: "WC_LIST", WC_SUBLIST: "WC_SUBLIST",
    WC_PIPE: "WC_PIPE", WC_REDIR: "WC_REDIR", WC_ASSIGN: "WC_ASSIGN",
    WC_SIMPLE: "WC_SIMPLE", WC_TYPESET: "WC_TYPESET", WC_SUBSH: "WC_SUBSH",
    WC_CURSH: "WC_CURSH", WC_TIMED: "WC_TIMED", WC_FUNCDEF: "WC_FUNCDEF",
    WC_FOR: "WC_FOR", WC_SELECT: "WC_SELECT", WC_WHILE: "WC_WHILE",
    WC_REPEAT: "WC_REPEAT", WC_CASE: "WC_CASE", WC_IF: "WC_IF",
    WC_COND: "WC_COND", WC_ARITH: "WC_ARITH", WC_AUTOFN: "WC_AUTOFN",
    WC_TRY: "WC_TRY",
}

# List flags
Z_SYNC = 1 << 1
Z_ASYNC = 1 << 2
Z_DISOWN = 1 << 3
Z_END = 1 << 4
Z_SIMPLE = 1 << 5

# Sublist
WC_SUBLIST_END = 0
WC_SUBLIST_AND = 1
WC_SUBLIST_OR = 2
WC_SUBLIST_COPROC = 4
WC_SUBLIST_NOT = 8
WC_SUBLIST_SIMPLE = 16

# Pipe
WC_PIPE_END = 0
WC_PIPE_MID = 1

# Assignment
WC_ASSIGN_SCALAR = 0
WC_ASSIGN_ARRAY = 1
WC_ASSIGN_NEW = 0
WC_ASSIGN_INC = 1

# Time
WC_TIMED_EMPTY = 0
WC_TIMED_PIPE = 1

# for/select/while
WC_FOR_PPARAM = 0
WC_FOR_LIST = 1
WC_FOR_COND = 2
WC_SELECT_PPARAM = 0
WC_SELECT_LIST = 1
WC_WHILE_WHILE = 0
WC_WHILE_UNTIL = 1

# case
WC_CASE_HEAD = 0
WC_CASE_OR = 1
WC_CASE_AND = 2
WC_CASE_TESTAND = 3

# if
WC_IF_HEAD = 0
WC_IF_IF = 1
WC_IF_ELIF = 2
WC_IF_ELSE = 3

# conditions
COND_NOT = 0
COND_AND = 1
COND_OR = 2
COND_STREQ = 3
COND_STRDEQ = 4
COND_STRNEQ = 5
COND_STRLT = 6
COND_STRGTR = 7
COND_NT = 8
COND_OT = 9
COND_EF = 10
COND_EQ = 11
COND_NE = 12
COND_LT = 13
COND_GT = 14
COND_LE = 15
COND_GE = 16
COND_REGEX = 17
COND_MOD = 18
COND_MODI = 19

COND_BINARY_OPS = [
    "=", "==", "!=", "<", ">", "-nt", "-ot", "-ef", "-eq",
    "-ne", "-lt", "-gt", "-le", "-ge", "=~",
]

# Redirection types/masks from zsh.h
REDIR_WRITE = 0
REDIR_WRITENOW = 1
REDIR_APP = 2
REDIR_APPNOW = 3
REDIR_ERRWRITE = 4
REDIR_ERRWRITENOW = 5
REDIR_ERRAPP = 6
REDIR_ERRAPPNOW = 7
REDIR_READWRITE = 8
REDIR_READ = 9
REDIR_HEREDOC = 10
REDIR_HEREDOCDASH = 11
REDIR_HERESTR = 12
REDIR_MERGEIN = 13
REDIR_MERGEOUT = 14
REDIR_CLOSE = 15
REDIR_INPIPE = 16
REDIR_OUTPIPE = 17
REDIR_TYPE_MASK = 0x1F
REDIR_VARID_MASK = 0x20
REDIR_FROM_HEREDOC_MASK = 0x40

REDIR_TEXT = {
    REDIR_WRITE: ">",
    REDIR_WRITENOW: ">|",
    REDIR_APP: ">>",
    REDIR_APPNOW: ">>|",
    REDIR_ERRWRITE: "&>",
    REDIR_ERRWRITENOW: "&>|",
    REDIR_ERRAPP: "&>>",
    REDIR_ERRAPPNOW: "&>>|",
    REDIR_READWRITE: "<>",
    REDIR_READ: "<",
    REDIR_HEREDOC: "<<",
    REDIR_HEREDOCDASH: "<<-",
    REDIR_HERESTR: "<<<",
    REDIR_MERGEIN: "<&",
    REDIR_MERGEOUT: ">&",
    REDIR_CLOSE: ">&-",
    REDIR_INPIPE: "<",
    REDIR_OUTPIPE: ">",
}

# Character tokens: must match ztokens in zsh 5.9 Src/lex.c.
META = 0x83
POUND = 0x84
NULARG = 0xA1
ZTOKENS = b"#$^*(())$=|{}[]`<>>?~`,-!'\"\\\\"
TOKEN_MAP = {POUND + i: bytes([b]) for i, b in enumerate(ZTOKENS)}

# ---- Errors / records ------------------------------------------------------

class ZWCError(Exception):
    pass

class DecompileError(ZWCError):
    pass

@dataclass
class Entry:
    name: str
    start_word: int
    length_bytes: int
    npats: int
    strings_offset: int
    header_words: int
    flags: int
    tail_offset: int

@dataclass
class Redir:
    type: int
    fd1: int
    name: bytes
    varid: Optional[bytes] = None
    from_heredoc: bool = False
    here_terminator: Optional[bytes] = None
    munged_here_terminator: Optional[bytes] = None

@dataclass
class Frame:
    code: int
    pop: bool
    redirs: Optional[List[Redir]] = None
    func_old_strs: Optional[int] = None
    func_end: Optional[int] = None
    func_nargs: int = 0
    case_end: Optional[int] = None
    if_end: Optional[int] = None
    if_cond: int = 0
    cond_par: int = 0
    subsh_end: Optional[int] = None

# ---- Small helpers ---------------------------------------------------------

def wc_code(c: int) -> int:
    return c & ((1 << WC_CODEBITS) - 1)

def wc_data(c: int) -> int:
    return c >> WC_CODEBITS

def wc_list_type(c: int) -> int:
    return wc_data(c)

def wc_sublist_type(c: int) -> int:
    return wc_data(c) & 3

def wc_sublist_flags(c: int) -> int:
    return wc_data(c) & 0x1C

def wc_sublist_skip(c: int) -> int:
    return wc_data(c) >> 5

def wc_pipe_type(c: int) -> int:
    return wc_data(c) & 1

def wc_redir_type(c: int) -> int:
    return wc_data(c) & REDIR_TYPE_MASK

def wc_redir_varid(c: int) -> bool:
    return bool(wc_data(c) & REDIR_VARID_MASK)

def wc_redir_from_heredoc(c: int) -> bool:
    return bool(wc_data(c) & REDIR_FROM_HEREDOC_MASK)

def wc_assign_type(c: int) -> int:
    return wc_data(c) & 1

def wc_assign_type2(c: int) -> int:
    return (wc_data(c) & 2) >> 1

def wc_assign_num(c: int) -> int:
    return wc_data(c) >> 2

def wc_funcdef_skip(c: int) -> int:
    return wc_data(c)

def wc_for_type(c: int) -> int:
    return wc_data(c) & 3

def wc_select_type(c: int) -> int:
    return wc_data(c) & 1

def wc_while_type(c: int) -> int:
    return wc_data(c) & 1

def wc_case_type(c: int) -> int:
    return wc_data(c) & 7

def wc_case_skip(c: int) -> int:
    return wc_data(c) >> 3

def wc_if_type(c: int) -> int:
    return wc_data(c) & 3

def wc_if_skip(c: int) -> int:
    return wc_data(c) >> 2

def wc_cond_type(c: int) -> int:
    return wc_data(c) & 127

def wc_cond_skip(c: int) -> int:
    return wc_data(c) >> 7

def is_read_fd(redir_type: int) -> bool:
    return (REDIR_READWRITE <= redir_type <= REDIR_MERGEIN) or redir_type == REDIR_INPIPE

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def cstring(data: bytes, off: int, limit: Optional[int] = None) -> bytes:
    if off < 0 or off > len(data):
        raise ZWCError(f"string offset outside file: 0x{off:x}")
    endlim = len(data) if limit is None else min(limit, len(data))
    end = data.find(b"\x00", off, endlim)
    if end < 0:
        raise ZWCError(f"unterminated string at 0x{off:x}")
    return data[off:end]

def untokenize_unmeta(raw: bytes) -> bytes:
    """
    Turn zsh character tokens back into printable shell characters and undo
    Meta encoding. Nularg has no printable character and is discarded.
    """
    tmp = bytearray()
    for b in raw:
        if b in TOKEN_MAP:
            tmp.extend(TOKEN_MAP[b])
        elif b == NULARG:
            continue
        else:
            tmp.append(b)

    out = bytearray()
    i = 0
    while i < len(tmp):
        if tmp[i] == META and i + 1 < len(tmp):
            out.append(tmp[i + 1] ^ 32)
            i += 2
        else:
            out.append(tmp[i])
            i += 1
    return bytes(out)

def display(raw: bytes) -> str:
    return untokenize_unmeta(raw).decode("utf-8", "backslashreplace")

# ---- ZWC container parser --------------------------------------------------

class ZWCFile:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.endian, self.endian_name = self._detect_endian()
        self.base = 0
        self.flags = self.data[4]
        self.other_offset = self.data[5] | (self.data[6] << 8) | (self.data[7] << 16)
        self.version = cstring(self.data, 8, 48).decode("ascii", "replace")
        self.entries = self._parse_entries()
        self._validate_other_image()

    def _detect_endian(self) -> Tuple[str, str]:
        if len(self.data) < (FD_PRELEN + 1) * 4:
            raise ZWCError("file is too small to be a ZWC dump")
        le = struct.unpack_from("<I", self.data, 0)[0]
        be = struct.unpack_from(">I", self.data, 0)[0]
        if le == FD_MAGIC:
            return "<", "little"
        if be == FD_MAGIC:
            return ">", "big"
        raise ZWCError(
            f"bad ZWC magic: first word is 0x{le:08x} little / 0x{be:08x} big"
        )

    def u32(self, off: int) -> int:
        if off < 0 or off + 4 > len(self.data):
            raise ZWCError(f"u32 read outside file at 0x{off:x}")
        return struct.unpack_from(self.endian + "I", self.data, off)[0]

    def _parse_entries(self) -> List[Entry]:
        # fdheaderlen(file) is first fdhead.start, at word FD_PRELEN.
        header_words = self.u32(FD_PRELEN * 4)
        header_end = header_words * 4
        if header_words < FD_PRELEN + 6 or header_end > len(self.data):
            raise ZWCError(f"invalid ZWC header length: {header_words} words")

        entries: List[Entry] = []
        p = FD_PRELEN * 4
        while p < header_end:
            if p + 24 > header_end:
                raise ZWCError(f"truncated fdhead at file offset 0x{p:x}")
            start, length, npats, strs, hlen, flags = struct.unpack_from(
                self.endian + "6I", self.data, p
            )
            if hlen < 7:  # six fdhead words plus at least one word for NUL name
                raise ZWCError(f"invalid fdhead.hlen={hlen} at 0x{p:x}")
            next_p = p + hlen * 4
            if next_p > header_end:
                raise ZWCError(f"fdhead at 0x{p:x} extends beyond header")
            name_b = cstring(self.data, p + 24, next_p)
            name = name_b.decode("utf-8", "backslashreplace")
            e = Entry(
                name=name,
                start_word=start,
                length_bytes=length,
                npats=npats,
                strings_offset=strs,
                header_words=hlen,
                flags=flags & 3,
                tail_offset=flags >> 2,
            )
            self._validate_entry(e)
            entries.append(e)
            p = next_p

        if p != header_end:
            raise ZWCError("header descriptors do not end on declared boundary")
        return entries

    def _validate_entry(self, e: Entry) -> None:
        start = e.start_word * 4
        end = start + ((e.length_bytes + 3) // 4) * 4
        if start < 0 or start > len(self.data):
            raise ZWCError(f"{e.name}: program start is outside file")
        if end > len(self.data):
            raise ZWCError(f"{e.name}: program body extends beyond file")
        if e.strings_offset < 0 or e.strings_offset > e.length_bytes:
            raise ZWCError(f"{e.name}: invalid string-table offset")
        if e.strings_offset % 4:
            raise ZWCError(f"{e.name}: string table is not word aligned")

    def _validate_other_image(self) -> None:
        if not self.other_offset:
            return
        if self.other_offset + 4 > len(self.data):
            raise ZWCError("opposite-byte-order image points outside file")
        # The other image should begin with FD_OMAGIC when read in creator order.
        other_word = struct.unpack_from(self.endian + "I", self.data, self.other_offset)[0]
        if other_word != 0x07060504:
            # Do not reject old/odd dumps; retain forensic usefulness.
            self.other_image_warning = (
                f"second image at 0x{self.other_offset:x} has unexpected "
                f"magic 0x{other_word:08x}"
            )
        else:
            self.other_image_warning = None

    def entry_program(self, e: Entry) -> "Program":
        start = e.start_word * 4
        code_end = start + e.strings_offset
        logical_end = start + e.length_bytes
        code_b = self.data[start:code_end]
        if len(code_b) % 4:
            raise ZWCError(f"{e.name}: wordcode length is not divisible by 4")
        nwords = len(code_b) // 4
        words = list(struct.unpack(self.endian + f"{nwords}I", code_b)) if nwords else []
        strings = self.data[code_end:logical_end]
        return Program(entry=e, words=words, strings=strings)

# ---- Program state ---------------------------------------------------------

@dataclass
class Program:
    entry: Entry
    words: List[int]
    strings: bytes

class State:
    def __init__(self, program: Program, trace: bool = False):
        self.program = program
        self.words = program.words
        self.strings = program.strings
        self.pc = 0
        self.strs_base = 0
        self.trace_enabled = trace
        self.trace: List[Dict[str, Any]] = []
        self.consumed: Set[int] = set()

    def check_pc(self, idx: Optional[int] = None) -> int:
        i = self.pc if idx is None else idx
        if i < 0 or i >= len(self.words):
            raise DecompileError(
                f"{self.program.entry.name}: wordcode PC {i} outside 0..{len(self.words)-1}"
            )
        return i

    def read_word(self, role: str = "word") -> int:
        i = self.check_pc()
        w = self.words[i]
        self.consumed.add(i)
        self.pc += 1
        if self.trace_enabled:
            self.trace.append({
                "pc": i,
                "raw": f"0x{w:08x}",
                "role": role,
                "opcode": WC_NAMES.get(wc_code(w)) if role == "opcode" else None,
                "data": wc_data(w) if role == "opcode" else None,
            })
        return w

    def peek_word(self, offset: int = 0) -> int:
        return self.words[self.check_pc(self.pc + offset)]

    def skip_word(self, role: str = "skip") -> int:
        return self.read_word(role)

    def set_pc(self, newpc: int, why: str = "jump") -> None:
        if newpc < 0 or newpc > len(self.words):
            raise DecompileError(
                f"{self.program.entry.name}: invalid {why} target PC {newpc}"
            )
        if self.trace_enabled:
            self.trace.append({"pc": self.pc, "role": why, "target": newpc})
        self.pc = newpc

    def getstr(self, role: str = "string") -> bytes:
        c = self.read_word(role)
        if c == 6 or c == 7:
            return b""
        if c & 2:
            raw = bytes([
                (c >> 3) & 0xFF,
                (c >> 11) & 0xFF,
                (c >> 19) & 0xFF,
            ])
            return raw.split(b"\x00", 1)[0]

        off = self.strs_base + (c >> 2)
        if off < 0 or off >= len(self.strings):
            raise DecompileError(
                f"{self.program.entry.name}: string offset 0x{off:x} "
                f"outside table (base 0x{self.strs_base:x}, size 0x{len(self.strings):x})"
            )
        end = self.strings.find(b"\x00", off)
        if end < 0:
            raise DecompileError(
                f"{self.program.entry.name}: unterminated string at table offset 0x{off:x}"
            )
        return self.strings[off:end]

# ---- Text reconstruction ---------------------------------------------------

class TextBuilder:
    def __init__(self, indent_spaces: int = 4):
        self.buf = bytearray()
        self.indent = 0
        self.indent_spaces = indent_spaces
        self.pending: List[bytes] = []

    def add(self, x: Union[bytes, str]) -> None:
        if isinstance(x, str):
            self.buf.extend(x.encode())
        else:
            self.buf.extend(x)

    def addchr(self, c: str) -> None:
        self.buf.extend(c.encode())

    def add_pending(self, a: bytes, b: bytes) -> None:
        self.pending.append(a + b)

    def flush_pending(self) -> None:
        if self.pending:
            self.buf.extend(b"\n")
            self.buf.extend(b"\n".join(self.pending))
            self.pending.clear()

    def nl(self, no_semicolon: bool = False) -> None:
        self.flush_pending()
        self.buf.extend(b"\n")
        self.buf.extend(b" " * (self.indent * self.indent_spaces))

    def dec_indent(self) -> None:
        if self.indent > 0:
            self.indent -= 1

    def finish(self) -> bytes:
        self.flush_pending()
        return bytes(self.buf).rstrip() + b"\n"

class Decompiler:
    """
    Python translation of zsh 5.9 text.c:getpermtext()/gettext2().
    It consumes the actual wordcode structure rather than guessing opcodes.
    """
    def __init__(self, program: Program, indent_spaces: int = 4, trace: bool = False):
        self.p = program
        self.s = State(program, trace=trace)
        self.t = TextBuilder(indent_spaces)
        self.stack: List[Frame] = []
        self.max_steps = max(10000, len(program.words) * 100)
        self.steps = 0
        self.warnings: List[str] = []

    def push(self, code: int, pop: bool) -> Frame:
        f = Frame(code=code, pop=bool(pop))
        self.stack.append(f)
        return f

    def taddlist(self, num: int) -> None:
        if num < 0 or num > len(self.s.words):
            raise DecompileError(f"unreasonable string-list count: {num}")
        vals = [self.s.getstr("string-arg") for _ in range(num)]
        self.t.add(b" ".join(vals))

    def taddassign(self, code: int, typeset: bool) -> None:
        self.t.add(self.s.getstr("assign-name"))
        if wc_assign_type2(code) == WC_ASSIGN_INC:
            if typeset:
                self.s.getstr("typeset-dummy-value")
                self.t.add(" ")
                return
            self.t.add("+")
        self.t.add("=")
        if wc_assign_type(code) == WC_ASSIGN_ARRAY:
            self.t.add("(")
            self.taddlist(wc_assign_num(code))
            self.t.add(") ")
        else:
            self.t.add(self.s.getstr("assign-value"))
            self.t.add(" ")

    def taddassignlist(self, count: int) -> None:
        if count:
            self.t.add(" ")
        for _ in range(count):
            code = self.s.read_word("typeset-assignment")
            if wc_code(code) != WC_ASSIGN:
                raise DecompileError(
                    f"typeset assignment at PC {self.s.pc-1} is "
                    f"{WC_NAMES.get(wc_code(code), wc_code(code))}, expected WC_ASSIGN"
                )
            self.taddassign(code, True)

    def ecgetredirs(self) -> List[Redir]:
        ret: List[Redir] = []
        while self.s.pc < len(self.s.words):
            code = self.s.peek_word()
            if wc_code(code) != WC_REDIR:
                break
            code = self.s.read_word("redir")
            typ = wc_redir_type(code)
            fd1 = self.s.read_word("redir-fd")
            name = self.s.getstr("redir-name")
            r = Redir(type=typ, fd1=fd1, name=name)
            if wc_redir_from_heredoc(code):
                r.from_heredoc = True
                r.here_terminator = self.s.getstr("heredoc-terminator")
                r.munged_here_terminator = self.s.getstr("heredoc-munged-terminator")
            if wc_redir_varid(code):
                r.varid = self.s.getstr("redir-varid")
            ret.append(r)
        return ret

    def render_redirs(self, redirs: List[Redir]) -> None:
        if not redirs:
            return
        self.t.add(" ")
        rendered: List[bytes] = []
        for r in redirs:
            part = bytearray()
            if r.varid:
                part.extend(b"{")
                part.extend(r.varid)
                part.extend(b"}")
            else:
                default_fd = 0 if is_read_fd(r.type) else 1
                if r.fd1 != default_fd:
                    part.extend(str(r.fd1).encode())

            if r.type == REDIR_HERESTR and r.from_heredoc:
                # Match getredirs(): reconstruct a heredoc.
                part.extend(b"<<")
                part.extend(r.here_terminator or b"EOF")
                self.t.add(bytes(part))
                self.t.add_pending(r.name, r.munged_here_terminator or b"")
                continue

            op = REDIR_TEXT.get(r.type, f"<REDIR:{r.type}>").encode()
            part.extend(op)
            if r.type not in (REDIR_MERGEIN, REDIR_MERGEOUT, REDIR_CLOSE):
                part.extend(b" ")
            if r.type != REDIR_CLOSE:
                part.extend(r.name)
            rendered.append(bytes(part))

        if rendered:
            self.t.add(b" ".join(rendered))

    def decompile(self) -> str:
        stack_flag = 0

        while True:
            self.steps += 1
            if self.steps > self.max_steps:
                raise DecompileError("wordcode walk exceeded safety step limit")

            if stack_flag:
                if not self.stack:
                    break
                frame = self.stack[-1]
                if frame.pop:
                    self.stack.pop()
                code = frame.code
                sframe: Optional[Frame] = frame
                stack_flag = 0
            else:
                if self.s.pc >= len(self.s.words):
                    # Well-formed Eprog ends with WC_END. Treat exact exhaustion
                    # as a graceful forensic fallback rather than looping.
                    if self.stack:
                        raise DecompileError(
                            f"wordcode exhausted at PC {self.s.pc} with "
                            f"{len(self.stack)} pending structure(s)"
                        )
                    break
                sframe = None
                code = self.s.read_word("opcode")

            op = wc_code(code)
            if op >= WC_COUNT:
                raise DecompileError(
                    f"unknown wordcode opcode {op} from 0x{code:08x} "
                    f"near PC {self.s.pc-1}"
                )

            if op == WC_LIST:
                if sframe is None:
                    sframe = self.push(code, bool(wc_list_type(code) & Z_END))
                    stack_flag = 0
                else:
                    if wc_list_type(code) & Z_ASYNC:
                        self.t.add(" &")
                        if wc_list_type(code) & Z_DISOWN:
                            self.t.add("|")
                    stack_flag = 1 if (wc_list_type(code) & Z_END) else 0
                    if not stack_flag:
                        self.t.nl(False)
                        sframe.code = self.s.read_word("next-list")
                        sframe.pop = bool(wc_list_type(sframe.code) & Z_END)
                if not stack_flag and (wc_list_type(sframe.code) & Z_SIMPLE):
                    self.s.skip_word("simple-list-lineno")
                continue

            if op == WC_SUBLIST:
                if sframe is None:
                    if not (wc_sublist_flags(code) & WC_SUBLIST_SIMPLE):
                        if wc_code(self.s.peek_word()) != WC_PIPE:
                            stack_flag = -1
                    if wc_sublist_flags(code) & WC_SUBLIST_NOT:
                        self.t.add("!" if stack_flag else "! ")
                    if wc_sublist_flags(code) & WC_SUBLIST_COPROC:
                        self.t.add("coproc" if stack_flag else "coproc ")
                    sframe = self.push(code, wc_sublist_type(code) == WC_SUBLIST_END)
                else:
                    stack_flag = 1 if wc_sublist_type(code) == WC_SUBLIST_END else 0
                    if not stack_flag:
                        self.t.add(" || " if wc_sublist_type(code) == WC_SUBLIST_OR else " && ")
                        sframe.code = self.s.read_word("next-sublist")
                        sframe.pop = wc_sublist_type(sframe.code) == WC_SUBLIST_END
                        if wc_sublist_flags(sframe.code) & WC_SUBLIST_NOT:
                            if wc_sublist_skip(sframe.code) == 0:
                                stack_flag = 1
                            complex_next = (
                                not (wc_sublist_flags(sframe.code) & WC_SUBLIST_SIMPLE)
                                and wc_code(self.s.peek_word()) != WC_PIPE
                            )
                            self.t.add("!" if (stack_flag or complex_next) else "! ")
                        if wc_sublist_flags(sframe.code) & WC_SUBLIST_COPROC:
                            self.t.add("coproc ")
                if stack_flag < 1 and (wc_sublist_flags(sframe.code) & WC_SUBLIST_SIMPLE):
                    self.s.skip_word("simple-sublist-lineno")
                continue

            if op == WC_PIPE:
                if sframe is None:
                    self.push(code, wc_pipe_type(code) == WC_PIPE_END)
                    if wc_pipe_type(code) == WC_PIPE_MID:
                        self.s.skip_word("pipe-next-offset")
                else:
                    stack_flag = 1 if wc_pipe_type(code) == WC_PIPE_END else 0
                    if not stack_flag:
                        self.t.add(" | ")
                        sframe.code = self.s.read_word("next-pipe")
                        sframe.pop = wc_pipe_type(sframe.code) == WC_PIPE_END
                        if not sframe.pop:
                            self.s.skip_word("pipe-next-offset")
                continue

            if op == WC_REDIR:
                if sframe is None:
                    self.s.pc -= 1
                    f = self.push(code, True)
                    f.redirs = self.ecgetredirs()
                else:
                    self.render_redirs(sframe.redirs or [])
                    stack_flag = 1
                continue

            if op == WC_ASSIGN:
                self.taddassign(code, False)
                continue

            if op == WC_SIMPLE:
                self.taddlist(wc_data(code))
                stack_flag = 1
                continue

            if op == WC_TYPESET:
                self.taddlist(wc_data(code))
                count = self.s.read_word("typeset-assignment-count")
                self.taddassignlist(count)
                stack_flag = 1
                continue

            if op == WC_SUBSH:
                if sframe is None:
                    self.t.add("(")
                    self.t.indent += 1
                    self.t.nl(True)
                    f = self.push(code, True)
                    f.subsh_end = self.s.pc + wc_data(code)
                    self.s.skip_word("subsh-try-slot")
                else:
                    self.s.set_pc(sframe.subsh_end, "subsh-end")
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add(")")
                    stack_flag = 1
                continue

            if op == WC_CURSH:
                if sframe is None:
                    self.t.add("{")
                    self.t.indent += 1
                    self.t.nl(True)
                    f = self.push(code, True)
                    f.subsh_end = self.s.pc + wc_data(code)
                    self.s.skip_word("cursh-try-slot")
                else:
                    self.s.set_pc(sframe.subsh_end, "cursh-end")
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("}")
                    stack_flag = 1
                continue

            if op == WC_TIMED:
                if sframe is None:
                    self.t.add("time")
                    if wc_data(code) == WC_TIMED_PIPE:
                        self.t.add(" ")
                        self.t.indent += 1
                        self.push(code, True)
                    else:
                        stack_flag = 1
                else:
                    self.t.dec_indent()
                    stack_flag = 1
                continue

            if op == WC_FUNCDEF:
                if sframe is None:
                    p = self.s.pc
                    end = p + wc_funcdef_skip(code)
                    if end < p or end > len(self.s.words):
                        raise DecompileError(f"bad function end PC {end} from PC {p}")
                    nargs = self.s.read_word("func-name-count")
                    if nargs > len(self.s.words):
                        raise DecompileError(f"unreasonable function name count: {nargs}")
                    # zsh 5.9 prints names and then () { ... }.
                    self.taddlist(nargs)
                    if nargs:
                        self.t.add(" ")
                    self.t.add("() {")
                    self.t.indent += 1
                    self.t.nl(True)
                    f = self.push(code, True)
                    f.func_old_strs = self.s.strs_base
                    f.func_end = end
                    f.func_nargs = nargs

                    str_delta = self.s.read_word("func-string-offset")
                    _str_len = self.s.read_word("func-string-length")
                    _npats = self.s.read_word("func-pattern-count")
                    _trace = self.s.read_word("func-tracing")
                    newbase = self.s.strs_base + str_delta
                    if newbase < 0 or newbase > len(self.s.strings):
                        raise DecompileError(
                            f"function string-table base 0x{newbase:x} outside entry table"
                        )
                    self.s.strs_base = newbase
                else:
                    assert sframe.func_old_strs is not None and sframe.func_end is not None
                    self.s.strs_base = sframe.func_old_strs
                    self.s.set_pc(sframe.func_end, "func-end")
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("}")
                    if sframe.func_nargs == 0:
                        # Anonymous function post-arguments.
                        offset = self.s.read_word("anon-func-end-offset")
                        final_end = sframe.func_end + offset
                        nargs = self.s.read_word("anon-func-arg-count")
                        if nargs:
                            self.t.add(" ")
                            self.taddlist(nargs)
                        self.s.set_pc(final_end, "anon-func-end")
                    stack_flag = 1
                continue

            if op == WC_FOR:
                if sframe is None:
                    self.t.add("for ")
                    typ = wc_for_type(code)
                    if typ == WC_FOR_COND:
                        self.t.add("((")
                        self.t.add(self.s.getstr("for-init"))
                        self.t.add("; ")
                        self.t.add(self.s.getstr("for-cond"))
                        self.t.add("; ")
                        self.t.add(self.s.getstr("for-advance"))
                        self.t.add(")) do")
                    else:
                        n = self.s.read_word("for-param-count")
                        self.taddlist(n)
                        if typ == WC_FOR_LIST:
                            self.t.add(" in ")
                            n = self.s.read_word("for-list-count")
                            self.taddlist(n)
                        self.t.nl(False)
                        self.t.add("do")
                    self.t.indent += 1
                    self.t.nl(False)
                    self.push(code, True)
                else:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("done")
                    stack_flag = 1
                continue

            if op == WC_SELECT:
                if sframe is None:
                    self.t.add("select ")
                    self.t.add(self.s.getstr("select-param"))
                    if wc_select_type(code) == WC_SELECT_LIST:
                        self.t.add(" in ")
                        n = self.s.read_word("select-list-count")
                        self.taddlist(n)
                    self.t.nl(False)
                    self.t.add("do")
                    self.t.nl(False)
                    self.t.indent += 1
                    self.push(code, True)
                else:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("done")
                    stack_flag = 1
                continue

            if op == WC_WHILE:
                if sframe is None:
                    self.t.add("until " if wc_while_type(code) == WC_WHILE_UNTIL else "while ")
                    self.t.indent += 1
                    self.push(code, False)
                elif not sframe.pop:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("do")
                    self.t.indent += 1
                    self.t.nl(False)
                    sframe.pop = True
                else:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("done")
                    stack_flag = 1
                continue

            if op == WC_REPEAT:
                if sframe is None:
                    self.t.add("repeat ")
                    self.t.add(self.s.getstr("repeat-count"))
                    self.t.nl(False)
                    self.t.add("do")
                    self.t.indent += 1
                    self.t.nl(False)
                    self.push(code, True)
                else:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("done")
                    stack_flag = 1
                continue

            if op == WC_CASE:
                if sframe is None:
                    end = self.s.pc + wc_case_skip(code)
                    self.t.add("case ")
                    self.t.add(self.s.getstr("case-word"))
                    self.t.add(" in")
                    if self.s.pc >= end:
                        self.t.nl(False)
                        self.t.add("esac")
                        stack_flag = 1
                    else:
                        self.t.indent += 1
                        self.t.nl(False)
                        self.t.add("(")
                        branch_code = self.s.read_word("case-branch")
                        prev_pc = self.s.pc
                        ialts = self.s.read_word("case-alt-count")
                        for i in range(ialts):
                            self.t.add(self.s.getstr("case-pattern"))
                            self.s.skip_word("case-pattern-number")
                            if i + 1 < ialts:
                                self.t.add(" | ")
                        self.t.add(") ")
                        self.t.indent += 1
                        f = self.push(branch_code, False)
                        f.case_end = end
                        f.pop = (prev_pc + wc_case_skip(branch_code) >= end)
                elif self.s.pc < (sframe.case_end or 0):
                    self.t.dec_indent()
                    typ = wc_case_type(code)
                    self.t.add(" ;;" if typ == WC_CASE_OR else " ;&" if typ == WC_CASE_AND else " ;|")
                    self.t.nl(False)
                    self.t.add("(")
                    branch_code = self.s.read_word("case-branch")
                    prev_pc = self.s.pc
                    ialts = self.s.read_word("case-alt-count")
                    for i in range(ialts):
                        self.t.add(self.s.getstr("case-pattern"))
                        self.s.skip_word("case-pattern-number")
                        if i + 1 < ialts:
                            self.t.add(" | ")
                    self.t.add(") ")
                    self.t.indent += 1
                    sframe.code = branch_code
                    sframe.pop = (prev_pc + wc_case_skip(branch_code) >= (sframe.case_end or 0))
                else:
                    self.t.dec_indent()
                    typ = wc_case_type(code)
                    self.t.add(" ;;" if typ == WC_CASE_OR else " ;&" if typ == WC_CASE_AND else " ;|")
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("esac")
                    stack_flag = 1
                continue

            if op == WC_IF:
                if sframe is None:
                    end = self.s.pc + wc_if_skip(code)
                    self.t.add("if ")
                    self.t.indent += 1
                    self.s.skip_word("if-first-branch")
                    f = self.push(code, False)
                    f.if_end = end
                    f.if_cond = 1
                elif sframe.pop:
                    stack_flag = 1
                elif sframe.if_cond:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("then")
                    self.t.indent += 1
                    self.t.nl(False)
                    sframe.if_cond = 0
                elif self.s.pc < (sframe.if_end or 0):
                    self.t.dec_indent()
                    self.t.nl(False)
                    branch_code = self.s.read_word("if-next-branch")
                    if wc_if_type(branch_code) == WC_IF_ELIF:
                        self.t.add("elif ")
                        self.t.indent += 1
                        sframe.if_cond = 1
                    else:
                        self.t.add("else")
                        self.t.indent += 1
                        self.t.nl(False)
                else:
                    sframe.pop = True
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("fi")
                    stack_flag = 1
                continue

            if op == WC_COND:
                ctype: int
                if sframe is None:
                    self.t.add("[[ ")
                    f = self.push(code, True)
                    f.cond_par = 2
                elif sframe.cond_par == 2:
                    self.t.add(" ]]")
                    stack_flag = 1
                    continue
                elif sframe.cond_par == 1:
                    self.t.add(" )")
                    stack_flag = 1
                    continue
                elif wc_cond_type(sframe.code) == COND_AND:
                    self.t.add(" && ")
                    code = self.s.read_word("cond-rhs")
                    if wc_cond_type(code) == COND_OR:
                        self.t.add("( ")
                        f = self.push(code, True)
                        f.cond_par = 1
                elif wc_cond_type(sframe.code) == COND_OR:
                    self.t.add(" || ")
                    code = self.s.read_word("cond-rhs")
                    if wc_cond_type(code) == COND_AND:
                        self.t.add("( ")
                        f = self.push(code, True)
                        f.cond_par = 1

                while not stack_flag:
                    ctype = wc_cond_type(code)
                    if ctype == COND_NOT:
                        self.t.add("! ")
                        code = self.s.read_word("cond-not-child")
                        if wc_cond_type(code) <= COND_OR:
                            self.t.add("( ")
                            f = self.push(code, True)
                            f.cond_par = 1
                        continue
                    if ctype == COND_AND:
                        f = self.push(code, True)
                        f.cond_par = 0
                        code = self.s.read_word("cond-left")
                        if wc_cond_type(code) == COND_OR:
                            self.t.add("( ")
                            f = self.push(code, True)
                            f.cond_par = 1
                        continue
                    if ctype == COND_OR:
                        f = self.push(code, True)
                        f.cond_par = 0
                        code = self.s.read_word("cond-left")
                        if wc_cond_type(code) == COND_AND:
                            self.t.add("( ")
                            f = self.push(code, True)
                            f.cond_par = 1
                        continue
                    if ctype == COND_MOD:
                        self.t.add(self.s.getstr("cond-module-name"))
                        self.t.add(" ")
                        self.taddlist(wc_cond_skip(code))
                        stack_flag = 1
                        break
                    if ctype == COND_MODI:
                        name = self.s.getstr("cond-infix-name")
                        self.t.add(self.s.getstr("cond-left-value"))
                        self.t.add(" ")
                        self.t.add(name)
                        self.t.add(" ")
                        self.t.add(self.s.getstr("cond-right-value"))
                        stack_flag = 1
                        break
                    if ctype < COND_MOD:
                        if ctype < COND_STREQ or ctype - COND_STREQ >= len(COND_BINARY_OPS):
                            raise DecompileError(f"invalid binary condition type {ctype}")
                        self.t.add(self.s.getstr("cond-left-value"))
                        self.t.add(" ")
                        self.t.add(COND_BINARY_OPS[ctype - COND_STREQ])
                        self.t.add(" ")
                        self.t.add(self.s.getstr("cond-right-value"))
                        if ctype in (COND_STREQ, COND_STRDEQ, COND_STRNEQ):
                            self.s.skip_word("cond-pattern-number")
                    else:
                        # Unary condition encodes operator character directly.
                        self.t.add("-" + chr(ctype) + " ")
                        self.t.add(self.s.getstr("cond-unary-value"))
                    stack_flag = 1
                    break
                continue

            if op == WC_ARITH:
                self.t.add("((")
                self.t.add(self.s.getstr("arith-expression"))
                self.t.add("))")
                stack_flag = 1
                continue

            if op == WC_AUTOFN:
                self.t.add("builtin autoload -X")
                stack_flag = 1
                continue

            if op == WC_TRY:
                if sframe is None:
                    self.t.add("{")
                    self.t.indent += 1
                    self.t.nl(False)
                    f = self.push(code, False)
                    first = self.s.read_word("try-first-cursh")
                    f.subsh_end = self.s.pc + wc_data(first)
                elif not sframe.pop:
                    self.s.set_pc(sframe.subsh_end, "try-block-end")
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("} always {")
                    self.t.indent += 1
                    self.t.nl(False)
                    sframe.pop = True
                else:
                    self.t.dec_indent()
                    self.t.nl(False)
                    self.t.add("}")
                    stack_flag = 1
                continue

            if op == WC_END:
                stack_flag = 1
                continue

            raise DecompileError(f"unhandled opcode {op}")

        raw = self.t.finish()
        return display(raw)

    def coverage(self) -> Dict[str, Any]:
        """
        Report traversal coverage.

        getpermtext()/gettext2() deliberately does not consume some WC_END
        sentinels: e.g. the end marker appended to an Eprog and function-body
        sentinels skipped when the enclosing WC_FUNCDEF resumes.  Therefore
        "complete" means every *non-zero* word was visited/consumed.  Remaining
        zero words are reported separately rather than counted as a failure.
        """
        total = len(self.s.words)
        consumed_set = self.s.consumed
        unconsumed = sorted(set(range(total)) - consumed_set)
        zero_unconsumed = [i for i in unconsumed if self.s.words[i] == 0]
        nonzero_unconsumed = [i for i in unconsumed if self.s.words[i] != 0]
        consumed = len(consumed_set)
        return {
            "total_words": total,
            "consumed_words": consumed,
            "consumed_percent": round((consumed / total * 100.0) if total else 100.0, 2),
            "semantic_walk_complete": not nonzero_unconsumed,
            "unconsumed_zero_word_indices": zero_unconsumed,
            "unconsumed_nonzero_word_indices": nonzero_unconsumed,
        }

# ---- Forensic string extraction -------------------------------------------

def extract_string_table(blob: bytes, min_len: int = 3) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pos = 0
    while pos < len(blob):
        end = blob.find(b"\x00", pos)
        if end < 0:
            break
        raw = blob[pos:end]
        rendered = display(raw)
        if len(rendered) >= min_len:
            out.append({"offset": pos, "value": rendered})
        pos = end + 1
    return out

# ---- Built-in regression tests ---------------------------------------------

def _wcb(op: int, data: int = 0) -> int:
    return op | (data << WC_CODEBITS)

def _scode(offset: int, tokenized: bool = False) -> int:
    return (offset << 2) | (1 if tokenized else 0)

def _test_program(name: str, words: List[int], strings: bytes, expected: str) -> None:
    e = Entry(
        name=name, start_word=0, length_bytes=0, npats=0,
        strings_offset=0, header_words=0, flags=0, tail_offset=0,
    )
    d = Decompiler(Program(e, words, strings))
    got = d.decompile()
    if got != expected:
        raise AssertionError(
            "{} failed\nEXPECTED:\n{!r}\nGOT:\n{!r}".format(name, expected, got)
        )
    cov = d.coverage()
    if not cov["semantic_walk_complete"]:
        raise AssertionError(
            "{} left non-zero wordcode unconsumed: {}".format(
                name, cov["unconsumed_nonzero_word_indices"]
            )
        )

def run_self_tests() -> None:
    # Simple command: echo hi
    strings = b"echo\x00hi\x00"
    words = [
        _wcb(WC_LIST, Z_END | Z_SIMPLE), 1,
        _wcb(WC_SUBLIST, WC_SUBLIST_END | WC_SUBLIST_SIMPLE), 1,
        _wcb(WC_PIPE, WC_PIPE_END),
        _wcb(WC_SIMPLE, 2), _scode(0), _scode(5),
        _wcb(WC_END),
    ]
    _test_program("simple", words, strings, "echo hi\n")

    # typeset/export dummy assignment: export PATH
    strings = b"export\x00PATH\x00dummy\x00"
    words = [
        _wcb(WC_LIST, Z_END | Z_SIMPLE), 1,
        _wcb(WC_SUBLIST, WC_SUBLIST_END | WC_SUBLIST_SIMPLE), 1,
        _wcb(WC_PIPE, WC_PIPE_END),
        _wcb(WC_TYPESET, 1), _scode(0), 1,
        _wcb(WC_ASSIGN, WC_ASSIGN_SCALAR | (WC_ASSIGN_INC << 1)),
        _scode(7), _scode(12),
        _wcb(WC_END),
    ]
    _test_program("typeset", words, strings, "export PATH\n")

    # Named function. The function-body WC_END and outer Eprog WC_END are
    # expected structural sentinels and need not be consumed by gettext2.
    strings = b"write\x00print\x00hello\x00"
    words = [
        _wcb(WC_LIST, Z_END | Z_SIMPLE), 1,
        _wcb(WC_SUBLIST, WC_SUBLIST_END | WC_SUBLIST_SIMPLE), 1,
        _wcb(WC_PIPE, WC_PIPE_END),
    ]
    fidx = len(words)
    words.append(0)                         # WC_FUNCDEF patched below
    pidx = len(words)                       # p in text.c: state->pc
    words += [1, _scode(0)]                 # one function name: write
    words += [0, 0, 0, 0]                  # strs delta,len,npats,tracing
    words += [
        _wcb(WC_LIST, Z_END | Z_SIMPLE), 1,
        _wcb(WC_SUBLIST, WC_SUBLIST_END | WC_SUBLIST_SIMPLE), 1,
        _wcb(WC_PIPE, WC_PIPE_END),
        _wcb(WC_SIMPLE, 2), _scode(6), _scode(12),
    ]
    body_end = len(words)
    words.append(_wcb(WC_END))
    words[fidx] = _wcb(WC_FUNCDEF, body_end - pidx)
    words.append(_wcb(WC_END))
    _test_program(
        "funcdef", words, strings,
        "write () {\n    print hello\n}\n",
    )

# ---- CLI ------------------------------------------------------------------

def sanitize_filename(name: str, index: int) -> str:
    tail = Path(name).name or f"entry-{index}"
    clean = "".join(c if c.isalnum() or c in "._-" else "_" for c in tail)
    return clean or f"entry-{index}"

def build_report(z: ZWCFile, args) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "file": str(z.path),
        "size": len(z.data),
        "sha256": sha256(z.data),
        "zsh_version": z.version,
        "byte_order": z.endian_name,
        "mode": "mapped" if z.flags & FDF_MAP else "read",
        "other_image_offset": z.other_offset,
        "other_image_warning": getattr(z, "other_image_warning", None),
        "entries": [],
    }

    for idx, e in enumerate(z.entries):
        if args.entry and args.entry not in e.name and args.entry != str(idx):
            continue
        p = z.entry_program(e)
        d = Decompiler(p, indent_spaces=args.indent, trace=args.trace)
        err = None
        source = None
        try:
            source = d.decompile()
        except DecompileError as exc:
            err = str(exc)

        cov = d.coverage()
        if err is None and args.strict and not cov["semantic_walk_complete"]:
            err = (
                "semantic walk left non-zero wordcode unconsumed at indices "
                + ",".join(map(str, cov["unconsumed_nonzero_word_indices"]))
            )
            source = None

        load_style = (
            "ksh" if (e.flags & 1) else
            "zsh" if (e.flags & 2) else
            "default"
        )
        er: Dict[str, Any] = {
            "index": idx,
            "name": e.name,
            "start_word": e.start_word,
            "length_bytes": e.length_bytes,
            "npats": e.npats,
            "strings_offset": e.strings_offset,
            "flags": e.flags,
            "load_style": load_style,
            "tail_offset": e.tail_offset,
            "wordcode_words": len(p.words),
            "string_table_bytes": len(p.strings),
            "decompiled": source,
            "error": err,
            "coverage": cov,
        }
        if args.strings:
            er["strings"] = extract_string_table(p.strings, args.min_string)
        if args.trace:
            er["trace"] = d.s.trace
        report["entries"].append(er)
    return report

def print_human(report: Dict[str, Any], args) -> int:
    print("=== ZWC STATIC DECOMPILER ===", file=sys.stderr)
    print(f"File:        {report['file']}", file=sys.stderr)
    print(f"SHA256:      {report['sha256']}", file=sys.stderr)
    print(f"zsh version: {report['zsh_version']}", file=sys.stderr)
    print(f"Byte order:  {report['byte_order']}", file=sys.stderr)
    print(f"Mode:        {report['mode']}", file=sys.stderr)
    print(f"Entries:     {len(report['entries'])}", file=sys.stderr)
    if report.get("other_image_warning"):
        print(f"Warning:     {report['other_image_warning']}", file=sys.stderr)

    exitcode = 0
    for er in report["entries"]:
        print(f"\n# ===== ZWC ENTRY {er['index']}: {er['name']} =====")
        walk = "complete" if er["coverage"]["semantic_walk_complete"] else "INCOMPLETE"
        print(
            f"# wordcode={er['wordcode_words']} words, "
            f"strings={er['string_table_bytes']} bytes, "
            f"semantic-walk={walk}, "
            f"raw-consumed={er['coverage']['consumed_percent']}%"
        )
        if er["coverage"]["unconsumed_zero_word_indices"]:
            print(
                "# structural zero/sentinel words not consumed: "
                + ",".join(map(str, er["coverage"]["unconsumed_zero_word_indices"]))
            )
        if er["coverage"]["unconsumed_nonzero_word_indices"]:
            print(
                "# WARNING: non-zero words not consumed: "
                + ",".join(map(str, er["coverage"]["unconsumed_nonzero_word_indices"]))
            )
        if er["error"]:
            exitcode = 2
            print(f"# [DECOMPILE ERROR] {er['error']}")
        else:
            print(er["decompiled"], end="" if er["decompiled"].endswith("\n") else "\n")

        if args.strings:
            print("\n# ----- STRING TABLE -----")
            for s in er.get("strings", []):
                print(f"# str+0x{s['offset']:04x}  {s['value']}")

        if args.trace:
            print("\n# ----- WORDCODE TRACE -----")
            for tr in er.get("trace", []):
                if tr.get("raw"):
                    opname = tr.get("opcode") or ""
                    data = f" data={tr['data']}" if tr.get("data") is not None else ""
                    print(
                        f"# pc={tr['pc']:06d} {tr['raw']} "
                        f"{tr['role']:<28} {opname}{data}"
                    )
                else:
                    print(f"# pc={tr['pc']:06d} {tr['role']} -> {tr.get('target')}")
    return exitcode

def write_outputs(report: Dict[str, Any], outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    for er in report["entries"]:
        name = sanitize_filename(er["name"], er["index"])
        target = outdir / f"{name}.reconstructed.zsh"
        if er["decompiled"] is not None:
            target.write_text(er["decompiled"], encoding="utf-8")
        else:
            target.write_text(f"# DECOMPILE ERROR: {er['error']}\n", encoding="utf-8")

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Statically reconstruct source-like text from zsh .zwc wordcode without executing it."
    )
    ap.add_argument("zwc", nargs="?", type=Path, help="compiled zsh .zwc file")
    ap.add_argument("--entry", help="only an entry containing this name, or numeric index")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    ap.add_argument("--strings", action="store_true", help="also dump the raw string table")
    ap.add_argument("--min-string", type=int, default=3, help="minimum forensic string length")
    ap.add_argument("--trace", action="store_true", help="include a word-by-word consumption trace")
    ap.add_argument("--indent", type=int, default=4, help="spaces per reconstructed indentation level")
    ap.add_argument("--output-dir", type=Path, help="write reconstructed entries as .zsh files")
    ap.add_argument("--strict", action="store_true",
                    help="fail an entry if non-zero wordcode remains unreachable")
    ap.add_argument("--self-test", action="store_true",
                    help="run built-in decoder regression tests and exit")
    args = ap.parse_args()

    if args.self_test:
        try:
            run_self_tests()
        except Exception as exc:
            print("[!] self-test failed: {}".format(exc), file=sys.stderr)
            return 1
        print("[+] all built-in decoder tests passed")
        return 0

    if args.zwc is None:
        ap.error("the following arguments are required: zwc (unless --self-test is used)")

    try:
        z = ZWCFile(args.zwc)
        report = build_report(z, args)
    except (OSError, ZWCError, struct.error) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    if not report["entries"]:
        print("[!] no matching ZWC entries", file=sys.stderr)
        return 1

    # The dump format is version-coupled. Be explicit rather than pretending
    # that an incompatible version is safe to decode.
    if z.version != "5.9":
        print(
            f"[!] warning: decoder is validated against zsh 5.9 layout; "
            f"file reports zsh {z.version}",
            file=sys.stderr,
        )

    if args.output_dir:
        write_outputs(report, args.output_dir)

    if args.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        print()
        return 2 if any(e["error"] for e in report["entries"]) else 0

    return print_human(report, args)

if __name__ == "__main__":
    raise SystemExit(main())
