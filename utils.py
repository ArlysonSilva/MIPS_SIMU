# utils.py
import re

# Mapeamento de nomes de registradores para seus números
REGISTER_MAP = {
    "$zero": 0, "$0": 0,
    "$at": 1, "$1": 1,
    "$v0": 2, "$2": 2,
    "$v1": 3, "$3": 3,
    "$a0": 4, "$4": 4,
    "$a1": 5, "$5": 5,
    "$a2": 6, "$6": 6,
    "$a3": 7, "$7": 7,
    "$t0": 8, "$8": 8,
    "$t1": 9, "$9": 9,
    "$t2": 10, "$10": 10,
    "$t3": 11, "$11": 11,
    "$t4": 12, "$12": 12,
    "$t5": 13, "$13": 13,
    "$t6": 14, "$14": 14,
    "$t7": 15, "$15": 15,
    "$s0": 16, "$16": 16,
    "$s1": 17, "$17": 17,
    "$s2": 18, "$18": 18,
    "$s3": 19, "$19": 19,
    "$s4": 20, "$20": 20,
    "$s5": 21, "$21": 21,
    "$s6": 22, "$22": 22,
    "$s7": 23, "$23": 23,
    "$t8": 24, "$24": 24,
    "$t9": 25, "$25": 25,
    "$k0": 26, "$26": 26,
    "$k1": 27, "$27": 27,
    "$gp": 28, "$28": 28,
    "$sp": 29, "$29": 29,
    "$fp": 30, "$30": 30, 
    "$s8": 30, 
    "$ra": 31, "$31": 31,
}

REG_NAME_MAP = {v: k for k, v in REGISTER_MAP.items() if k.startswith("$") and len(k) > 2 and not k[1].isdigit()}
for i in range(32):
    if i not in REG_NAME_MAP: REG_NAME_MAP[i] = f"${i}"
REG_NAME_MAP[0] = "$zero"; REG_NAME_MAP[30] = "$fp"

# Opcodes e Functs
# Chave: mnemônico, Valor: (opcode, funct se R-type/None, tipo_instrução_categoria, [operand_format_esperado_opcional])
INSTRUCTION_FORMATS = {
    # R-Type
    "add":    (0x00, 0x20, 'R', None), "addu":   (0x00, 0x21, 'R', None),
    "sub":    (0x00, 0x22, 'R', None), "subu":   (0x00, 0x23, 'R', None),
    "and":    (0x00, 0x24, 'R', None), "or":     (0x00, 0x25, 'R', None),
    "xor":    (0x00, 0x26, 'R', None), "nor":    (0x00, 0x27, 'R', None),
    "slt":    (0x00, 0x2a, 'R', None), "sltu":   (0x00, 0x2b, 'R', None),
    "sll":    (0x00, 0x00, 'R', None), "srl":    (0x00, 0x02, 'R', None), "sra":    (0x00, 0x03, 'R', None),
    "sllv":   (0x00, 0x04, 'R', None), "srlv":   (0x00, 0x06, 'R', None), "srav":   (0x00, 0x07, 'R', None),
    "jr":     (0x00, 0x08, 'R', None), "jalr":   (0x00, 0x09, 'R', None),
    "mult":   (0x00, 0x18, 'R', None), "multu":  (0x00, 0x19, 'R', None),
    "div":    (0x00, 0x1a, 'R', None), "divu":   (0x00, 0x1b, 'R', None),
    "mfhi":   (0x00, 0x10, 'R', None), "mflo":   (0x00, 0x12, 'R', None),
    "mthi":   (0x00, 0x11, 'R', None), "mtlo":   (0x00, 0x13, 'R', None),
    "syscall":(0x00, 0x0c, 'Syscall', None), 
    "break":  (0x00, 0x0d, 'R', None), 

    # I-Type
    "addi":   (0x08, None, 'I', None), "addiu":  (0x09, None, 'I', None),
    "andi":   (0x0c, None, 'I', None), "ori":    (0x0d, None, 'I', None), "xori":   (0x0e, None, 'I', None),
    "slti":   (0x0a, None, 'I', None), "sltiu":  (0x0b, None, 'I', None),
    "lui":    (0x0f, None, 'I', None),

    # Load/Store
    "lw":     (0x23, None, 'LoadStore', None), "sw":     (0x2b, None, 'LoadStore', None),
    "lb":     (0x20, None, 'LoadStore', None), "lbu":    (0x24, None, 'LoadStore', None),
    "lh":     (0x21, None, 'LoadStore', None), "lhu":    (0x25, None, 'LoadStore', None),
    "sb":     (0x28, None, 'LoadStore', None), "sh":     (0x29, None, 'LoadStore', None),

    # Branch
    "beq":    (0x04, None, 'Branch', None),  "bne":    (0x05, None, 'Branch', None),
    "blez":   (0x06, None, 'Branch', None),  "bgtz":   (0x07, None, 'Branch', None),

    # J-Type
    "j":      (0x02, None, 'J', None), "jal":    (0x03, None, 'J', None),
}

def _expand_li(rt_str, imm_val): 
    if -32768 <= imm_val <= 32767: return [("addiu", [rt_str, "$zero", str(imm_val)])]
    elif 0 <= imm_val <= 0xFFFF: return [("ori", [rt_str, "$zero", str(imm_val)])]
    else:
        upper = (imm_val >> 16) & 0xFFFF; lower = imm_val & 0xFFFF
        instrs = [("lui", [rt_str, str(upper)])]
        if lower != 0 or (upper == 0 and lower == 0): instrs.append(("ori", [rt_str, rt_str, str(lower)]))
        return instrs

def _expand_la(rt_str, label_str):
    return [("lui", [rt_str, f"%hi({label_str})"]),
            ("ori", [rt_str, rt_str, f"%lo({label_str})"])]

PSEUDO_INSTRUCTIONS = {
    "move": lambda ops: [("add", [ops[0], ops[1], "$zero"])], 
    "li": lambda ops: _expand_li(ops[0], ops[1]), 
    "la": lambda ops: _expand_la(ops[0], ops[1]), 
    "nop": lambda ops: [("sll", ["$zero", "$zero", "0"])],
    "b": lambda ops: [("beq", ["$zero", "$zero", ops[0]])], 
    "bal": lambda ops: [("bgezal", ["$zero", ops[0]])], 
}

TEXT_SEGMENT_START = 0x00400000
DATA_SEGMENT_START = 0x10010000
STACK_POINTER_INITIAL = 0x7FFFFFFC 
MAX_MEMORY_ADDR_MIPS = 0x7FFFFFFF 

def get_reg_num(reg_str): return REGISTER_MAP.get(reg_str.lower())
def get_reg_name(reg_num): return REG_NAME_MAP.get(reg_num, f"${reg_num}")
def to_signed_32(value): value &= 0xFFFFFFFF; return value - 0x100000000 if value & 0x80000000 else value
def to_unsigned_32(value): return value & 0xFFFFFFFF
def sign_extend_16_to_32(value): value &= 0xFFFF; return value | 0xFFFF0000 if value & 0x8000 else value
def sign_extend_8_to_32(value): value &= 0xFF; return value | 0xFFFFFF00 if value & 0x80 else value
def assemble_r_type(op, rs, rt, rd, sh, fn): return (op<<26)|(rs<<21)|(rt<<16)|(rd<<11)|(sh<<6)|fn
def assemble_i_type(op, rs, rt, imm): return (op<<26)|(rs<<21)|(rt<<16)|(imm&0xFFFF)
def assemble_j_type(op, addr): return (op<<26)|(addr&0x03FFFFFF)

SYSCALL_PRINT_INT = 1; SYSCALL_PRINT_FLOAT = 2; SYSCALL_PRINT_DOUBLE = 3
SYSCALL_PRINT_STRING = 4; SYSCALL_READ_INT = 5; SYSCALL_READ_FLOAT = 6
SYSCALL_READ_DOUBLE = 7; SYSCALL_READ_STRING = 8; SYSCALL_SBRK = 9
SYSCALL_EXIT = 10; SYSCALL_PRINT_CHAR = 11; SYSCALL_READ_CHAR = 12
SYSCALL_OPEN = 13; SYSCALL_READ = 14; SYSCALL_WRITE = 15; SYSCALL_CLOSE = 16
SYSCALL_EXIT2 = 17