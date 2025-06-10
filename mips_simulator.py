# mips_simulator.py
from utils import (get_reg_name, to_signed_32, to_unsigned_32, sign_extend_16_to_32, sign_extend_8_to_32,
                   INSTRUCTION_FORMATS, TEXT_SEGMENT_START, DATA_SEGMENT_START, STACK_POINTER_INITIAL,
                   SYSCALL_PRINT_INT, SYSCALL_PRINT_STRING, SYSCALL_READ_INT, SYSCALL_READ_STRING,
                   SYSCALL_SBRK, SYSCALL_EXIT, SYSCALL_PRINT_CHAR, SYSCALL_READ_CHAR, SYSCALL_EXIT2)

class ArithmeticOverflow(Exception): pass
class InvalidInstruction(Exception): pass
class MemoryAccessException(Exception): pass


class MipsSimulator:
    def __init__(self, clock_hz=100e6, cpi_config=None, gui_hooks=None):
        self.gui_hooks = gui_hooks
        self.clock_hz = float(clock_hz)
        default_cpi = {'R': 1, 'I': 1, 'J': 1, 'LoadStore': 2, 'Branch':1, 'Syscall': 10, 'Unknown': 1}
        self.cpi_values = {**default_cpi, **(cpi_config if cpi_config else {})}
        
        # Memória e Mapeamento
        self.memory_array_size = 16 * 1024 * 1024 # 16MB
        self.memory = bytearray(self.memory_array_size)

        self.text_segment_mips_base = TEXT_SEGMENT_START
        self.text_segment_array_offset = 0 
        self.text_segment_max_size = 4 * 1024 * 1024 

        self.data_segment_mips_base = DATA_SEGMENT_START
        self.data_segment_array_offset = self.text_segment_max_size 
        self.data_segment_max_size = 8 * 1024 * 1024 # Aumentado para dados + heap

        self.stack_mips_top = STACK_POINTER_INITIAL
        self.stack_array_end = self.memory_array_size - 1
        self.stack_max_size = 1 * 1024 * 1024 
        
        # Validação do layout da memória no array
        if (self.data_segment_array_offset + self.data_segment_max_size > self.memory_array_size or
            self.text_segment_array_offset + self.text_segment_max_size > self.data_segment_array_offset or
            (self.memory_array_size - self.stack_max_size) < (self.data_segment_array_offset + self.data_segment_max_size) ): # Checa se pilha não invade dados
            # A última checagem acima é simplista. A pilha cresce para baixo a partir do fim do array,
            # os dados crescem para cima a partir de data_segment_array_offset. Eles não devem se encontrar.
            # O importante é que os offsets e tamanhos sejam consistentes com memory_array_size.
            self._log_gui(f"Alert: Memory layout issue. Text end: {self.text_segment_array_offset + self.text_segment_max_size}, Data end: {self.data_segment_array_offset + self.data_segment_max_size}, Stack start: {self.memory_array_size - self.stack_max_size}")


        self.reset_state() # Inicializa registradores, PC, etc.

    def _log_gui(self, message, is_exception=False):
        if self.gui_hooks and self.gui_hooks.get('log_message'):
            prefix = "EXCEPTION: " if is_exception else "SIM_LOG: "
            self.gui_hooks['log_message'](prefix + message)
        else:
            print(prefix + message if is_exception else message)

    def reset_state(self):
        self.regs = [0] * 32
        self.pc = self.text_segment_mips_base
        self.hi, self.lo = 0, 0
        self.regs[29] = self.stack_mips_top # $sp
        self.heap_pointer_mips = self.data_segment_mips_base # Início do heap MIPS
        self.total_cycles = 0
        self.instruction_counts = {k: 0 for k in self.cpi_values.keys()}
        self.program_instructions_info = {}
        self.running = False
        self.exit_code = 0
        self.waiting_for_gui_input = False
        self.gui_input_type = None
        self.gui_input_reg_target = None
        self.gui_input_buffer_addr = None
        self.gui_input_buffer_len = None
        # Não limpa a memória aqui, load_program fará isso para as seções relevantes

    def _mips_addr_to_mem_offset(self, mips_address):
        if self.text_segment_mips_base <= mips_address < self.text_segment_mips_base + self.text_segment_max_size:
            offset = self.text_segment_array_offset + (mips_address - self.text_segment_mips_base)
            if 0 <= offset < self.text_segment_array_offset + self.text_segment_max_size: return offset
        elif self.data_segment_mips_base <= mips_address < self.data_segment_mips_base + self.data_segment_max_size:
            offset = self.data_segment_array_offset + (mips_address - self.data_segment_mips_base)
            if self.data_segment_array_offset <= offset < self.data_segment_array_offset + self.data_segment_max_size : return offset
        
        # Pilha: mips_address está entre (stack_mips_top - stack_max_size + 4) e stack_mips_top
        stack_mips_bottom = self.stack_mips_top - self.stack_max_size + 4 # Endereço MIPS mais baixo da pilha
        if stack_mips_bottom <= mips_address <= self.stack_mips_top:
            offset_from_mips_stack_top = self.stack_mips_top - mips_address
            array_idx = self.stack_array_end - offset_from_mips_stack_top
            # Garante que o índice está dentro da porção de pilha do array
            stack_array_start = self.memory_array_size - self.stack_max_size
            if stack_array_start <= array_idx <= self.stack_array_end: return array_idx
        
        raise MemoryAccessException(f"Endereço MIPS {mips_address:#0x} fora dos segmentos mapeados.")

    def load_program(self, machine_code_list, data_segment_bytes):
        self.reset_state() # Limpa estado anterior, mas não a memória inteira
        # Limpar as seções de memória que serão usadas
        # Texto:
        ts_array_start = self.text_segment_array_offset
        ts_array_end = ts_array_start + self.text_segment_max_size
        self.memory[ts_array_start:ts_array_end] = bytearray(self.text_segment_max_size)
        # Dados:
        ds_array_start = self.data_segment_array_offset
        ds_array_end = ds_array_start + self.data_segment_max_size
        self.memory[ds_array_start:ds_array_end] = bytearray(self.data_segment_max_size)
        # Pilha (a parte alta da pilha é implicitamente "limpa" ao ser sobrescrita)

        max_text_addr_mips = 0
        for instr_info in machine_code_list:
            addr_mips, code, asm_orig, cpi_type = instr_info['address'], instr_info['machine_code'], instr_info['asm'], instr_info['type']
            self.program_instructions_info[addr_mips] = (code, asm_orig, cpi_type)
            try:
                mem_offset = self._mips_addr_to_mem_offset(addr_mips)
                if mem_offset + 3 >= len(self.memory): raise MemoryAccessException("Escrita de instrução fora dos limites do array.")
                self.memory[mem_offset : mem_offset+4] = code.to_bytes(4, 'big')
                max_text_addr_mips = max(max_text_addr_mips, addr_mips + 3)
            except MemoryAccessException as e: self._log_gui(f"Erro ao carregar instrução em MIPS {addr_mips:#0x}: {e}", True); return False
        if machine_code_list: self._log_gui(f"Texto carregado: {len(machine_code_list)} instruções (MIPS {machine_code_list[0]['address']:#0x} a {max_text_addr_mips:#0x}).")

        if data_segment_bytes:
            try:
                data_start_array_offset = self._mips_addr_to_mem_offset(self.data_segment_mips_base)
                data_len = len(data_segment_bytes)
                if data_start_array_offset + data_len > ds_array_end : # ds_array_end é o fim da seção de dados no array
                    raise MemoryAccessException(f"Segmento de dados (len {data_len}) excede seção de dados do array.")
                self.memory[data_start_array_offset : data_start_array_offset + data_len] = data_segment_bytes
                self.heap_pointer_mips = self.data_segment_mips_base + data_len
                self._log_gui(f"Dados carregados em MIPS {self.data_segment_mips_base:#0x} ({data_len} bytes). Heap MIPS em {self.heap_pointer_mips:#0x}.")
            except MemoryAccessException as e: self._log_gui(f"Erro ao carregar segmento de dados: {e}", True); return False
        
        self.pc = self.text_segment_mips_base
        self.regs[29] = self.stack_mips_top
        self.running = True
        return True

    def _get_reg(self, idx): return 0 if idx == 0 else self.regs[idx]
    def _set_reg(self, idx, val):
        if idx != 0: self.regs[idx] = to_signed_32(val)

    def _read_mem_word(self, mips_address):
        if mips_address % 4 != 0: raise MemoryAccessException(f"Acesso desalinhado (read_word): {mips_address:#0x}")
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset + 3 >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (read_word): MIPS {mips_address:#0x} -> offset {offset}")
        return int.from_bytes(self.memory[offset:offset+4], 'big', signed=True)
    def _write_mem_word(self, mips_address, value):
        if mips_address % 4 != 0: raise MemoryAccessException(f"Acesso desalinhado (write_word): {mips_address:#0x}")
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset + 3 >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (write_word): MIPS {mips_address:#0x} -> offset {offset}")
        self.memory[offset:offset+4] = to_signed_32(value).to_bytes(4, 'big', signed=True)
    def _read_mem_half(self, mips_address, signed=True):
        if mips_address % 2 != 0: raise MemoryAccessException(f"Acesso desalinhado (read_half): {mips_address:#0x}")
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset + 1 >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (read_half): MIPS {mips_address:#0x} -> offset {offset}")
        return int.from_bytes(self.memory[offset:offset+2], 'big', signed=signed)
    def _write_mem_half(self, mips_address, value):
        if mips_address % 2 != 0: raise MemoryAccessException(f"Acesso desalinhado (write_half): {mips_address:#0x}")
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset + 1 >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (write_half): MIPS {mips_address:#0x} -> offset {offset}")
        self.memory[offset:offset+2] = (value & 0xFFFF).to_bytes(2, 'big', signed=False) # signed=False para evitar problemas com to_bytes
    def _read_mem_byte(self, mips_address, signed=True):
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (read_byte): MIPS {mips_address:#0x} -> offset {offset}")
        return int.from_bytes(self.memory[offset:offset+1], 'big', signed=signed)
    def _write_mem_byte(self, mips_address, value):
        offset = self._mips_addr_to_mem_offset(mips_address)
        if offset >= len(self.memory): raise MemoryAccessException(f"Fora dos limites (write_byte): MIPS {mips_address:#0x} -> offset {offset}")
        self.memory[offset:offset+1] = (value & 0xFF).to_bytes(1, 'big', signed=False)

    def _handle_exception(self, message, exception_type=None):
        self._log_gui(message, is_exception=True)
        self.running = False
        # No MIPS real, o tipo de exceção e o PC seriam salvos em registradores do CP0.
        # E o PC pularia para um endereço de handler de exceção.
        # Aqui, apenas paramos.
        if self.gui_hooks and self.gui_hooks.get('simulation_ended'):
            self.gui_hooks['simulation_ended']()


    def fetch(self):
        if not self.running: return None, None, None
        try:
            instr_val = self._read_mem_word(self.pc)
            _, asm, cpi_type = self.program_instructions_info.get(self.pc, (0, f"NOP (PC={self.pc:#0x} não mapeado)", 'Unknown'))
            return instr_val, asm, cpi_type
        except MemoryAccessException as e: self._handle_exception(f"Fetch (PC={self.pc:#0x}): {e}"); return None,None,None
        except Exception as e: self._handle_exception(f"Erro inesperado no Fetch (PC={self.pc:#0x}): {e}"); return None,None,None

    def decode_and_execute(self, instr_val, instr_cpi_type):
        if not self.running: return
        opcode = (instr_val >> 26) & 0x3F; next_pc = self.pc + 4
        
        cpi_cat = instr_cpi_type if instr_cpi_type in self.cpi_values else 'Unknown'
        self.total_cycles += self.cpi_values[cpi_cat]
        self.instruction_counts[cpi_cat] = self.instruction_counts.get(cpi_cat, 0) + 1

        try:
            rs_idx = (instr_val >> 21) & 0x1F; rs_val = self._get_reg(rs_idx)
            rt_idx = (instr_val >> 16) & 0x1F; rt_val = self._get_reg(rt_idx)
            rd_idx = (instr_val >> 11) & 0x1F
            shamt  = (instr_val >> 6) & 0x1F
            funct  = instr_val & 0x3F
            imm16_unsigned = instr_val & 0xFFFF
            imm16_signed   = sign_extend_16_to_32(imm16_unsigned)
            addr_jtype = instr_val & 0x03FFFFFF

            if opcode == 0x00: # R-Type
                if funct == 0x20: # ADD
                    res = rs_val + rt_val
                    if (rs_val > 0 and rt_val > 0 and to_signed_32(res) < 0) or \
                    (rs_val < 0 and rt_val < 0 and to_signed_32(res) > 0): raise ArithmeticOverflow("ADD")
                    self._set_reg(rd_idx, res)
                elif funct == 0x21: self._set_reg(rd_idx, rs_val + rt_val) # ADDU
                elif funct == 0x22: # SUB
                    res = rs_val - rt_val
                    if (rs_val > 0 and rt_val < 0 and to_signed_32(res) < 0) or \
                    (rs_val < 0 and rt_val > 0 and to_signed_32(res) > 0): raise ArithmeticOverflow("SUB")
                    self._set_reg(rd_idx, res)
                elif funct == 0x23: self._set_reg(rd_idx, rs_val - rt_val) # SUBU
                elif funct == 0x24: self._set_reg(rd_idx, rs_val & rt_val) # AND
                elif funct == 0x25: self._set_reg(rd_idx, rs_val | rt_val) # OR
                elif funct == 0x26: self._set_reg(rd_idx, rs_val ^ rt_val) # XOR
                elif funct == 0x27: self._set_reg(rd_idx, ~(rs_val | rt_val))# NOR
                elif funct == 0x2A: self._set_reg(rd_idx, 1 if rs_val < rt_val else 0) # SLT
                elif funct == 0x2B: self._set_reg(rd_idx, 1 if to_unsigned_32(rs_val) < to_unsigned_32(rt_val) else 0) # SLTU
                elif funct == 0x00: self._set_reg(rd_idx, rt_val << shamt) # SLL
                elif funct == 0x02: self._set_reg(rd_idx, to_unsigned_32(rt_val) >> shamt) # SRL
                elif funct == 0x03: self._set_reg(rd_idx, rt_val >> shamt) # SRA
                elif funct == 0x04: self._set_reg(rd_idx, rt_val << (rs_val & 0x1F)) # SLLV
                elif funct == 0x06: self._set_reg(rd_idx, to_unsigned_32(rt_val) >> (rs_val & 0x1F)) # SRLV
                elif funct == 0x07: self._set_reg(rd_idx, rt_val >> (rs_val & 0x1F)) # SRAV
                elif funct == 0x08: next_pc = rs_val # JR
                elif funct == 0x09: self._set_reg(rd_idx if rd_idx!=0 else 31, self.pc + 4); next_pc = rs_val # JALR
                elif funct == 0x10: self._set_reg(rd_idx, self.hi) # MFHI
                elif funct == 0x11: self.hi = rs_val # MTHI
                elif funct == 0x12: self._set_reg(rd_idx, self.lo) # MFLO
                elif funct == 0x13: self.lo = rs_val # MTLO
                elif funct == 0x18: res=rs_val * rt_val; self.hi=to_signed_32((res>>32)&0xFFFFFFFF); self.lo=to_signed_32(res&0xFFFFFFFF) # MULT
                elif funct == 0x19: res=to_unsigned_32(rs_val)*to_unsigned_32(rt_val); self.hi=(res>>32)&0xFFFFFFFF; self.lo=res&0xFFFFFFFF # MULTU
                elif funct == 0x1A: # DIV
                    if rt_val == 0: self._handle_exception("Divisão por zero (DIV)"); return
                    self.lo = to_signed_32(rs_val // rt_val); self.hi = to_signed_32(rs_val % rt_val)
                elif funct == 0x1B: # DIVU
                    if rt_val == 0: self._handle_exception("Divisão por zero (DIVU)"); return
                    self.lo = to_unsigned_32(to_unsigned_32(rs_val)//to_unsigned_32(rt_val)); self.hi = to_unsigned_32(to_unsigned_32(rs_val)%to_unsigned_32(rt_val))
                elif funct == 0x0C: # SYSCALL
                    if not self.handle_syscall(): self.running = False
                elif funct == 0x0D: self._handle_exception("BREAK instruction encountered") # BREAK
                else: self._handle_exception(f"Funct R-Type {funct:#04x} inválido", InvalidInstruction)
            elif opcode == 0x08: # ADDI
                res = rs_val + imm16_signed
                if (rs_val > 0 and imm16_signed > 0 and to_signed_32(res) < 0) or \
                (rs_val < 0 and imm16_signed < 0 and to_signed_32(res) > 0): raise ArithmeticOverflow("ADDI")
                self._set_reg(rt_idx, res)
            elif opcode == 0x09: self._set_reg(rt_idx, rs_val + imm16_signed) # ADDIU
            elif opcode == 0x0C: self._set_reg(rt_idx, rs_val & imm16_unsigned) # ANDI
            elif opcode == 0x0D: self._set_reg(rt_idx, rs_val | imm16_unsigned) # ORI
            elif opcode == 0x0E: self._set_reg(rt_idx, rs_val ^ imm16_unsigned) # XORI
            elif opcode == 0x0A: self._set_reg(rt_idx, 1 if rs_val < imm16_signed else 0) # SLTI
            elif opcode == 0x0B: self._set_reg(rt_idx, 1 if to_unsigned_32(rs_val) < to_unsigned_32(imm16_signed) else 0) # SLTIU (imm is sign-extended)
            elif opcode == 0x0F: self._set_reg(rt_idx, imm16_unsigned << 16) # LUI
            elif opcode == 0x23: self._set_reg(rt_idx, self._read_mem_word(rs_val + imm16_signed)) # LW
            elif opcode == 0x2B: self._write_mem_word(rs_val + imm16_signed, rt_val) # SW
            elif opcode == 0x20: self._set_reg(rt_idx, self._read_mem_byte(rs_val + imm16_signed, signed=True)) # LB
            elif opcode == 0x24: self._set_reg(rt_idx, self._read_mem_byte(rs_val + imm16_signed, signed=False))# LBU
            elif opcode == 0x21: self._set_reg(rt_idx, self._read_mem_half(rs_val + imm16_signed, signed=True)) # LH
            elif opcode == 0x25: self._set_reg(rt_idx, self._read_mem_half(rs_val + imm16_signed, signed=False))# LHU
            elif opcode == 0x28: self._write_mem_byte(rs_val + imm16_signed, rt_val) # SB
            elif opcode == 0x29: self._write_mem_half(rs_val + imm16_signed, rt_val) # SH
            elif opcode == 0x04: # BEQ
                if rs_val == rt_val: next_pc = self.pc + 4 + (imm16_signed << 2)
            elif opcode == 0x05: # BNE
                if rs_val != rt_val: next_pc = self.pc + 4 + (imm16_signed << 2)
            elif opcode == 0x06: # BLEZ (rt must be 0)
                if rs_val <= 0: next_pc = self.pc + 4 + (imm16_signed << 2)
            elif opcode == 0x07: # BGTZ (rt must be 0)
                if rs_val > 0: next_pc = self.pc + 4 + (imm16_signed << 2)
            elif opcode == 0x02: next_pc = ((self.pc + 4) & 0xF0000000) | (addr_jtype << 2) # J
            elif opcode == 0x03: self._set_reg(31, self.pc + 4); next_pc = ((self.pc+4) & 0xF0000000) | (addr_jtype << 2) # JAL
            else: self._handle_exception(f"Opcode {opcode:#04x} inválido", InvalidInstruction)
            self.pc = next_pc
        except MemoryAccessException as e: self._handle_exception(f"Memória (PC={self.pc:#0x}, Instr={instr_val:#010x}): {e}")
        except ArithmeticOverflow as e: self._handle_exception(f"Aritmética (PC={self.pc:#0x}, Instr={instr_val:#010x}): Overflow em {e}")
        except InvalidInstruction as e: self._handle_exception(f"Instrução (PC={self.pc:#0x}, Instr={instr_val:#010x}): {e}")
        except Exception as e: self._handle_exception(f"Inesperado (PC={self.pc:#0x}, Instr={instr_val:#010x}): {e}"); import traceback; traceback.print_exc()

    def handle_syscall(self): # Retorna False se SYSCALL_EXIT ou erro grave
        code = self._get_reg(2) # $v0
        if self.gui_hooks and self.gui_hooks.get('log_message'): self.gui_hooks['log_message'](f"SYSCALL: code={code} $a0={self._get_reg(4)} $a1={self._get_reg(5)}")

        if code == SYSCALL_PRINT_INT:
            if self.gui_hooks and self.gui_hooks.get('print_int'): self.gui_hooks['print_int'](self._get_reg(4))
            else: print(self._get_reg(4), end='')
        elif code == SYSCALL_PRINT_STRING:
            addr, s = self._get_reg(4), ""
            try:
                char = self._read_mem_byte(addr, signed=False)
                while char != 0: s += chr(char); addr += 1; char = self._read_mem_byte(addr, signed=False)
                if self.gui_hooks and self.gui_hooks.get('print_string'): self.gui_hooks['print_string'](s)
                else: print(s, end='')
            except MemoryAccessException as e: self._handle_exception(f"SYSCALL print_string: {e}"); return False
        elif code == SYSCALL_PRINT_CHAR:
            char_val = self._get_reg(4) & 0xFF
            if self.gui_hooks and self.gui_hooks.get('print_char'): self.gui_hooks['print_char'](chr(char_val))
            else: print(chr(char_val), end='')
        elif code == SYSCALL_READ_INT:
            if self.gui_hooks and self.gui_hooks.get('read_int_async'):
                self.waiting_for_gui_input = True; self.gui_input_type = 'int'; self.gui_input_reg_target = 2
                self.gui_hooks['read_int_async'](); return True # Pausa execução
            else: # Fallback console
                try: self._set_reg(2, int(input("IN(int): ")))
                except ValueError: self._handle_exception("Entrada inválida para read_int."); return False
        elif code == SYSCALL_READ_CHAR:
            if self.gui_hooks and self.gui_hooks.get('read_char_async'):
                self.waiting_for_gui_input = True; self.gui_input_type = 'char'; self.gui_input_reg_target = 2
                self.gui_hooks['read_char_async'](); return True
            else:
                val_str = input("IN(char): "); self._set_reg(2, ord(val_str[0]) if val_str else 0)
        elif code == SYSCALL_READ_STRING:
            buf_addr, max_len = self._get_reg(4), self._get_reg(5)
            if self.gui_hooks and self.gui_hooks.get('read_string_async'):
                self.waiting_for_gui_input = True; self.gui_input_type = 'string'
                self.gui_input_buffer_addr = buf_addr; self.gui_input_buffer_len = max_len
                self.gui_hooks['read_string_async'](max_len); return True
            else:
                s_in = input(f"IN(str, max {max_len-1}): ")[:max_len-1]
                try:
                    for i, char_write in enumerate(s_in): self._write_mem_byte(buf_addr + i, ord(char_write))
                    self._write_mem_byte(buf_addr + len(s_in), 0) # Null terminator
                except MemoryAccessException as e: self._handle_exception(f"SYSCALL read_string: {e}"); return False
        elif code == SYSCALL_SBRK:
            amount = self._get_reg(4)
            current_brk = self.heap_pointer_mips
            new_brk = current_brk + amount
            # Validação básica do heap (não deve exceder a seção de dados/heap nem colidir com a pilha MIPS)
            data_segment_mips_end = self.data_segment_mips_base + self.data_segment_max_size
            if new_brk < self.data_segment_mips_base or new_brk >= data_segment_mips_end or new_brk >= self.stack_mips_top - self.stack_max_size:
                self._handle_exception(f"SBRK: Alocação inválida. new_brk={new_brk:#0x} fora dos limites.")
                self._set_reg(2, current_brk) # Ou um código de erro como -1, mas $v0 é para endereço
            else:
                self._set_reg(2, current_brk) # Retorna o valor antigo de $v0
                self.heap_pointer_mips = new_brk
        elif code == SYSCALL_EXIT: self.exit_code = 0; self._log_gui("SYSCALL EXIT"); return False
        elif code == SYSCALL_EXIT2: self.exit_code = self._get_reg(4); self._log_gui(f"SYSCALL EXIT2 code={self.exit_code}"); return False
        else: self._handle_exception(f"Syscall {code} desconhecido."); return False
        return True

    def provide_gui_input(self, value_str):
        if not self.waiting_for_gui_input: return
        self.waiting_for_gui_input = False
        try:
            if self.gui_input_type == 'int': self._set_reg(self.gui_input_reg_target, int(value_str))
            elif self.gui_input_type == 'char': self._set_reg(self.gui_input_reg_target, ord(value_str[0]) if value_str else 0)
            elif self.gui_input_type == 'string':
                s_in = value_str[:self.gui_input_buffer_len-1]
                for i, char_w in enumerate(s_in): self._write_mem_byte(self.gui_input_buffer_addr + i, ord(char_w))
                self._write_mem_byte(self.gui_input_buffer_addr + len(s_in), 0)
            if self.gui_hooks and self.gui_hooks.get('input_provided_resume_simulation'):
                self.gui_hooks['input_provided_resume_simulation']()
        except (ValueError, TypeError) as e: self._handle_exception(f"Erro ao processar entrada da GUI ({self.gui_input_type}): {e}")
        except MemoryAccessException as e: self._handle_exception(f"Erro de memória ao escrever entrada da GUI (string): {e}")
        self.gui_input_type = None

    def run_step(self):
        if not self.running or self.waiting_for_gui_input: return self.running
        instr_val, asm, cpi_type = self.fetch()
        if instr_val is None or not self.running:
            if self.running: self._log_gui("Fetch falhou ou fim inesperado.") # Se running era True mas fetch falhou
            self.running = False
            if self.gui_hooks and self.gui_hooks.get('simulation_ended'): self.gui_hooks['simulation_ended']()
            return False
        
        if self.gui_hooks and self.gui_hooks.get('update_display_before_execute'):
             self.gui_hooks['update_display_before_execute'](self.pc, instr_val, asm)
        
        self.decode_and_execute(instr_val, cpi_type)
        
        if self.gui_hooks and self.gui_hooks.get('update_display_after_execute'):
            self.gui_hooks['update_display_after_execute']()
        
        if not self.running and self.gui_hooks and self.gui_hooks.get('simulation_ended'):
            self.gui_hooks['simulation_ended']()
        return self.running

    def get_state_for_gui(self):
        regs_named = {get_reg_name(i): self._get_reg(i) for i in range(32)}
        return {"pc": self.pc, "hi": self.hi, "lo": self.lo,
                "registers_by_num": list(self.regs), "registers_by_name": regs_named,
                "total_cycles": self.total_cycles, "instruction_counts": dict(self.instruction_counts),
                "running": self.running, "waiting_for_input": self.waiting_for_gui_input,
                "exit_code": self.exit_code if not self.running else None}

    def get_memory_word_for_gui(self, mips_address):
        try:
            if mips_address % 4 != 0: return "AlignErr"
            # Não precisa chamar _mips_addr_to_mem_offset aqui, _read_mem_word faz isso
            return self._read_mem_word(mips_address)
        except MemoryAccessException: return "AddrErr" # Erro de mapeamento ou bounds
        except Exception: return "UnknownErr"