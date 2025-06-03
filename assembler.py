# assembler.py
import re
from utils import (REGISTER_MAP, INSTRUCTION_FORMATS, PSEUDO_INSTRUCTIONS,
                get_reg_num, assemble_r_type, assemble_i_type, assemble_j_type,
            TEXT_SEGMENT_START, DATA_SEGMENT_START, _expand_li, _expand_la)

class Assembler:
    def __init__(self, text_base_address=TEXT_SEGMENT_START, data_base_address=DATA_SEGMENT_START, logger_func=None):
        self.text_base_address = text_base_address
        self.data_base_address = data_base_address
        self.symbol_table = {}
        self.data_labels = {}
        self.intermediate_code = []
        self.machine_code_output = []
        self.current_data_address_offset = 0
        self.data_segment_bytes = bytearray()
        # Se logger_func não for passado, usa print com um prefixo para distinguir
        self.logger = logger_func if logger_func else lambda msg: print(f"[ASM_LOG_FALLBACK] {msg.strip()}")


    def _log(self, message):
        # Garante que a mensagem termine com newline para o logger da GUI ou console
        if not message.endswith('\n'):
            message += '\n'
        if callable(self.logger):
            self.logger(message)
        else:
            print(message) # Fallback


    def _parse_operand(self, operand_str, current_instr_addr=0, is_branch_label=False, is_j_label=False, is_data_label_ref=False):
        operand_str = str(operand_str).strip() # Garante que é string e limpa espaços
        if not operand_str: # Se o operando ficou vazio após o strip
            raise ValueError("Operando vazio encontrado.")

        if operand_str.lower() in REGISTER_MAP:
            return get_reg_num(operand_str)
        
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", operand_str): # Potencial label
            if is_data_label_ref and operand_str in self.data_labels:
                return self.data_labels[operand_str]
            if (is_branch_label or is_j_label) and operand_str in self.symbol_table:
                return self.symbol_table[operand_str]
            return operand_str 
            
        try:
            if operand_str.lower().startswith("0x"):
                return int(operand_str, 16)
            return int(operand_str) # Decimal
        except ValueError:
            # Formato offset(base_reg) para lw/sw
            match_mem = re.match(r"(-?\d+|-?0x[0-9a-fA-F]+)\s*\(\s*(\$\w+|\$?\d+)\s*\)", operand_str, re.IGNORECASE)
            if match_mem:
                offset_str = match_mem.group(1)
                base_reg_str = match_mem.group(2)
                offset = int(offset_str, 16) if offset_str.lower().startswith("0x") else int(offset_str)
                base_reg = get_reg_num(base_reg_str)
                if base_reg is None:
                    raise ValueError(f"Registrador base inválido: '{base_reg_str}' em '{operand_str}'")
                return offset, base_reg # Retorna tupla (offset, base_reg_num)
            raise ValueError(f"Operando inválido ou não reconhecido: '{operand_str}'")

    def _process_directive_data(self, directive, values_str, line_num):
        if directive == ".word":
            for val_str in re.split(r'[,\s]\s*', values_str.strip()):
                if not val_str: continue
                val_or_label = self._parse_operand(val_str, is_data_label_ref=True)
                val = 0
                if isinstance(val_or_label, str):
                    if val_or_label in self.data_labels: val = self.data_labels[val_or_label]
                    elif val_or_label in self.symbol_table: val = self.symbol_table[val_or_label]
                    else: raise ValueError(f"Label '{val_or_label}' não definida para .word na linha {line_num+1}")
                else: val = val_or_label
                self.data_segment_bytes.extend(val.to_bytes(4, 'big', signed=True))
                self.current_data_address_offset += 4
        elif directive == ".asciiz":
            # Regex aprimorado para lidar com strings contendo '#' se não forem comentários
            match = re.match(r'"((?:[^"\\]|\\.)*)"', values_str.strip()) 
            if not match: raise ValueError(f"String mal formada em .asciiz na linha {line_num+1}: '{values_str}'")
            string_data = match.group(1).encode('latin-1', 'backslashreplace').decode('unicode_escape')
            self.data_segment_bytes.extend(string_data.encode('utf-8'))
            self.data_segment_bytes.append(0)
            self.current_data_address_offset += len(string_data) + 1
        elif directive == ".byte":
            for val_str in re.split(r'[,\s]\s*', values_str.strip()):
                if not val_str: continue
                val = self._parse_operand(val_str)
                if not isinstance(val, int) or not (-128 <= val <= 255):
                    raise ValueError(f"Valor '{val_str}' inválido para .byte na linha {line_num+1}")
                self.data_segment_bytes.extend(val.to_bytes(1, 'big', signed=True))
                self.current_data_address_offset += 1
        elif directive == ".space":
            size = self._parse_operand(values_str.strip())
            if not isinstance(size, int) or size < 0: raise ValueError(f"Tamanho inválido para .space na linha {line_num+1}")
            self.data_segment_bytes.extend(bytearray(size))
            self.current_data_address_offset += size
        elif directive == ".align":
            align_val = self._parse_operand(values_str.strip())
            if not isinstance(align_val, int) or align_val < 0: raise ValueError(f"Valor de alinhamento inválido para .align na linha {line_num+1}")
            align_bytes = 1 << align_val
            padding = (align_bytes - (self.current_data_address_offset % align_bytes)) % align_bytes
            self.data_segment_bytes.extend(bytearray(padding))
            self.current_data_address_offset += padding
        else:
            self._log(f"Aviso: Diretiva de dados '{directive}' não suportada (linha {line_num+1}). Ignorando.")

    def first_pass(self, all_lines):
        self.symbol_table.clear(); self.data_labels.clear(); self.intermediate_code.clear()
        self.data_segment_bytes = bytearray(); self.current_data_address_offset = 0
        
        current_segment = ".text"; temp_text_lines_with_labels = []
        pre_scan_data_labels = {}; tentative_data_offset = 0

        # Pass 1a: Pré-scan para encontrar todas as labels de DADOS e calcular seus tamanhos/offsets
        active_segment_for_prescan = ".text" # Para saber em qual segmento estamos no pré-scan
        for line_num, original_line in enumerate(all_lines):
            line = original_line.strip()
            # Remover comentário da linha inteira primeiro para o pré-scan
            processed_line_for_prescan = line.split('#', 1)[0].strip()
            if not processed_line_for_prescan: continue

            if processed_line_for_prescan.lower() == ".data": active_segment_for_prescan = ".data"; continue
            elif processed_line_for_prescan.lower() == ".text": active_segment_for_prescan = ".text"; continue
            
            if active_segment_for_prescan == ".data":
                label_part, content_part = None, processed_line_for_prescan
                if ":" in processed_line_for_prescan:
                    label_part, content_part = processed_line_for_prescan.split(":", 1)
                    label_part = label_part.strip()
                content_part = content_part.strip()
                
                if label_part:
                    if label_part in pre_scan_data_labels: raise ValueError(f"Label de dados '{label_part}' redefinida (linha {line_num+1}).")
                    pre_scan_data_labels[label_part] = self.data_base_address + tentative_data_offset
                
                if content_part:
                    parts = re.split(r'\s+', content_part, 1)
                    directive, values_str = parts[0].lower(), parts[1] if len(parts) > 1 else ""
                    try:
                        if directive == ".word": tentative_data_offset += len([v for v in re.split(r'[,\s]\s*', values_str.strip()) if v]) * 4
                        elif directive == ".asciiz":
                            m = re.match(r'"((?:[^"\\]|\\.)*)"', values_str.strip())
                            if not m: raise ValueError(f"String .asciiz mal formada para cálculo de tamanho (linha {line_num+1})")
                            tentative_data_offset += len(m.group(1).encode('latin-1','backslashreplace').decode('unicode_escape')) + 1
                        elif directive == ".byte": tentative_data_offset += len([v for v in re.split(r'[,\s]\s*', values_str.strip()) if v]) * 1
                        elif directive == ".space": tentative_data_offset += self._parse_operand(values_str.strip())
                        elif directive == ".align":
                            ab = 1 << self._parse_operand(values_str.strip())
                            tentative_data_offset += (ab - (tentative_data_offset % ab)) % ab
                    except Exception as e: raise ValueError(f"Erro ao calcular tamanho para diretiva '{directive}' na linha {line_num+1}: {e}")
        self.data_labels = pre_scan_data_labels
        current_segment = ".text"

        # Pass 1b: Processar de verdade, preenchendo data_segment_bytes e coletando linhas de texto
        for line_num, original_line in enumerate(all_lines):
            line_content_no_comment = original_line.split('#', 1)[0].strip()
            if not line_content_no_comment: continue

            if line_content_no_comment.lower() == ".data": current_segment = ".data"; continue
            elif line_content_no_comment.lower() == ".text": current_segment = ".text"; continue
            
            first_word = line_content_no_comment.split(maxsplit=1)[0].lower()
            ignored_directives = [".globl", ".global", ".extern", ".ent", ".end", ".set", ".ktext", ".kdata", ".frame", ".mask", ".fmask", ".gpword"]
            if first_word in ignored_directives or (first_word == ".align" and current_segment == ".text"):
                self._log(f"Info: Diretiva '{first_word}' na linha {line_num+1} ignorada.")
                continue
            
            label, content_after_label = None, line_content_no_comment
            if ":" in line_content_no_comment:
                label_part, content_after_label = line_content_no_comment.split(":", 1)
                label = label_part.strip()
            content_after_label = content_after_label.strip()
            
            if current_segment == ".data":
                if content_after_label:
                    parts = re.split(r'\s+', content_after_label, 1)
                    directive, values_str = parts[0].lower(), parts[1] if len(parts) > 1 else ""
                    self._process_directive_data(directive, values_str, line_num) # Preenche data_segment_bytes
            elif current_segment == ".text":
                if content_after_label:
                    # Regex para mnemônico e o resto (operandos)
                    match_instr = re.match(r"([a-zA-Z.]+)\s*(.*)", content_after_label)
                    if not match_instr:
                        if label and not content_after_label: # Linha só com label já tratada
                            temp_text_lines_with_labels.append((label, None, [], original_line, line_num))
                            continue
                        self._log(f"Aviso: Linha de texto mal formatada ou vazia após label/comentário na linha {line_num+1}: '{original_line.strip()}'")
                        continue
                    
                    mnemonic = match_instr.group(1).lower()
                    operands_str_part = match_instr.group(2).strip()
                    raw_operands = [op.strip() for op in operands_str_part.split(',') if op.strip()] if operands_str_part else []
                    temp_text_lines_with_labels.append((label, mnemonic, raw_operands, original_line, line_num))
                elif label: # Linha só com label (sem instrução)
                    temp_text_lines_with_labels.append((label, None, [], original_line, line_num))

        # Pass 1c: Expandir pseudo-instruções e calcular endereços de labels de CÓDIGO
        processed_lines_for_addr_calc = []
        for label_str, mnemonic, raw_ops, original_line, line_n in temp_text_lines_with_labels:
            if label_str and mnemonic is None: processed_lines_for_addr_calc.append((label_str, None, [], original_line)); continue
            if mnemonic is None: continue

            if mnemonic in PSEUDO_INSTRUCTIONS:
                expander_func = PSEUDO_INSTRUCTIONS[mnemonic]
                parsed_ops_for_pseudo = [] # Estes são os operandos *para a função de expansão*
                if mnemonic == 'la':
                    if len(raw_ops) != 2: raise ValueError(f"Pseudo 'la' espera 2 operandos, recebeu {raw_ops} na L{line_n+1}")
                    parsed_ops_for_pseudo = [raw_ops[0], raw_ops[1]] # rt_str, label_name_str
                elif mnemonic == 'li':
                    if len(raw_ops) != 2: raise ValueError(f"Pseudo 'li' espera 2 operandos, recebeu {raw_ops} na L{line_n+1}")
                    rt_str, val_str = raw_ops[0], raw_ops[1]
                    imm_val = self.data_labels.get(val_str, self.symbol_table.get(val_str))
                    if imm_val is None:
                        try: imm_val = self._parse_operand(val_str)
                        except ValueError: raise ValueError(f"Valor/Label '{val_str}' inválido para 'li' na L{line_n+1} (original: {original_line.strip()})")
                    parsed_ops_for_pseudo = [rt_str, imm_val] # rt_str, imm_numeric_value
                else: parsed_ops_for_pseudo = raw_ops 
                
                try: expanded_instrs = expander_func(parsed_ops_for_pseudo)
                except Exception as e: raise ValueError(f"Erro expandindo '{mnemonic}' (ops:{parsed_ops_for_pseudo}) L{line_n+1} ({original_line.strip()}): {e}")
                
                first = True
                for exp_mne, exp_ops in expanded_instrs:
                    lab = label_str if first else None; first = False
                    processed_lines_for_addr_calc.append((lab, exp_mne, [str(op) for op in exp_ops], f"  ; expanded from: {original_line.strip()}"))
            else:
                processed_lines_for_addr_calc.append((label_str, mnemonic, raw_ops, original_line))

        current_text_address = self.text_base_address
        self.intermediate_code = [] # Limpar antes de preencher
        for label_str, mnemonic, ops_list, original_line_text in processed_lines_for_addr_calc:
            if label_str:
                if label_str in self.symbol_table: raise ValueError(f"Label de código '{label_str}' redefinida.")
                self.symbol_table[label_str] = current_text_address
            if mnemonic:
                self.intermediate_code.append({
                    "address": current_text_address, "mnemonic": mnemonic,
                    "operands_str_list": ops_list, "original_asm": original_line_text.strip(),
                })
                current_text_address += 4
    
    def second_pass(self):
        self.machine_code_output = []
        for inter_instr in self.intermediate_code:
            addr, mne, ops_s_list, orig_asm = inter_instr["address"], inter_instr["mnemonic"], inter_instr["operands_str_list"], inter_instr["original_asm"]
            
            if mne not in INSTRUCTION_FORMATS:
                if mne.startswith("."): self._log(f"Aviso (2nd pass): Diretiva '{mne}' inesperada. Ignorando. ({orig_asm})"); continue
                raise ValueError(f"Instrução '{mne}' desconhecida em {addr:#0x} ({orig_asm})")

            opcode, funct, instr_cat, _ = INSTRUCTION_FORMATS[mne] # Ignoramos operand_format_expected por enquanto
            mc, rs, rt, rd, shamt, imm = 0,0,0,0,0,0
            
            try: # Bloco try para erros de parsing de operandos
                if mne == "lui": 
                    rt = self._parse_operand(ops_s_list[0])
                    op1_str = ops_s_list[1] 
                    if op1_str.startswith("%hi("):
                        lab, t_addr = op1_str[4:-1], None
                        t_addr = self.data_labels.get(lab, self.symbol_table.get(lab))
                        if t_addr is None: raise ValueError(f"Label '{lab}' não achada para %hi LUI")
                        imm = (t_addr >> 16) & 0xFFFF
                    else: imm = self._parse_operand(op1_str) & 0xFFFF # Espera número
                    mc = assemble_i_type(opcode, 0, rt, imm) 
                elif mne == "ori" and len(ops_s_list)==3 and ops_s_list[2].startswith("%lo("):
                    rt, rs = self._parse_operand(ops_s_list[0]), self._parse_operand(ops_s_list[1])
                    lab, t_addr = ops_s_list[2][4:-1], None
                    t_addr = self.data_labels.get(lab, self.symbol_table.get(lab))
                    if t_addr is None: raise ValueError(f"Label '{lab}' não achada para %lo ORI")
                    imm = t_addr & 0xFFFF
                    mc = assemble_i_type(opcode, rs, rt, imm)
                elif instr_cat == 'R':
                    # A ordem dos operandos é crucial e varia. ops_s_list é [op1_str, op2_str, ...]
                    if mne in ["sll","srl","sra"]: rd,rt,shamt = self._parse_operand(ops_s_list[0]),self._parse_operand(ops_s_list[1]),self._parse_operand(ops_s_list[2])
                    elif mne == "jr": rs = self._parse_operand(ops_s_list[0])
                    elif mne == "jalr": rd,rs = (31, self._parse_operand(ops_s_list[0])) if len(ops_s_list)==1 else (self._parse_operand(ops_s_list[0]), self._parse_operand(ops_s_list[1]))
                    elif mne in ["mfhi","mflo"]: rd = self._parse_operand(ops_s_list[0])
                    elif mne in ["mthi","mtlo"]: rs = self._parse_operand(ops_s_list[0])
                    elif mne in ["mult","multu","div","divu"]: rs,rt = self._parse_operand(ops_s_list[0]),self._parse_operand(ops_s_list[1])
                    elif mne in ["sllv","srlv","srav"]: rd,rt,rs = self._parse_operand(ops_s_list[0]),self._parse_operand(ops_s_list[1]),self._parse_operand(ops_s_list[2])
                    else: rd,rs,rt = self._parse_operand(ops_s_list[0]),self._parse_operand(ops_s_list[1]),self._parse_operand(ops_s_list[2])
                    mc = assemble_r_type(opcode,rs,rt,rd,shamt,funct)
                elif instr_cat in ['I', 'LoadStore', 'Branch']:
                    if instr_cat == 'LoadStore': # rt, offset(base)
                        rt = self._parse_operand(ops_s_list[0])
                        off_base = self._parse_operand(ops_s_list[1]) 
                        if not isinstance(off_base, tuple): raise ValueError(f"Formato inválido para Load/Store: '{ops_s_list[1]}'")
                        imm, rs = off_base[0], off_base[1]
                    elif instr_cat == 'Branch': 
                        rs = self._parse_operand(ops_s_list[0])
                        lab_idx = 1; rt = 0 
                        if mne not in ["blez","bgtz"]: rt, lab_idx = self._parse_operand(ops_s_list[1]), 2
                        lab_s = ops_s_list[lab_idx]
                        t_addr = self.symbol_table.get(lab_s)
                        if t_addr is None: raise ValueError(f"Label '{lab_s}' não definida para branch")
                        imm = ((t_addr - (addr + 4)) // 4) & 0xFFFF
                    else: # Generic I-type: rt, rs, imm_str
                        rt, rs = self._parse_operand(ops_s_list[0]), self._parse_operand(ops_s_list[1])
                        imm_s = ops_s_list[2]
                        # O imediato já deve ser um número (como string) das expansões de 'li' ou direto do asm.
                        # Se for label de dados, já foi resolvido por 'li' ou não é suportado por addi direto.
                        imm = self._parse_operand(imm_s)
                    mc = assemble_i_type(opcode,rs,rt,imm)
                elif instr_cat == 'J':
                    lab_s = ops_s_list[0]
                    t_addr = self.symbol_table.get(lab_s)
                    if t_addr is None: raise ValueError(f"Label '{lab_s}' não definida para jump")
                    mc = assemble_j_type(opcode, (t_addr >> 2) & 0x03FFFFFF)
                elif instr_cat == 'Syscall': mc = assemble_r_type(opcode,0,0,0,0,funct)
                else: raise ValueError(f"Lógica de montagem não implementada para {mne}")
            except ValueError as e_parse: raise ValueError(f"Erro ao processar operandos para '{mne}' em '{orig_asm}': {e_parse}")
            except Exception as e_gen: raise Exception(f"Erro genérico ao processar '{mne}' em '{orig_asm}': {e_gen}")

            self.machine_code_output.append({"address":addr, "machine_code":mc, "asm":orig_asm, "type":self._get_instr_type_for_cpi(mne)})

    def _get_instr_type_for_cpi(self, mne):
        if mne not in INSTRUCTION_FORMATS: return 'Unknown'
        cat = INSTRUCTION_FORMATS[mne][2] # Categoria base (R, I, J, LoadStore, Branch, Syscall)
        # Mapear para as categorias de CPI que o simulador espera
        if cat in ['R', 'I', 'J', 'LoadStore', 'Branch', 'Syscall']: return cat
        return 'Unknown' # Fallback

    def assemble(self, filepath_or_lines):
        try:
            lines = []
            if isinstance(filepath_or_lines, str):
                with open(filepath_or_lines, 'r', encoding='utf-8') as f: lines = f.readlines()
            elif isinstance(filepath_or_lines, list): lines = filepath_or_lines
            else: raise TypeError("Entrada para assemble deve ser caminho de arquivo ou lista de strings.")
            
            self.first_pass(lines) # Pode levantar ValueError
            self.second_pass()     # Pode levantar ValueError
        except FileNotFoundError: self._log(f"Erro: Arquivo '{filepath_or_lines}' não encontrado."); return None,None,None,None
        except OSError as e: self._log(f"Erro OS ao abrir '{filepath_or_lines}': {e}"); return None,None,None,None
        except ValueError as e: self._log(f"Erro de Montagem: {e}"); return None,None,None,None # Erros de parsing/lógica
        except Exception as e: self._log(f"Erro inesperado na montagem: {e}"); import traceback; traceback.print_exc(); return None,None,None,None
        return self.machine_code_output, self.data_segment_bytes, self.symbol_table, self.data_labels