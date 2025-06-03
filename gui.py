# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, simpledialog, messagebox
# import threading # Threading para 'run_all' pode ser complexo com Tkinter, 'after' é mais seguro

from utils import get_reg_name, TEXT_SEGMENT_START, DATA_SEGMENT_START, STACK_POINTER_INITIAL
from assembler import Assembler
from mips_simulator import MipsSimulator

class MipsGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simulador MIPS Avançado")
        self.geometry("1250x850")

        self.assembler = Assembler(logger_func=self.gui_log_message_assembler)
        
        gui_hooks = {
            'print_int': self.gui_print_int, 'print_string': self.gui_print_string,
            'print_char': self.gui_print_char, 'read_int_async': self.gui_read_int_start,
            'read_char_async': self.gui_read_char_start, 'read_string_async': self.gui_read_string_start,
            'log_message': self.gui_log_message, # Para logs do simulador e GUI
            'update_display_before_execute': self.update_displays_before_execute,
            'update_display_after_execute': self.update_displays_after_execute,
            'input_provided_resume_simulation': self.resume_simulation_after_input,
            'program_terminated': self.handle_program_termination,
            'simulation_ended': self.handle_simulation_end
        }
        self.simulator = MipsSimulator(gui_hooks=gui_hooks) # Clock e CPI serão configurados depois

        self.current_asm_file = None
        self.program_loaded = False
        self._running_all_active = False # Flag para controlar o loop de "Rodar Tudo"

        self._create_widgets()
        self.update_all_displays() 

    def gui_log_message_assembler(self, msg):
        self.gui_log_message(f"[ASM] {msg.strip()}") # gui_log_message adiciona \n

    def _create_widgets(self):
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        left_pane = ttk.PanedWindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(left_pane, weight=2) # Mais espaço para código e I/O
        right_pane = ttk.Frame(main_pane)
        main_pane.add(right_pane, weight=3) # Mais espaço para regs e memória

        # Left Pane
        code_frame = ttk.LabelFrame(left_pane, text="Editor Assembly")
        self.code_text = scrolledtext.ScrolledText(code_frame, wrap=tk.WORD, height=20, undo=True) # Undo habilitado
        self.code_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Adicionar save button para o editor
        save_btn_frame = ttk.Frame(code_frame)
        save_btn_frame.pack(fill=tk.X, padx=5)
        ttk.Button(save_btn_frame, text="Salvar Alterações", command=self.save_asm_changes).pack(side=tk.RIGHT, pady=2)

        left_pane.add(code_frame, weight=3)

        controls_frame = ttk.LabelFrame(left_pane, text="Controles de Simulação")
        self.btn_load = ttk.Button(controls_frame, text="Carregar ASM", command=self.load_asm_file)
        self.btn_load.grid(row=0, column=0, padx=2, pady=2, sticky="ew")
        self.btn_config_cpu = ttk.Button(controls_frame, text="Configurar CPU", command=self.prompt_for_cpu_config)
        self.btn_config_cpu.grid(row=0, column=1, padx=2, pady=2, sticky="ew")
        self.btn_assemble = ttk.Button(controls_frame, text="Montar", command=self.assemble_code, state=tk.DISABLED)
        self.btn_assemble.grid(row=0, column=2, padx=2, pady=2, sticky="ew")
        
        self.btn_run = ttk.Button(controls_frame, text="Rodar Tudo", command=self.run_all, state=tk.DISABLED)
        self.btn_run.grid(row=1, column=0, padx=2, pady=2, sticky="ew")
        self.btn_step = ttk.Button(controls_frame, text="Passo", command=self.run_step_gui, state=tk.DISABLED)
        self.btn_step.grid(row=1, column=1, padx=2, pady=2, sticky="ew")
        self.btn_reset_sim = ttk.Button(controls_frame, text="Resetar Sim.", command=self.reset_simulation_state)
        self.btn_reset_sim.grid(row=1, column=2, padx=2, pady=2, sticky="ew")
        for i in range(3): controls_frame.grid_columnconfigure(i, weight=1)
        left_pane.add(controls_frame, weight=0)

        io_frame = ttk.LabelFrame(left_pane, text="Console I/O e Logs")
        self.io_text = scrolledtext.ScrolledText(io_frame, wrap=tk.WORD, height=12, state=tk.DISABLED, font=("Consolas", 9))
        self.io_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        input_field_frame = ttk.Frame(io_frame)
        input_field_frame.pack(fill=tk.X, padx=5, pady=2)
        self.input_var = tk.StringVar()
        self.input_entry = ttk.Entry(input_field_frame, textvariable=self.input_var, state=tk.DISABLED, width=60)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input_entry.bind("<Return>", self.submit_gui_input)
        self.btn_submit_input = ttk.Button(input_field_frame, text="Enviar", command=self.submit_gui_input, state=tk.DISABLED)
        self.btn_submit_input.pack(side=tk.LEFT, padx=2)
        left_pane.add(io_frame, weight=2)

        # Right Pane
        reg_frame = ttk.LabelFrame(right_pane, text="Registradores")
        reg_frame.pack(fill=tk.X, padx=5, pady=5)
        self.reg_labels = {}
        cols = 4 # Registradores por linha
        for i in range(32):
            row, col = divmod(i, cols)
            f = ttk.Frame(reg_frame); f.grid(row=row, column=col, padx=3, pady=1, sticky="w")
            ttk.Label(f, text=f"{get_reg_name(i):>5s}:", font=("Consolas",9)).pack(side=tk.LEFT)
            self.reg_labels[i] = ttk.Label(f, text="0x00000000 (0)", width=20, anchor="w", font=("Consolas",9))
            self.reg_labels[i].pack(side=tk.LEFT)
        
        pc_hi_lo_f = ttk.Frame(reg_frame); pc_hi_lo_f.grid(row=32//cols, column=0, columnspan=cols, sticky="ew", pady=3)
        for lbl_text, var_name in [("PC:", "pc_label"), ("HI:", "hi_label"), ("LO:", "lo_label")]:
            ttk.Label(pc_hi_lo_f, text=lbl_text, font=("Consolas",9)).pack(side=tk.LEFT, padx=(5,1))
            setattr(self, var_name, ttk.Label(pc_hi_lo_f, text="0x00000000", width=12, font=("Consolas",9)))
            getattr(self, var_name).pack(side=tk.LEFT, padx=(0,10))

        current_instr_frame = ttk.LabelFrame(right_pane, text="Instrução Atual (no PC)")
        current_instr_frame.pack(fill=tk.X, padx=5, pady=5)
        self.current_instr_asm_label = ttk.Label(current_instr_frame, text="ASM: -", wraplength=450, justify=tk.LEFT, font=("Consolas",9))
        self.current_instr_asm_label.pack(anchor="w", fill=tk.X)
        self.current_instr_hex_label = ttk.Label(current_instr_frame, text="HEX: -", font=("Consolas",9))
        self.current_instr_hex_label.pack(anchor="w", fill=tk.X)

        mem_frame = ttk.LabelFrame(right_pane, text="Visualizador de Memória")
        mem_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        mem_ctrl_f = ttk.Frame(mem_frame); mem_ctrl_f.pack(fill=tk.X)
        ttk.Label(mem_ctrl_f, text="Endereço (Hex):").pack(side=tk.LEFT)
        self.mem_addr_var = tk.StringVar(value=f"{DATA_SEGMENT_START:#010x}")
        self.mem_addr_entry = ttk.Entry(mem_ctrl_f, textvariable=self.mem_addr_var, width=12)
        self.mem_addr_entry.pack(side=tk.LEFT, padx=5)
        self.mem_addr_entry.bind("<Return>", lambda e: self.update_memory_display())
        ttk.Button(mem_ctrl_f, text="Ver", command=self.update_memory_display).pack(side=tk.LEFT)
        ttk.Button(mem_ctrl_f, text="Texto", command=lambda: self.set_mem_view_addr(self.simulator.text_segment_mips_base)).pack(side=tk.LEFT, padx=1)
        ttk.Button(mem_ctrl_f, text="Dados", command=lambda: self.set_mem_view_addr(self.simulator.data_segment_mips_base)).pack(side=tk.LEFT, padx=1)
        ttk.Button(mem_ctrl_f, text="$sp", command=lambda: self.set_mem_view_addr(self.simulator._get_reg(29))).pack(side=tk.LEFT, padx=1)
        self.mem_text = scrolledtext.ScrolledText(mem_frame, wrap=tk.NONE, height=15, state=tk.DISABLED, font=("Consolas", 9))
        self.mem_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        stats_frame = ttk.LabelFrame(right_pane, text="Estatísticas de Execução")
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.cycles_label = ttk.Label(stats_frame, text="Ciclos: 0", font=("Consolas",9))
        self.cycles_label.pack(anchor="w")
        self.time_label = ttk.Label(stats_frame, text="Tempo Exec.: 0.000000 s", font=("Consolas",9))
        self.time_label.pack(anchor="w")
        self.instr_count_label = ttk.Label(stats_frame, text="Instruções: 0", font=("Consolas",9))
        self.instr_count_label.pack(anchor="w")
    
    def save_asm_changes(self):
        if self.current_asm_file:
            try:
                content = self.code_text.get(1.0, tk.END).strip() # Get all text
                with open(self.current_asm_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.gui_log_message(f"Alterações salvas em {self.current_asm_file}")
            except Exception as e:
                messagebox.showerror("Erro ao Salvar", f"Não foi possível salvar o arquivo:\n{e}")
        else:
            messagebox.showwarning("Salvar", "Nenhum arquivo carregado para salvar. Use 'Carregar ASM' primeiro e depois edite.")


    def set_mem_view_addr(self, addr_mips):
        self.mem_addr_var.set(f"{addr_mips:#010x}")
        self.update_memory_display()

    def update_all_displays(self):
        state = self.simulator.get_state_for_gui()
        for i in range(32): self.reg_labels[i].config(text=f"{state['registers_by_num'][i]:#010x} ({state['registers_by_num'][i]})")
        self.pc_label.config(text=f"{state['pc']:#010x}")
        self.hi_label.config(text=f"{state['hi']:#010x}")
        self.lo_label.config(text=f"{state['lo']:#010x}")
        self.cycles_label.config(text=f"Ciclos: {state['total_cycles']}")
        exec_time = state['total_cycles'] / self.simulator.clock_hz if self.simulator.clock_hz > 0 else 0
        self.time_label.config(text=f"Tempo Exec.: {exec_time:.6f} s")
        total_instr = sum(state['instruction_counts'].values())
        self.instr_count_label.config(text=f"Instruções: {total_instr}")

        if self.program_loaded and (state['running'] or self.simulator.pc != self.simulator.text_segment_mips_base): # Show even if not running but PC moved
            pc = state['pc']
            instr_info = self.simulator.program_instructions_info.get(pc)
            if instr_info:
                mc, asm, _ = instr_info
                self.current_instr_asm_label.config(text=f"ASM: {asm}")
                self.current_instr_hex_label.config(text=f"HEX: {mc:#010x} (b{mc:032b})")
            elif state['running']: # PC em local desconhecido mas rodando (ex: JR para endereço calculado)
                self.current_instr_asm_label.config(text=f"ASM: (PC={pc:#0x} instrução desconhecida)")
                try: mc_raw = self.simulator._read_mem_word(pc) # Tenta ler diretamente
                except: mc_raw = "ERRO_LEITURA_MEM"
                self.current_instr_hex_label.config(text=f"HEX: {mc_raw:#010x if isinstance(mc_raw,int) else mc_raw}")
            elif not state['running'] and state['exit_code'] is not None: # Terminou
                self.current_instr_asm_label.config(text="ASM: (Programa Terminado)")
                self.current_instr_hex_label.config(text=f"HEX: (Exit Code: {state['exit_code']})")
            else: # Não rodando, PC pode ser inicial
                self.current_instr_asm_label.config(text="ASM: (Pronto para iniciar ou resetado)")
                self.current_instr_hex_label.config(text="HEX: -")

        elif not self.program_loaded:
            self.current_instr_asm_label.config(text="ASM: (Nenhum programa carregado)")
            self.current_instr_hex_label.config(text="HEX: -")
        self.update_memory_display()
        self.update_button_states()

    def update_displays_before_execute(self, pc_val, instr_val_mc, asm_str):
        self.pc_label.config(text=f"{pc_val:#010x}")
        self.current_instr_asm_label.config(text=f"ASM: {asm_str}")
        self.current_instr_hex_label.config(text=f"HEX: {instr_val_mc:#010x} (b{instr_val_mc:032b})")
        self.update_button_states()

    def update_displays_after_execute(self):
        self.update_all_displays() # Atualiza tudo, incluindo regs e memória
        # self.update_button_states() # update_all_displays já chama

    def update_memory_display(self):
        self.mem_text.config(state=tk.NORMAL); self.mem_text.delete(1.0, tk.END)
        try: start_addr = int(self.mem_addr_var.get(), 16)
        except ValueError: self.mem_text.insert(tk.END, "Endereço inicial inválido."); self.mem_text.config(state=tk.DISABLED); return

        words_per_line = 4; num_lines = 16 # Mostrar 16 linhas de 4 palavras
        for i in range(num_lines):
            line_str = f"{start_addr + (i * words_per_line * 4):#010x}: "
            ascii_line_part = ""
            for j in range(words_per_line):
                current_addr = start_addr + (i * words_per_line * 4) + (j * 4)
                val = self.simulator.get_memory_word_for_gui(current_addr)
                if isinstance(val, int):
                    line_str += f" {val:#010x}"
                    try:
                        for byte_char_val in val.to_bytes(4, 'big'): ascii_line_part += chr(byte_char_val) if 32<=byte_char_val<=126 else '.'
                    except: ascii_line_part += "...." # Overflow ou outro erro
                else: line_str += f" {val:<10s}"; ascii_line_part += "----" # Erro como AddrErr
            self.mem_text.insert(tk.END, f"{line_str} |{ascii_line_part}|\n")
        self.mem_text.config(state=tk.DISABLED)

    def update_button_states(self):
        sim_state = self.simulator.get_state_for_gui()
        self.btn_assemble.config(state=tk.NORMAL if self.current_asm_file else tk.DISABLED)
        can_run_step = self.program_loaded and sim_state["running"] and not sim_state["waiting_for_input"]
        self.btn_run.config(state=tk.NORMAL if can_run_step else tk.DISABLED)
        self.btn_step.config(state=tk.NORMAL if can_run_step else tk.DISABLED)
        # btn_reset_sim sempre habilitado para permitir reset geral
        self.input_entry.config(state=tk.NORMAL if sim_state["waiting_for_input"] else tk.DISABLED)
        self.btn_submit_input.config(state=tk.NORMAL if sim_state["waiting_for_input"] else tk.DISABLED)

    def load_asm_file(self):
        filepath = filedialog.askopenfilename(title="Abrir Assembly MIPS", filetypes=(("Assembly", "*.asm *.s"), ("Todos", "*.*")))
        if filepath:
            self.current_asm_file = filepath
            self.gui_log_message(f"Arquivo Assembly: {filepath}")
            try:
                with open(filepath, 'r', encoding='utf-8') as f: content = f.read()
                self.code_text.config(state=tk.NORMAL); self.code_text.delete(1.0, tk.END)
                self.code_text.insert(tk.END, content); self.code_text.config(state=tk.DISABLED)
                self.program_loaded = False # Precisa montar
                self.prompt_for_cpu_config() # Sempre pede config ao carregar novo arquivo
            except Exception as e: messagebox.showerror("Erro ao Ler", f"Falha ao ler arquivo:\n{e}"); self.current_asm_file = None
            self.update_all_displays() # Atualiza estado inicial e botões

    def prompt_for_cpu_config(self):
        title = "Configuração da CPU"
        prompts = [
            ("Frequência Clock (Hz, ex: 100M):", f"{self.simulator.clock_hz:.0f}", 'clock_hz'),
            ("CPI Tipo R:", str(self.simulator.cpi_values.get('R',1)), ('cpi_values','R')),
            ("CPI Tipo I (não Load/Store/Branch):", str(self.simulator.cpi_values.get('I',1)), ('cpi_values','I')),
            ("CPI Load/Store:", str(self.simulator.cpi_values.get('LoadStore',2)), ('cpi_values','LoadStore')),
            ("CPI Branch:", str(self.simulator.cpi_values.get('Branch',1)), ('cpi_values','Branch')),
            ("CPI Tipo J:", str(self.simulator.cpi_values.get('J',1)), ('cpi_values','J')),
            ("CPI Syscall:", str(self.simulator.cpi_values.get('Syscall',10)), ('cpi_values','Syscall')),
        ]
        new_configs = {}
        try:
            for prompt_text, initial_val, attr_key in prompts:
                val_str = simpledialog.askstring(title, prompt_text, initialvalue=initial_val, parent=self)
                if val_str is None: return # Usuário cancelou
                
                if attr_key == 'clock_hz':
                    if 'g' in val_str.lower(): val_num = float(val_str.lower().replace('g',''))*1e9
                    elif 'm' in val_str.lower(): val_num = float(val_str.lower().replace('m',''))*1e6
                    elif 'k' in val_str.lower(): val_num = float(val_str.lower().replace('k',''))*1e3
                    else: val_num = float(val_str)
                    new_configs[attr_key] = val_num
                else: # É um CPI
                    if isinstance(attr_key, tuple): # ('cpi_values', 'Key')
                        if 'cpi_values' not in new_configs: new_configs['cpi_values'] = self.simulator.cpi_values.copy()
                        new_configs['cpi_values'][attr_key[1]] = int(val_str)
                    else: # Deveria ser tupla para CPIs
                        new_configs[attr_key] = int(val_str) # Não deve acontecer com a estrutura atual
            
            # Aplicar configurações
            if 'clock_hz' in new_configs: self.simulator.clock_hz = new_configs['clock_hz']
            if 'cpi_values' in new_configs: self.simulator.cpi_values = new_configs['cpi_values']
            self.gui_log_message(f"CPU Config: Clock={self.simulator.clock_hz/1e6:.2f}MHz, CPIs={self.simulator.cpi_values}")
        except (ValueError, TypeError) as e: messagebox.showerror("Erro Config", f"Valor inválido: {e}\nUsando defaults ou anteriores.")
        self.update_all_displays()

    def assemble_code(self):
        if not self.current_asm_file: messagebox.showwarning("Montagem", "Nenhum arquivo ASM carregado."); return
        self.gui_log_message("Montando código...")
        # Garante que o simulador use as configs de CPU atuais ao ser resetado/recriado
        self.simulator = MipsSimulator(clock_hz=self.simulator.clock_hz, 
                                    cpi_config=self.simulator.cpi_values, 
                                    gui_hooks=self.simulator.gui_hooks)
        self.assembler = Assembler(logger_func=self.gui_log_message_assembler) # Recria assembler

        # Obter conteúdo do editor de texto em vez de reler o arquivo
        current_code_content = self.code_text.get(1.0, tk.END).splitlines()

        machine_code, data_s, sym_t, data_l = self.assembler.assemble(current_code_content) # Passa linhas do editor
        if machine_code is not None:
            self.gui_log_message("-- Tabela de Símbolos (Código) --")
            for lbl,adr in sym_t.items(): self.gui_log_message(f"  {lbl}: {adr:#010x}")
            self.gui_log_message("-- Tabela de Símbolos (Dados) --")
            for lbl,adr in data_l.items(): self.gui_log_message(f"  {lbl}: {adr:#010x}")
            if self.simulator.load_program(machine_code, data_s):
                self.gui_log_message("Código montado e carregado com sucesso."); self.program_loaded = True
            else: self.gui_log_message("Falha ao carregar código no simulador."); self.program_loaded = False
        else: self.gui_log_message("Falha na montagem."); self.program_loaded = False
        self.update_all_displays()

    def run_step_gui(self):
        if self.program_loaded and self.simulator.running:
            if self.simulator.waiting_for_gui_input: self.gui_log_message("Aguardando entrada do usuário..."); return
            self.simulator.run_step()
        else: self.gui_log_message("Programa não carregado ou simulação parada.")
        # update_button_states é chamado por update_all_displays que é chamado por hooks

    def run_all(self):
        if self.program_loaded and self.simulator.running:
            if self.simulator.waiting_for_gui_input: self.gui_log_message("Aguardando input para 'Rodar Tudo'..."); return
            self._running_all_active = True; self.btn_run.config(state=tk.DISABLED); self.btn_step.config(state=tk.DISABLED)
            self.gui_log_message("Rodando programa...")
            def continuous_step():
                if self.simulator.running and not self.simulator.waiting_for_gui_input and self._running_all_active:
                    self.simulator.run_step()
                    if self.simulator.running and not self.simulator.waiting_for_gui_input and self._running_all_active:
                        self.after(1, continuous_step) # Delay mínimo para manter GUI responsiva
                    else: # Parou (fim, erro, input) ou interrompido
                        if self._running_all_active : self.gui_log_message("Execução 'Rodar Tudo' pausada ou concluída.")
                        self._running_all_active = False; self.update_button_states()
                else: # Não estava rodando ou foi interrompido
                    if self._running_all_active: self.gui_log_message("Execução 'Rodar Tudo' finalizada.")
                    self._running_all_active = False; self.update_button_states()
            self.after(1, continuous_step)
        else: self.gui_log_message("Programa não carregado ou simulação parada para 'Rodar Tudo'.")

    def reset_simulation_state(self):
        self._running_all_active = False # Para qualquer 'run_all'
        self.gui_log_message("Resetando simulador...")
        # Mantém configs de CPU, mas reseta o estado do simulador e recarrega programa se houver
        self.simulator = MipsSimulator(clock_hz=self.simulator.clock_hz, 
                                    cpi_config=self.simulator.cpi_values, 
                                    gui_hooks=self.simulator.gui_hooks)
        if self.current_asm_file: # Se um arquivo foi carregado e montado
            self.gui_log_message("Remontando e recarregando o arquivo atual...")
            self.assemble_code() # Isso irá recarregar o programa no simulador resetado
        else:
            self.program_loaded = False
            self.update_all_displays() # Atualiza para estado vazio
        self.gui_log_message("Simulador resetado.")

    def gui_print_int(self, val): self.io_text.config(state=tk.NORMAL); self.io_text.insert(tk.END, str(val)); self.io_text.see(tk.END); self.io_text.config(state=tk.DISABLED)
    def gui_print_string(self, s): self.io_text.config(state=tk.NORMAL); self.io_text.insert(tk.END, s); self.io_text.see(tk.END); self.io_text.config(state=tk.DISABLED)
    def gui_print_char(self, c): self.io_text.config(state=tk.NORMAL); self.io_text.insert(tk.END, c); self.io_text.see(tk.END); self.io_text.config(state=tk.DISABLED)
    def gui_log_message(self, msg):
        if not msg.endswith('\n'): msg += '\n'
        self.io_text.config(state=tk.NORMAL); self.io_text.insert(tk.END, msg); self.io_text.see(tk.END); self.io_text.config(state=tk.DISABLED)
    def _enable_input_area(self, prompt="Entrada: "):
        self.gui_log_message(prompt.strip()) # Loga o prompt sem adicionar \n extra
        self.input_entry.config(state=tk.NORMAL); self.btn_submit_input.config(state=tk.NORMAL); self.input_entry.focus()
    def gui_read_int_start(self): self._enable_input_area("syscall read_int: ")
    def gui_read_char_start(self): self._enable_input_area("syscall read_char: ")
    def gui_read_string_start(self, max_len): self._enable_input_area(f"syscall read_string (max {max_len-1} chars): ")
    def submit_gui_input(self, event=None):
        user_val = self.input_var.get(); self.input_var.set("")
        self.input_entry.config(state=tk.DISABLED); self.btn_submit_input.config(state=tk.DISABLED)
        self.gui_log_message(f"Input: {user_val}") # Loga o que foi digitado
        self.simulator.provide_gui_input(user_val)
    def resume_simulation_after_input(self):
        self.update_button_states(); self.gui_log_message("Entrada recebida.")
        if self._running_all_active: self.gui_log_message("Continuando 'Rodar Tudo'..."); self.after(1, self.run_all)
        else: self.gui_log_message("Prossiga com 'Passo' ou 'Rodar Tudo'.")
    def handle_program_termination(self, exit_code):
        self._running_all_active = False
        self.gui_log_message(f"PROGRAMA TERMINADO. Código de saída: {exit_code}")
        self.update_all_displays(); self.update_button_states()
    def handle_simulation_end(self): # Chamado quando self.running se torna False por qualquer motivo
        self._running_all_active = False
        if not self.simulator.get_state_for_gui()['waiting_for_input']: # Só se não estiver esperando input
            self.gui_log_message("SIMULAÇÃO ENCERRADA.")
        self.update_all_displays(); self.update_button_states()

if __name__ == "__main__":
    app = MipsGui()
    app.mainloop()