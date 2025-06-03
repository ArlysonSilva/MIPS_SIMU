# main.py
# Este arquivo é para rodar o simulador via console, sem a GUI.
# A GUI (gui.py) é agora o método principal de interação.

from assembler import Assembler
from mips_simulator import MipsSimulator

def main_console():
    print("--- Simulador MIPS Console ---")
    asm_filepath = input("Caminho para o arquivo Assembly MIPS (.asm): ")
    
    try:
        clock_str = input("Clock (Hz, ex: 100M): ")
        if 'g' in clock_str.lower(): clock_hz = float(clock_str.lower().replace('g','')) * 1e9
        elif 'm' in clock_str.lower(): clock_hz = float(clock_str.lower().replace('m','')) * 1e6
        elif 'k' in clock_str.lower(): clock_hz = float(clock_str.lower().replace('k','')) * 1e3
        else: clock_hz = float(clock_str)

        cpi_r = int(input("CPI Tipo R: "))
        cpi_i = int(input("CPI Tipo I (não Load/Store/Branch): ")) # Separar CPIs
        cpi_ls = int(input("CPI Load/Store: "))
        cpi_br = int(input("CPI Branch: "))
        cpi_j = int(input("CPI Tipo J: "))
        cpi_syscall = int(input("CPI Syscall: "))
        cpi_config = {'R': cpi_r, 'I': cpi_i, 'LoadStore': cpi_ls, 'Branch': cpi_br, 'J': cpi_j, 'Syscall': cpi_syscall}
    except ValueError:
        print("Entrada inválida para CPU config. Usando defaults.")
        clock_hz = 100e6
        cpi_config = {'R': 1, 'I': 1, 'LoadStore':2, 'Branch':1, 'J': 1, 'Syscall': 10}

    assembler = Assembler() # Pode passar logger_func=print se quiser logs do assembler
    print("\n--- Montagem ---")
    machine_code, data_segment, symbol_table, data_labels = assembler.assemble(asm_filepath)

    if machine_code is None:
        print("Falha na montagem. Encerrando.")
        return

    print("Tabela de Símbolos (Código):")
    for label, addr in (symbol_table or {}).items(): print(f"  {label}: {addr:#010x}")
    print("Tabela de Símbolos (Dados):")
    for label, addr in (data_labels or {}).items(): print(f"  {label}: {addr:#010x}")

    simulator = MipsSimulator(clock_hz=clock_hz, cpi_config=cpi_config) # Sem GUI hooks
    print("\n--- Simulação ---")
    if not simulator.load_program(machine_code, data_segment):
        print("Falha ao carregar programa no simulador. Encerrando.")
        return

    max_steps = 2000; step_count = 0
    while simulator.running and step_count < max_steps:
        if simulator.waiting_for_gui_input: # No console, isso não deveria acontecer sem GUI hooks
            print("ERRO: Simulador esperando por input da GUI no modo console.")
            break
        
        pc_before = simulator.pc
        instr_val, original_asm, _ = simulator.fetch() # Fetch para display
        if instr_val is None: break

        print(f"\nPC: {pc_before:#010x} | ASM: {original_asm} | HEX: {instr_val:#010x}")
        
        if not simulator.run_step(): break # run_step faz fetch, decode, execute
        step_count += 1
        
        # Display de registradores (simplificado)
        # for i in range(0,32,4): print(f" ${i}:{simulator.regs[i]} ${i+1}:{simulator.regs[i+1]} ${i+2}:{simulator.regs[i+2]} ${i+3}:{simulator.regs[i+3]}")
        
        inp = input("Enter para próximo, 'r' para rodar, 'q' para sair: ")
        if inp.lower() == 'q': break
        if inp.lower() == 'r': 
            while simulator.run_step() and step_count < max_steps: step_count += 1
            break
    
    print("\n--- Fim da Simulação ---")
    state = simulator.get_state_for_gui()
    print(f"PC Final: {state['pc']:#010x}, Exit Code: {state['exit_code']}")
    print(f"Total de ciclos: {state['total_cycles']}")
    exec_time = state['total_cycles'] / clock_hz if clock_hz > 0 else 0
    print(f"Tempo de execução: {exec_time:.9f} segundos")
    print("Contagem de instruções:")
    for tipo, count in state['instruction_counts'].items():
        if count > 0 : print(f"  {tipo}: {count}")

if __name__ == "__main__":
    # Para rodar a GUI: execute python gui.py
    # Para rodar a versão console (se desejar):
    # main_console() 
    print("Para rodar o simulador com interface gráfica, execute: python gui.py")
    print("Para rodar a versão console (limitada), descomente 'main_console()' em main.py e execute este arquivo.")