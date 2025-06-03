# Simulador MIPS Avançado com Interface Gráfica

Este projeto é um simulador para um subconjunto da arquitetura MIPS I, implementado em Python com uma interface gráfica de usuário (GUI) construída usando Tkinter. Ele permite carregar, montar, executar passo a passo ou continuamente, e depurar programas escritos em assembly MIPS.

## Funcionalidades Principais

*   **Editor de Código Assembly:**
    *   Carregar arquivos de assembly MIPS (`.asm`, `.s`).
    *   Visualizar e editar o código diretamente na interface.
    *   Salvar alterações no arquivo original.
*   **Montador Integrado (Assembler):**
    *   Converte código assembly MIPS em código de máquina.
    *   Suporte a diretivas de dados (`.data`, `.text`, `.word`, `.asciiz`, `.byte`, `.space`, `.align`).
    *   Resolução de labels para código e dados.
    *   Expansão de pseudo-instruções comuns (`li`, `la`, `move`, `nop`, `b`, `bal`).
    *   Logs detalhados do processo de montagem.
*   **Simulador MIPS:**
    *   Execução do código de máquina MIPS.
    *   Simulação do banco de 32 registradores, mais PC, HI, LO.
    *   Simulação de memória para segmentos de texto, dados e pilha.
    *   Implementação de um conjunto significativo de instruções MIPS (Tipo R, I, J), incluindo aritméticas, lógicas, transferência de dados, desvios e syscalls.
    *   Tratamento de exceções básicas (acesso à memória, instrução inválida, overflow).
*   **Interface Gráfica Detalhada:**
    *   Visualização em tempo real dos registradores.
    *   Visualização da instrução atual (assembly e hexadecimal/binário).
    *   Visualizador de memória interativo com representação hexadecimal e ASCII.
    *   Exibição de estatísticas de execução (ciclos, tempo, contagem de instruções).
    *   Console para I/O de syscalls e logs do sistema.
*   **Controles de Simulação Flexíveis:**
    *   Execução passo a passo (`Passo`).
    *   Execução contínua (`Rodar Tudo`).
    *   Resetar o estado da simulação.
*   **Configuração da CPU:**
    *   Permite ao usuário definir a frequência do clock da CPU.
    *   Permite configurar o número de Ciclos Por Instrução (CPI) para diferentes categorias de instruções (R, I, Load/Store, Branch, J, Syscall).

## Estrutura do Projeto

*   **`gui.py`**: Contém a classe `MipsGui` que implementa toda a interface gráfica do usuário usando Tkinter. É o ponto de entrada principal para rodar o simulador com GUI.
*   **`mips_simulator.py`**: Contém a classe `MipsSimulator` responsável pela lógica de simulação do processador MIPS, incluindo registradores, memória, fetch-decode-execute e tratamento de syscalls.
*   **`assembler.py`**: Contém a classe `Assembler` que realiza a montagem do código assembly MIPS para código de máquina (processo de duas passagens).
*   **`utils.py`**: Arquivo utilitário com constantes, mapeamentos de registradores, formatos de instrução, definições de syscalls, e funções auxiliares usadas em todo o projeto.
*   **`main.py`**: Ponto de entrada alternativo para rodar o simulador em modo console (funcionalidade limitada comparada à GUI).

## Como Executar

### Pré-requisitos
*   Python 3.x
*   Tkinter (geralmente incluído na instalação padrão do Python)

### Executando a Interface Gráfica (Recomendado)
Para iniciar o simulador com a interface gráfica, execute o seguinte comando no seu terminal, a partir do diretório raiz do projeto:
```bash
python gui.py