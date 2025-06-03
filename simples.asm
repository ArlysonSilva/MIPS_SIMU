# simples.asm

.data
mensagem_ola: .asciiz "Ola Mundo!\n"
prompt_num:   .asciiz "Digite um numero: "
resultado_msg: .asciiz "Voce digitou: "

.text
.globl main # Esta diretiva será ignorada, o que é o comportamento esperado

main:
    # Imprimir "Ola Mundo!"
    la $a0, mensagem_ola    # Carrega endereço da string
    li $v0, 4               # Código para print_string
    syscall

    # Pedir um número ao usuário
    la $a0, prompt_num
    li $v0, 4
    syscall

    # Ler o número digitado
    li $v0, 5               # Código para read_int
    syscall                 # O inteiro lido estará em $v0

    # Mover o número lido para $s0 para guardá-lo
    move $s0, $v0           # $s0 = $v0 (pseudo-instrução: add $s0, $v0, $zero)

    # Imprimir a mensagem "Voce digitou: "
    la $a0, resultado_msg
    li $v0, 4
    syscall

    # Imprimir o número que o usuário digitou (que está em $s0)
    move $a0, $s0           # Argumento para print_int em $a0
    li $v0, 1               # Código para print_int
    syscall

    # Adicionar um newline para formatação
    li $a0, 10              # ASCII para newline '\n' (alternativa para .asciiz)
    li $v0, 11              # Código para print_char
    syscall

    # Terminar o programa
    li $v0, 10              # Código para exit
    syscall

# Fim do programa