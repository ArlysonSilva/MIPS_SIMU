# exemplo_completo.asm

.data
str_prompt:  .asciiz "Digite um numero inteiro: "
str_num_lido: .asciiz "Numero lido: "
str_soma:    .asciiz "Soma (a+b): "
str_sub:     .asciiz "Subtracao (a-b): "
str_prod:    .asciiz "Produto (a*b): "
str_quoc:    .asciiz "Quociente (a/b): "
str_resto:   .asciiz "Resto (a%b): "
str_fatorial: .asciiz "Fatorial do numero lido: "
str_ola:     .asciiz "\nOla do procedimento!\n"
newline:     .asciiz "\n"

# Variáveis globais (exemplo, não ideal mas para teste de lw/sw)
var_a:       .word 0
var_b:       .word 0

.text
.globl main # Diretiva para indicar ponto de entrada, ignorada pelo assembler simples

main:
    # Ler primeiro número (a)
    la $a0, str_prompt      # Carrega endereço da string de prompt
    li $v0, 4               # Código para print_string
    syscall

    li $v0, 5               # Código para read_int
    syscall
    move $s0, $v0           # Salva o número lido em $s0 (a)
    sw $s0, var_a           # Salva 'a' na variável global var_a

    # Ler segundo número (b)
    la $a0, str_prompt
    li $v0, 4
    syscall

    li $v0, 5
    syscall
    move $s1, $v0           # Salva o número lido em $s1 (b)
    sw $s1, var_b           # Salva 'b' na variável global var_b

    # Mostrar números lidos (usando load das variáveis globais)
    la $a0, str_num_lido
    li $v0, 4
    syscall
    lw $a0, var_a           # Carrega 'a' da memória
    li $v0, 1
    syscall
    la $a0, newline
    li $v0, 4
    syscall

    # Operações
    add $t0, $s0, $s1       # t0 = a + b
    sub $t1, $s0, $s1       # t1 = a - b
    mult $s0, $s1           # HI:LO = a * b
    mflo $t2                # t2 = LO (produto)
    
    # Tratamento para divisão por zero
    beq $s1, $zero, divisao_por_zero
    div $s0, $s1            # LO = a / b, HI = a % b
    mflo $t3                # t3 = quociente
    mfhi $t4                # t4 = resto
    j imprimir_divisao      # Pula a mensagem de erro
divisao_por_zero:
    li $t3, 0               # Define quociente como 0
    li $t4, 0               # Define resto como 0 (ou $s0 se preferir)
    # Poderia imprimir uma mensagem de erro aqui
imprimir_divisao:

    # Imprimir resultados
    la $a0, str_soma; li $v0, 4; syscall
    move $a0, $t0; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    la $a0, str_sub; li $v0, 4; syscall
    move $a0, $t1; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    la $a0, str_prod; li $v0, 4; syscall
    move $a0, $t2; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    la $a0, str_quoc; li $v0, 4; syscall
    move $a0, $t3; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    la $a0, str_resto; li $v0, 4; syscall
    move $a0, $t4; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    # Chamada de função: Fatorial de 'a' (que está em $s0)
    move $a0, $s0           # Argumento para fatorial em $a0
    jal fatorial            # Chama a função fatorial
    move $s3, $v0           # Salva resultado do fatorial em $s3

    la $a0, str_fatorial; li $v0, 4; syscall
    move $a0, $s3; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall

    jal meu_procedimento

    li $t5, 0; li $t6, 3
loop_teste:
    beq $t5, $t6, fim_loop_teste
    move $a0, $t5; li $v0, 1; syscall
    la $a0, newline; li $v0, 4; syscall
    addi $t5, $t5, 1
    j loop_teste
fim_loop_teste:

    li $v0, 10; syscall

# ----------------------------------
fatorial:
    addiu $sp, $sp, -8      # Salvar $ra e $s0 (exemplo)
    sw $ra, 4($sp)
    sw $s0, 0($sp)          # Salva $s0 (embora fatorial não o modifique muito)
    
    move $s0, $a0           # Copia n para $s0 para trabalhar

    # Caso base: n <= 1, fatorial é 1
    slti $t0, $s0, 2        # t0 = 1 se n < 2 (n=0 ou n=1)
    bne $t0, $zero, fat_base_ret # Se t0 != 0 (ou seja, t0=1), vá para fat_base_ret

    # n > 1, fatorial(n) = n * fatorial(n-1) -- Iterativo
    li $v0, 1               # Acumulador do fatorial
fat_iter_loop:
    beq $s0, $zero, fat_fim # Se n (em $s0) == 0, loop termina
    mult $v0, $s0
    mflo $v0
    addiu $s0, $s0, -1
    j fat_iter_loop
    
fat_base_ret:
    li $v0, 1               # Resultado para n=0 ou n=1

fat_fim:
    lw $s0, 0($sp)          # Restaura $s0
    lw $ra, 4($sp)
    addiu $sp, $sp, 8
    jr $ra
# ----------------------------------
meu_procedimento:
    addiu $sp, $sp, -4; sw $ra, 0($sp)
    la $a0, str_ola; li $v0, 4; syscall
    lw $ra, 0($sp); addiu $sp, $sp, 4
    jr $ra