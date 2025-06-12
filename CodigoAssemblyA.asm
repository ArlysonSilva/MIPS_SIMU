config_CPU = [20MHZ, I=1, J=3, R=2] 
main:
    # Inicialização de registradores
    li $t0, 12
    li $t1, 5

    # Aritmética
    add $t2, $t0, $t1
    sub $t3, $t0, $t1
    mul $t4, $t0, $t1

    # Operações lógicas
    and $t5, $t0, $t1  # $t5 = 12 & 5
    or  $t6, $t0, $t1  # $t6 = 12 | 5

    # Simulando memória com a stack
    addi $sp, $sp, -12   
    sw $t2, 0($sp)
    sw $t4, 4($sp)
    sb $t5, 8($sp)

    # Carrega valores de volta
    lw $s0, 0($sp)
    lw $s1, 4($sp)
    lb $s2, 8($sp)

    # Desvio condicional
    beq $t0, $t1, equal_case
    j  not_equal_case

equal_case:
    li $s3, 111
    j end

not_equal_case:
    li $s3, 222

end:
    nop

// N instruções 19 