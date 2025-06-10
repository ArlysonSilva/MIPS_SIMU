.data
  msg: .asciiz "Resultado: "

.text
  main:
    li $t0, 5        # Carrega o valor 5 no registrador $t0
    li $t1, 10       # Carrega o valor 10 no registrador $t1
    add $t2, $t0, $t1  # Soma $t0 + $t1 e armazena o resultado em $t2

    li $v0, 4        # Código do serviço para imprimir string
    la $a0, msg      # Carrega o endereço da mensagem em $a0
    syscall

    li $v0, 1        # Código do serviço para imprimir inteiro
    move $a0, $t2    # Move o resultado da soma para $a0
    syscall

    li $v0, 10       # Código do serviço para encerrar o programa
    syscall
