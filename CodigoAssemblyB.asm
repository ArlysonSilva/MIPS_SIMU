config_CPU = [20MHZ, I=1, J=1, R=1] 
main:
    addi $t0, $zero, 0
    addi $t1, $zero, 6

loop:
    beq $t0, $t1, end
    addi $t0, $t0, 1
    j loop

end:
