config_CPU = [5MHZ, I=1, J=1, R=1] 
main:
    lw   $t0, 0($a0)
    lw   $t1, 4($a0)
    add  $t2, $t0, $t1
    sub  $t3, $t0, $t1
    mul  $t4, $t0, $t1
    add  $t5, $t2, $t4
    add  $t6, $t3, $t5
