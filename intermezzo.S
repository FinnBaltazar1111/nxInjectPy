.globl _start
.section ".text"
_start:
    ldr r0, =INTERMEZZO_RELOCATED_ADDRESS
    ldr r1, =post_relocation
    ldr r2, =intermezzo_end
    sub r2, r2, r1
    bl  copy
    ldr r0, =INTERMEZZO_RELOCATED_ADDRESS
    bx  r0
.align 4
post_relocation:
    ldr r0, =RELOCATION_TARGET
    ldr r1, =PAYLOAD_START_ADDR
    ldr r2, =BEFORE_SPRAY_LENGTH
    bl  copy
    ldr r0, =RELOCATION_TARGET
    ldr r1, =BEFORE_SPRAY_LENGTH
    add r0, r0, r1
    ldr r1, =STACK_SPRAY_END
    ldr r2, =AFTER_SPRAY_LENGTH
    bl  copy
    ldr r0, =ENTRY_POINT_ADDRESS
    bx r0
copy:
    ldr r3, [r1], #4
    str r3, [r0], #4
    subs r2, r2, #4
    bne copy
    bx lr