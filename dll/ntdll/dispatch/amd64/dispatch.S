/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntdll/dispatch/amd64/dispatch.S
 * PURPOSE:         Usermode dispatcher stubs
 *
 * PROGRAMMER:      Timo kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <asm.inc>
#include <ksamd64.inc>

EXTERN NtContinue:PROC
EXTERN LdrpInit:PROC
EXTERN ZwCallbackReturn:PROC
EXTERN RtlRaiseStatus:PROC

.code

PUBLIC LdrInitializeThunk
.PROC LdrInitializeThunk
    mov rbp, 0
    .setframe rbp, 0
    .endprolog

    /* First parameter is the APC context */
    mov rcx, r9
    jmp LdrpInit

.ENDP

PUBLIC KiUserApcDispatcher
.PROC KiUserApcDispatcher
    .endprolog
    /* We enter with a 16 byte aligned stack */

    call Execute

    mov rcx, [rsp + CONTEXT_P1Home] /* NormalContext */
    mov rdx, [rsp + CONTEXT_P2Home] /* SystemArgument1 */
    mov r8, [rsp + CONTEXT_P3Home]  /* SystemArgument2 */
    lea r9, [rsp]                   /* Context */
    call qword ptr [rsp + CONTEXT_P4Home] /* NormalRoutine */

    /* NtContinue(Context, TRUE); */
    lea rcx, [rsp]
    mov dl, 1
    call NtContinue

    nop
    int 3
.ENDP

PUBLIC KiRaiseUserExceptionDispatcher
.PROC KiRaiseUserExceptionDispatcher
    .endprolog
    int 3

.ENDP

PUBLIC KiUserCallbackDispatcher
.PROC KiUserCallbackDispatcher

    ; The stack is set up with a UCALLOUT_FRAME
    ; The frame ends with a MACHINE_FRAME.
    .PUSHFRAME

    ; This is for the Home space, Buffer, Length and ApiNumber
    .ALLOCSTACK 6 * 8
    .ENDPROLOG

#if DBG
    ; We enter the function with a fully setup stack, so it must be aligned!
    test rsp, 15
    jz AlignmentOk
    int HEX(2C)
AlignmentOk:
#endif

    ; Get the parameters from the callout frame
    mov rcx, [rsp + CkBuffer]
    mov edx, [rsp + CkLength]
    mov r8d, [rsp + CkApiNumber]

    ; Get the callback table
    mov rax, gs:[TePeb]
    mov r9, [rax + PeKernelCallbackTable]

    ; Call the routine
    call qword ptr [r9 + r8 * 8]

    ; Return from callback
    xor ecx, ecx
    xor edx, edx
    mov r8d, eax
    call ZwCallbackReturn

    ; Save callback return value
    mov esi, eax

    ; Raise status
StatusRaise:
    mov ecx, esi
    call RtlRaiseStatus
    jmp StatusRaise

.ENDP

PUBLIC KiUserExceptionDispatcher
.PROC KiUserExceptionDispatcher
    .endprolog
    int 3

.ENDP

; This is the global memory address we apply the hardware breakpoint on.
EXTERN StackSelector: word

; A reference to the C++ routine that will set a hardware breakpoint
; on a target memory address.
EXTERN SetDataBreakpoint: proc

.code

Execute PROC
	; Store the current (valid) SS selector.
	mov [StackSelector], ss

	; BREAKPOINT_TYPE::Access
	mov r9, 3

	; DEBUG_REGISTERS::DR0
	mov r8, 0

	; BREAKPOINT_SIZE::Four
	mov rdx, 3
	
	; Address to place a DB (HWBP) on. This is the address of the global 
	; that contains the SS selector value.
	lea rcx, StackSelector

	; Setup shadow space on the stack.
	sub rsp, 20h

	; Prime the current thread's debug registers.
	call SetDataBreakpoint

	; Restore home space.
	add rsp, 20h

	; Check to see if the routine failed.
	test rax, rax
	jz exit
	
	mov ss, [rax] ; #DB should fire here, but it's supressed.
	int 3

	; #DB is released after the INT 03 instruction executes. 
	;
	; INT 03 will branch to kernelmode, in particular, to the IDT
	; entry at nt!KiBreakpointTrap.
	;
	; nt!KiBreakpointTrap will not execute its first instruction, 
	; since it will be interrupted by the #DB that was just
	; dispatched. This will cause the processor to transition to 
	; the #DB handler at nt!KiDebugTrapOrFault.

exit:
	; This instruction shouldn't execute if we succeed.
	ret
Execute ENDP

END

