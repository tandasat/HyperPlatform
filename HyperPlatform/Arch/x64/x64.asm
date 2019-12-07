; Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements all assembler code
;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN VmmVmExitHandler : PROC
EXTERN VmmVmxFailureHandler : PROC
EXTERN UtilDumpGpRegisters : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2
KTRAP_FRAME_SIZE            EQU     190h
MACHINE_FRAME_SIZE          EQU     28h

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Saves all general purpose registers to the stack
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

; Dumps all general purpose registers and a flag register.
ASM_DUMP_REGISTERS MACRO
    pushfq
    PUSHAQ                      ; -8 * 16
    mov rcx, rsp                ; all_regs
    mov rdx, rsp
    add rdx, 8*17               ; stack_pointer

    sub rsp, 28h                ; 28h for alignment
    call UtilDumpGpRegisters    ; UtilDumpGpRegisters(all_regs, stack_pointer);
    add rsp, 28h

    POPAQ
    popfq
ENDM


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; implementations
;
.CODE

; bool __stdcall AsmInitializeVm(
;     _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
;                                            _In_opt_ void *),
;     _In_opt_ void *context);
AsmInitializeVm PROC
    ; RSP is not 16 bit aligned when it gets called, but the following odd
    ; number (17 times) of push makes RSP 16 bit aligned.
    pushfq
    PUSHAQ              ; -8 * 16

    mov rax, rcx
    mov r8, rdx
    mov rdx, asmResumeVm
    mov rcx, rsp

    sub rsp, 20h
    call rax            ; vm_initialization_routine(rsp, asmResumeVm, context)
    add rsp, 20h

    POPAQ
    popfq
    xor rax, rax        ; return false
    ret

    ; This is where the virtualized guest start to execute after successful
    ; vmlaunch.
asmResumeVm:
    nop                 ; keep this nop for ease of debugging
    POPAQ
    popfq

    sub rsp, 8          ; align RSP
    ASM_DUMP_REGISTERS
    add rsp, 8          ; restore RSP

    xor rax, rax
    inc rax             ; return true
    ret
AsmInitializeVm ENDP

; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC FRAME
    ; In oder for Windbg to display the stack trace of the guest while the
    ; VM-exit handlers are being executed, we use several tricks:
    ;   - The use of the FRAME (above) attribute. This emits a function table
    ;     entry for this function in the .pdata section. See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/proc?view=vs-2017
    ;
    ;   - The use of the .PUSHFRAME pseudo operation: This emits unwind data
    ;     indicating that a machine frame has been pushed on the stack. A machine
    ;     frame is usually pushed by the CPU in response to a trap or fault (
    ;     see: Exception- or Interrupt-Handler Procedures), hence this pseudo
    ;     operation is often used for their handler code. (In Windows kernel, the
    ;     use of this pseudo operation is often wrapped in the GENERATE_TRAP_FRAME
    ;     macro.) In our case, since VM-exit does not push the machine frame, we
    ;     manually allocate it in right above the VMM stack pointer. Nothing has
    ;     to be done in this function with regard to pushing the machine frame
    ;     since that and the VMM stack pointer are both already set up in
    ;     VmpInitializeVm. See the diagram in VmpInitializeVm for more details.
    ;     See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-pushframe?view=vs-2017
    ;
    ;   - The use of the .ALLOCSTACK pseudo operation: This also emits another
    ;     unwind data indicating how much the function uses stack. (This pseudo
    ;     code is often wrapped by the alloc_stack macro and used within the
    ;     GENERATE_TRAP_FRAME macro). This function consumes 108h of stack on
    ;     the top of the KTRAP_FRAME size (minus the machine frame size which is
    ;     already allocated outside this function). See also:
    ;     https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-allocstack?view=vs-2017
    .PUSHFRAME
    sub rsp, KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE
    .ALLOCSTACK KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 108h

    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    PUSHAQ                  ; -8 * 16
    mov rcx, rsp            ; save the "stack" parameter for VmmVmExitHandler

    ; save volatile XMM registers
    sub rsp, 68h            ; 8 for alignment
    movaps xmmword ptr [rsp +  0h], xmm0
    movaps xmmword ptr [rsp + 10h], xmm1
    movaps xmmword ptr [rsp + 20h], xmm2
    movaps xmmword ptr [rsp + 30h], xmm3
    movaps xmmword ptr [rsp + 40h], xmm4
    movaps xmmword ptr [rsp + 50h], xmm5

    sub rsp, 20h

    ; All stack allocation is done now. Indicate the end of prologue as required
    ; by the FRAME attribute.
    .ENDPROLOG

    call VmmVmExitHandler   ; bool vm_continue = VmmVmExitHandler(stack);
    add rsp, 20h

    ; restore XMM registers
    movaps xmm0, xmmword ptr [rsp +  0h]
    movaps xmm1, xmmword ptr [rsp + 10h]
    movaps xmm2, xmmword ptr [rsp + 20h]
    movaps xmm3, xmmword ptr [rsp + 30h]
    movaps xmm4, xmmword ptr [rsp + 40h]
    movaps xmm5, xmmword ptr [rsp + 50h]
    add rsp, 68h

    test al, al
    jz exitVm               ; if (!vm_continue) jmp exitVm

    POPAQ
    vmresume
    jmp vmxError

exitVm:
    ; Executes vmxoff and ends virtualization
    ;   rax = Guest's rflags
    ;   rdx = Guest's rsp
    ;   rcx = Guest's rip for the next instruction
    POPAQ
    vmxoff
    jz vmxError             ; if (ZF) jmp
    jc vmxError             ; if (CF) jmp
    push rax
    popfq                   ; rflags <= GurstFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn

vmxError:
    ; Diagnose a critical error
    pushfq
    PUSHAQ                      ; -8 * 16
    mov rcx, rsp                ; all_regs

    sub rsp, 28h                ; 28h for alignment
    call VmmVmxFailureHandler   ; VmmVmxFailureHandler(all_regs);
    add rsp, 28h
    int 3
AsmVmmEntryPoint ENDP

; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
;                                    _In_opt_ void *context);
AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP

; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP

; void __stdcall AsmInvalidateInternalCaches();
AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP

; void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);
AsmWriteCR2 PROC
    mov cr2, rcx
    ret
AsmWriteCR2 ENDP

; unsigned char __stdcall AsmInvept(
;     _In_ InvEptType invept_type,
;     _In_ const InvEptDescriptor *invept_descriptor);
AsmInvept PROC
    invept rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP

; unsigned char __stdcall AsmInvvpid(
;     _In_ InvVpidType invvpid_type,
;     _In_ const InvVpidDescriptor *invvpid_descriptor);
AsmInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


PURGE PUSHAQ
PURGE POPAQ
PURGE ASM_DUMP_REGISTERS
END
