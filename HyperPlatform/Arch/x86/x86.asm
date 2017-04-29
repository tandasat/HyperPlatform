; Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
; Use of this source code is governed by a MIT-style license that can be
; found in the LICENSE file.

;
; This module implements all assembler code
;
.686p
.model flat, stdcall
.MMX
.XMM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; References to C functions
;
EXTERN VmmVmExitHandler@4 : PROC
EXTERN VmmVmxFailureHandler@4 : PROC
EXTERN UtilDumpGpRegisters@8 : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; constants
;
.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Dumps all general purpose registers and a flag register.
ASM_DUMP_REGISTERS MACRO
    pushfd
    pushad                      ; -4 * 8
    mov ecx, esp                ; all_regs
    mov edx, esp
    add edx, 4*9                ; stack_pointer

    push ecx
    push edx
    call UtilDumpGpRegisters@8  ; UtilDumpGpRegisters(all_regs, stack_pointer);

    popad
    popfd
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
AsmInitializeVm PROC vm_initialization_routine, context
    pushfd
    pushad                  ; -4 * 8

    mov ecx, esp            ; esp

    ; vm_initialization_routine(rsp, asmResumeVm, context)
    push context
    push asmResumeVm
    push ecx
    call vm_initialization_routine

    popad
    popfd
    xor eax, eax            ; return false
    ret

    ; This is where the virtualized guest start to execute after successful
    ; vmlaunch.
asmResumeVm:
    nop                     ; keep this nop for ease of debugging
    popad
    popfd
    ASM_DUMP_REGISTERS
    xor eax, eax
    inc eax                 ; return true
    ret
AsmInitializeVm ENDP

; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC
    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    pushad                  ; -4 * 8
    mov eax, esp

    ; save volatile XMM registers
    sub esp, 68h            ; +8 for alignment
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0
    movaps xmmword ptr [esp +  0h], xmm0
    movaps xmmword ptr [esp + 10h], xmm1
    movaps xmmword ptr [esp + 20h], xmm2
    movaps xmmword ptr [esp + 30h], xmm3
    movaps xmmword ptr [esp + 40h], xmm4
    movaps xmmword ptr [esp + 50h], xmm5
    mov cr0, edx            ; restore the original CR0

    push eax
    call VmmVmExitHandler@4 ; bool vm_continue = VmmVmExitHandler(guest_context);

    ; restore XMM registers
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0
    movaps xmm0, xmmword ptr [esp +  0h]
    movaps xmm1, xmmword ptr [esp + 10h]
    movaps xmm2, xmmword ptr [esp + 20h]
    movaps xmm3, xmmword ptr [esp + 30h]
    movaps xmm4, xmmword ptr [esp + 40h]
    movaps xmm5, xmmword ptr [esp + 50h]
    mov cr0, edx            ; restore the original CR0
    add esp, 68h            ; +8 for alignment

    test al, al
    jz exitVm               ; if (!vm_continue) jmp exitVm

    popad
    vmresume
    jmp vmxError

exitVm:
    ; Executes vmxoff and ends virtualization
    ;   eax = Guest's eflags
    ;   edx = Guest's esp
    ;   ecx = Guest's eip for the next instruction
    popad
    vmxoff
    jz vmxError             ; if (ZF) jmp
    jc vmxError             ; if (CF) jmp
    push eax
    popfd                   ; eflags <= GurstFlags
    mov esp, edx            ; esp <= GuestRsp
    push ecx
    ret                     ; jmp AddressToReturn

vmxError:
    ; Diagnose a critical error
    pushfd
    pushad                      ; -4 * 8
    mov ecx, esp                ; all_regs
    push ecx
    call VmmVmxFailureHandler@4 ; VmmVmxFailureHandler(all_regs);
    int 3
AsmVmmEntryPoint ENDP

; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
;                                    _In_opt_ void *context);
AsmVmxCall PROC hypercall_number, context
    mov ecx, hypercall_number
    mov edx, context
    vmcall                  ; vmcall(hypercall_number, context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP

; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC gdtr
    mov ecx, gdtr
    lgdt fword ptr [ecx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmReadGDT(_Out_ GDTR *gdtr);
AsmReadGDT PROC gdtr
    mov ecx, gdtr
    sgdt [ecx]
    ret
AsmReadGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC local_segmeng_selector
    mov ecx, local_segmeng_selector
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC task_register
    mov ecx, task_register
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC segment_selector
    mov ecx, segment_selector
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC segment_selector
    mov ecx, segment_selector
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC segment_selector
    mov ecx, segment_selector
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC segment_selector
    mov ecx, segment_selector
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC segment_selector
    mov ecx, segment_selector
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC segment_selector
    mov ecx, segment_selector
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(
;    _In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC segment_selector
    mov ecx, segment_selector
    lar eax, ecx
    ret
AsmLoadAccessRightsByte ENDP

; void __stdcall AsmInvalidateInternalCaches();
AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP

; void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);
AsmWriteCR2 PROC cr2_value
    mov ecx, cr2_value
    mov cr2, ecx
    ret
AsmWriteCR2 ENDP

; unsigned char __stdcall AsmInvept(
;     _In_ InvEptType invept_type,
;     _In_ const InvEptDescriptor *invept_descriptor);
AsmInvept PROC invept_type, invept_descriptor
    mov ecx, invept_type
    mov edx, invept_descriptor
    ; invept  ecx, oword ptr [edx]
    db  66h, 0fh, 38h, 80h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP

; unsigned char __stdcall AsmInvvpid(
;     _In_ InvVpidType invvpid_type,
;     _In_ const InvVpidDescriptor *invvpid_descriptor);
AsmInvvpid PROC invvpid_type, invvpid_descriptor
    mov ecx, invvpid_type
    mov edx, invvpid_descriptor
    ; invvpid  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 81h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor eax, eax            ; return VMX_OK
    ret

errorWithoutCode:
    mov eax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov eax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


PURGE ASM_DUMP_REGISTERS
END
