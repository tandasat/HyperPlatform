; Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
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
KTRAP_FRAME_SIZE            EQU     8ch
MACHINE_FRAME_SIZE          EQU     14h
; The frap frame type
; https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_fpo_data
FRAME_TRAP                  EQU     1

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
    ; This .FPO directive emits debug information that helps Windbg construct
    ; the stack trace of the guest while the VM-exit handlers are being executed.
    ;
    ; This directive emits information about the frame pointer optimization (FPO)
    ; for this function, precisely, how the stack frame of this function is
    ; constructed. This information is referred to as the frame type, and we set
    ; the trap frame type for this function as FRAME_TRAP. When Windbg encouters
    ; such a function while constructng the stack trace, it interprets the value
    ; at ebp as an address of the KTRAP_FRAME structure and reads its Eip and
    ; HardwareEsp fields to find a return address, instead of using the value at
    ; ebp+4 as it normally would (when the frame type is non-FPO).
    ;
    ; On Windows, this frame type is often used in an interrupt handler, and an
    ; interrupt handler builds the frame, that is KTRAP_FRAME, first. This is
    ; done by, first, the processor pushing eip, cs, eflags, esp, and ss, which
    ; are referred to as the machine frame, into the stack prior to execution of
    ; the interrup handler, then the handler pushing the rest of register values
    ; to form the complete KTRAP_FRAME structure (this part is wrappered in the
    ; ENTER_TRAP macro). We emulate this behaviour; by the time AsmVmmEntryPoint
    ; is executed, the machine frame is already allocated right above the VMM
    ; stack pointer, and then, the rest of space to form the KTRAP_FRAME structue
    ; is allocated by the first adjustment of esp (hence, KTRAP_FRAME_SIZE minus
    ; MACHINE_FRAME_SIZE). Then, only necessary fields, that are Eip and
    ; HardwareEsp, are updated later in VmmVmExitHandler.
    ;
    ; Note that the FPO directive takes five other parameters. See:
    ; https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-fpo?view=vs-2017
    ; However, they are not used by Windbg to constuct the stack trace.
    ;
    ; The FPO information emitted by this directive can be confirmd with the
    ; kv or .fnent commands on Windbg. See:
    ; https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/k--kb--kc--kd--kp--kp--kv--display-stack-backtrace-
    ; https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-fnent--display-function-data-
    ;
    ; NB: Windbg did not correctly construct the stack frame when any other
    ;     frame types were used (with various combinations of other parameters).
    ;     It appeared that Windbg stopped walking through the ebp-chain when one
    ;     of them points to far away from the current and started to search a
    ;     correct-looking value from nearby memory by assuming that the stack
    ;     was corrupt.
    ;
    ; Finally, this directive always emits the below warning and, it is reported
    ; as an issue of Visual Studio:
    ;   warning A5000: @@: label defined but not referenced
    ; https://developercommunity.visualstudio.com/content/problem/349442/the-fpo-directive-always-emits-false-warning-a5000.html
    .FPO(0, 0, 0, 0, 0, FRAME_TRAP)

    ; "Push" the KTRAP_FRAME structure. The values are uninitilized but unused
    ; anyway, except for Eip and HardwareEsp that are updated later. This esp
    ; does not have to be restored because the guest esp is restored from VMCS
    ; on VMRESUME or manually with the MOV instruction after VMXOFF (see below
    ; the exitVm label).
    sub esp, KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE

    ; No need to save the flag registers since it is restored from the VMCS at
    ; the time of vmresume.
    pushad                  ; -4 * 8
    mov eax, esp            ; save the "stack" parameter for VmmVmExitHandler
    mov ebp, eax
    add ebp, 4*8            ; update EBP to point to the KTRAP_FRAME

    ; prior to touching XMM registers, must make sure that does not cause #GP
    sub esp, 60h
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0

    ; save volatile XMM registers
    movaps xmmword ptr [esp +  0h], xmm0
    movaps xmmword ptr [esp + 10h], xmm1
    movaps xmmword ptr [esp + 20h], xmm2
    movaps xmmword ptr [esp + 30h], xmm3
    movaps xmmword ptr [esp + 40h], xmm4
    movaps xmmword ptr [esp + 50h], xmm5
    mov cr0, edx            ; restore the original CR0

    push eax
    call VmmVmExitHandler@4 ; bool vm_continue = VmmVmExitHandler(stack);

    ; prior to touching XMM registers, must make sure that does not cause #GP
    mov ecx, cr0
    mov edx, ecx            ; save original CR0
    and cl, 0f1h            ; clear MP, EM, TS bits for floating point access
    mov cr0, ecx            ; update CR0

    ; restore XMM registers
    movaps xmm0, xmmword ptr [esp +  0h]
    movaps xmm1, xmmword ptr [esp + 10h]
    movaps xmm2, xmmword ptr [esp + 20h]
    movaps xmm3, xmmword ptr [esp + 30h]
    movaps xmm4, xmmword ptr [esp + 40h]
    movaps xmm5, xmmword ptr [esp + 50h]
    mov cr0, edx            ; restore the original CR0
    add esp, 60h

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
    invept ecx, oword ptr [edx]
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
    invvpid ecx, oword ptr [edx]
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
