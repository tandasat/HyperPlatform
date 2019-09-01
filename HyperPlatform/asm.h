// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to assembly functions.

#ifndef HYPERPLATFORM_ASM_H_
#define HYPERPLATFORM_ASM_H_

#include "ia32_type.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// A wrapper for vm_initialization_routine.
/// @param vm_initialization_routine  A function pointer for entering VMX-mode
/// @param context  A context parameter for vm_initialization_routine
/// @return true if vm_initialization_routine was successfully executed
bool __stdcall AsmInitializeVm(
    _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
                                           _In_opt_ void *),
    _In_opt_ void *context);

/// An entry point of VMM where gets called whenever VM-exit occurred.
void __stdcall AsmVmmEntryPoint();

/// Executes VMCALL with the given hypercall number and a context.
/// @param hypercall_number   A hypercall number
/// @param context  A context parameter for VMCALL
/// @return Equivalent to #VmxStatus
unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
                                   _In_opt_ void *context);

/// Writes to GDT
/// @param gdtr   A value to write
void __stdcall AsmWriteGDT(_In_ const Gdtr *gdtr);

/// Reads SLDT
/// @return LDT
USHORT __stdcall AsmReadLDTR();

/// Writes to TR
/// @param task_register   A value to write
void __stdcall AsmWriteTR(_In_ USHORT task_register);

/// Reads STR
/// @return TR
USHORT __stdcall AsmReadTR();

/// Writes to ES
/// @param segment_selector   A value to write
void __stdcall AsmWriteES(_In_ USHORT segment_selector);

/// Reads ES
/// @return ES
USHORT __stdcall AsmReadES();

/// Writes to CS
/// @param segment_selector   A value to write
void __stdcall AsmWriteCS(_In_ USHORT segment_selector);

/// Reads CS
/// @return CS
USHORT __stdcall AsmReadCS();

/// Writes to SS
/// @param segment_selector   A value to write
void __stdcall AsmWriteSS(_In_ USHORT segment_selector);

/// Reads SS
/// @return SS
USHORT __stdcall AsmReadSS();

/// Writes to DS
/// @param segment_selector   A value to write
void __stdcall AsmWriteDS(_In_ USHORT segment_selector);

/// Reads DS
/// @return DS
USHORT __stdcall AsmReadDS();

/// Writes to FS
/// @param segment_selector   A value to write
void __stdcall AsmWriteFS(_In_ USHORT segment_selector);

/// Reads FS
/// @return FS
USHORT __stdcall AsmReadFS();

/// Writes to GS
/// @param segment_selector   A value to write
void __stdcall AsmWriteGS(_In_ USHORT segment_selector);

/// Reads GS
/// @return GS
USHORT __stdcall AsmReadGS();

/// Loads access rights byte
/// @param segment_selector   A value to get access rights byte
/// @return An access rights byte
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

/// Invalidates internal caches
void __stdcall AsmInvalidateInternalCaches();

/// Writes to CR2
/// @param cr2_value  A value to write
void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);

/// Invalidates translations derived from EPT
/// @param invept_type  A type of invalidation
/// @param invept_descriptor  A reference to EPTP to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvept(
    _In_ InvEptType invept_type,
    _In_ const InvEptDescriptor *invept_descriptor);

/// Invalidate translations based on VPID
/// @param invvpid_type  A type of invalidation
/// @param invvpid_descriptor  A description of translations to invalidate
/// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
unsigned char __stdcall AsmInvvpid(
    _In_ InvVpidType invvpid_type,
    _In_ const InvVpidDescriptor *invvpid_descriptor);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

/// Writes to GDT
/// @param gdtr   A value to write
void _sgdt(_Out_ void *gdtr);

/// Reads SGDT
/// @param gdtr   A pointer to read GDTR
inline void __lgdt(_In_ void *gdtr) { AsmWriteGDT(static_cast<Gdtr *>(gdtr)); }

// Followings are original implementations of Microsoft VMX intrinsic functions
// which are not available on x86.
#if defined(_X86_)

/// Activates virtual machine extensions (VMX) operation in the processor
/// @param vms_support_physical_address   A pointer to a 64 bit physical address
///        that points to a virtual machine control structure(VMCS)
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_on(
    _In_ unsigned __int64 *vms_support_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vms_support_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit  0xF3
    _emit  0x0F
    _emit  0xC7
    _emit  0x34
    _emit  0x24  // VMXON [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Initializes the specified VMCS and sets its launch state to Clear
/// @param vmcs_physical_address  A pointer to a 64-bit memory location that
///        contains the physical address of the VMCS to clear
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmclear(
    _In_ unsigned __int64 *vmcs_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vmcs_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit 0x66
    _emit 0x0F
    _emit 0xc7
    _emit 0x34
    _emit 0x24  // VMCLEAR [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Places the calling application in VMX non-root operation state (VM enter)
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmlaunch() {
  FlagRegister flags = {};
  __asm {
    _emit 0x0f
    _emit 0x01
    _emit 0xc2  // VMLAUNCH

    pushfd
    pop flags.all
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  /* UNREACHABLE */
  return 0;
}

/// Loads the pointer to the current VMCS from the specified address
/// @param vmcs_physical_address  The address where the VMCS pointer is stored
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmptrld(
    _In_ unsigned __int64 *vmcs_physical_address) {
  FlagRegister flags = {};
  PHYSICAL_ADDRESS physical_address = {};
  physical_address.QuadPart = *vmcs_physical_address;
  __asm {
    push physical_address.HighPart
    push physical_address.LowPart

    _emit 0x0F
    _emit 0xC7
    _emit 0x34
    _emit 0x24  // VMPTRLD [ESP]

    pushfd
    pop flags.all

    add esp, 8
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Reads a specified field from the current VMCS
/// @param field  The VMCS field to read
/// @param field_value  A pointer to the location to store the value read from
///        the VMCS field specified by the Field parameter
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmread(_In_ size_t field,
                                  _Out_ size_t *field_value) {
  FlagRegister flags = {};
  __asm {
    pushad
    mov eax, field

    _emit 0x0F
    _emit 0x78
    _emit 0xC3  // VMREAD  EBX, EAX

    pushfd
    pop flags.all

    mov eax, field_value
    mov [eax], ebx
    popad
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

/// Writes the specified value to the specified field in the current VMCS
/// @param field  The VMCS field to write
/// @param field_value  The value to write to the VMCS field
/// @return Equivalent to #VmxStatus
inline unsigned char __vmx_vmwrite(_In_ size_t field, _In_ size_t field_value) {
  FlagRegister flags = {};
  __asm {
    pushad
    push field_value
    mov eax, field

    _emit 0x0F
    _emit 0x79
    _emit 0x04
    _emit 0x24  // VMWRITE EAX, [ESP]

    pushfd
    pop flags.all

    add esp, 4
    popad
  }
  if (flags.fields.cf) {
    return 2;
  }
  if (flags.fields.zf) {
    return 1;
  }
  return 0;
}

#endif

}  // extern "C"

#endif  // HYPERPLATFORM_ASM_H_
