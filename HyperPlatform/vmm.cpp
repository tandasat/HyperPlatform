// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements VMM functions.

#include "vmm.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif  // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "performance.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Whether VM-exit recording is enabled
static const long kVmmpEnableRecordVmExit = false;

// How many events should be recorded per a processor
static const long kVmmpNumberOfRecords = 100;

// How many processors are supported for recording
static const long kVmmpNumberOfProcessors = 2;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

// Represents raw structure of stack of VMM when VmmVmExitHandler() is called
struct VmmInitialStack {
  GpRegisters gp_regs;
  ULONG_PTR reserved;
  ProcessorData *processor_data;
};

// Things need to be read and written by each VM-exit handler
struct GuestContext {
  union {
    VmmInitialStack *stack;
    GpRegisters *gp_regs;
  };
  FlagRegister flag_reg;
  ULONG_PTR ip;
  ULONG_PTR cr8;
  KIRQL irql;
  bool vm_continue;
};
#if defined(_AMD64_)
static_assert(sizeof(GuestContext) == 40, "Size check");
#else
static_assert(sizeof(GuestContext) == 20, "Size check");
#endif

// Context at the moment of vmexit
struct VmExitHistory {
  GpRegisters gp_regs;
  ULONG_PTR ip;
  VmExitInformation exit_reason;
  ULONG_PTR exit_qualification;
  ULONG_PTR instruction_info;
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

bool __stdcall VmmVmExitHandler(_Inout_ VmmInitialStack *stack);

DECLSPEC_NORETURN void __stdcall VmmVmxFailureHandler(
    _Inout_ AllRegisters *all_regs);

static void VmmpHandleVmExit(_Inout_ GuestContext *guest_context);

DECLSPEC_NORETURN static void VmmpHandleTripleFault(
    _Inout_ GuestContext *guest_context);

DECLSPEC_NORETURN static void VmmpHandleUnexpectedExit(
    _Inout_ GuestContext *guest_context);

static void VmmpHandleMonitorTrap(_Inout_ GuestContext *guest_context);

static void VmmpHandleException(_Inout_ GuestContext *guest_context);

static void VmmpHandleCpuid(_Inout_ GuestContext *guest_context);

static void VmmpHandleRdtsc(_Inout_ GuestContext *guest_context);

static void VmmpHandleRdtscp(_Inout_ GuestContext *guest_context);

static void VmmpHandleXsetbv(_Inout_ GuestContext *guest_context);

static void VmmpHandleMsrReadAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleMsrWriteAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleMsrAccess(_Inout_ GuestContext *guest_context,
                                _In_ bool read_access);

static void VmmpHandleGdtrOrIdtrAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleLdtrOrTrAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleDrAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleCrAccess(_Inout_ GuestContext *guest_context);

static void VmmpHandleVmx(_Inout_ GuestContext *guest_context);

static void VmmpHandleVmCall(_Inout_ GuestContext *guest_context);

static void VmmpHandleInvalidateInternalCaches(
    _Inout_ GuestContext *guest_context);

static void VmmpHandleInvalidateTLBEntry(_Inout_ GuestContext *guest_context);

static void VmmpHandleEptViolation(_Inout_ GuestContext *guest_context);

static void VmmpHandleEptMisconfig(_Inout_ GuestContext *guest_context);

static ULONG_PTR *VmmpSelectRegister(_In_ ULONG index,
                                     _In_ GuestContext *guest_context);

static void VmmpDumpGuestSelectors();

static void VmmpAdjustGuestInstructionPointer(_In_ ULONG_PTR guest_ip);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// Those variables are all for diagnostic purpose
static ULONG g_vmmp_next_history_index[kVmmpNumberOfProcessors];
static VmExitHistory g_vmmp_vm_exit_history[kVmmpNumberOfProcessors]
                                           [kVmmpNumberOfRecords];

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A high level VMX handler called from AsmVmExitHandler().
// Return true for vmresume, or return false for vmxoff.
#pragma warning(push)
#pragma warning(disable : 28167)
_Use_decl_annotations_ bool __stdcall VmmVmExitHandler(VmmInitialStack *stack) {
  // Save guest's context and raise IRQL as quick as possible
  const auto guest_irql = KeGetCurrentIrql();
  const auto guest_cr8 = IsX64() ? __readcr8() : 0;
  if (guest_irql < DISPATCH_LEVEL) {
    KeRaiseIrqlToDpcLevel();
  }
  NT_ASSERT(stack->reserved == MAXULONG_PTR);

  // Capture the current guest state
  GuestContext guest_context = {stack,
                                UtilVmRead(VmcsField::kGuestRflags),
                                UtilVmRead(VmcsField::kGuestRip),
                                guest_cr8,
                                guest_irql,
                                true};
  guest_context.gp_regs->sp = UtilVmRead(VmcsField::kGuestRsp);

  // Dispatch the current VM-exit event
  VmmpHandleVmExit(&guest_context);

  // Restore guest's context
  if (guest_context.irql < DISPATCH_LEVEL) {
    KeLowerIrql(guest_context.irql);
  }

  // Apply possibly updated CR8 by the handler
  if (IsX64()) {
    __writecr8(guest_context.cr8);
  }
  return guest_context.vm_continue;
}
#pragma warning(pop)

// Dispatches VM-exit to a corresponding handler
_Use_decl_annotations_ static void VmmpHandleVmExit(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

  const VmExitInformation exit_reason = {
      static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason))};

  if (kVmmpEnableRecordVmExit) {
    // Save them for ease of trouble shooting
    const auto processor = KeGetCurrentProcessorNumberEx(nullptr);
    auto &index = g_vmmp_next_history_index[processor];
    auto &history = g_vmmp_vm_exit_history[processor][index];

    history.gp_regs = *guest_context->gp_regs;
    history.ip = guest_context->ip;
    history.exit_reason = exit_reason;
    history.exit_qualification = UtilVmRead(VmcsField::kExitQualification);
    history.instruction_info = UtilVmRead(VmcsField::kVmxInstructionInfo);
    if (++index == kVmmpNumberOfRecords) {
      index = 0;
    }
  }

  switch (exit_reason.fields.reason) {
    case VmxExitReason::kExceptionOrNmi:
      VmmpHandleException(guest_context);
      break;
    case VmxExitReason::kTripleFault:
      VmmpHandleTripleFault(guest_context);
      break;
    case VmxExitReason::kCpuid:
      VmmpHandleCpuid(guest_context);
      break;
    case VmxExitReason::kInvd:
      VmmpHandleInvalidateInternalCaches(guest_context);
      break;
    case VmxExitReason::kInvlpg:
      VmmpHandleInvalidateTLBEntry(guest_context);
      break;
    case VmxExitReason::kRdtsc:
      VmmpHandleRdtsc(guest_context);
      break;
    case VmxExitReason::kCrAccess:
      VmmpHandleCrAccess(guest_context);
      break;
    case VmxExitReason::kDrAccess:
      VmmpHandleDrAccess(guest_context);
      break;
    case VmxExitReason::kMsrRead:
      VmmpHandleMsrReadAccess(guest_context);
      break;
    case VmxExitReason::kMsrWrite:
      VmmpHandleMsrWriteAccess(guest_context);
      break;
    case VmxExitReason::kMonitorTrapFlag:
      VmmpHandleMonitorTrap(guest_context);
      break;
    case VmxExitReason::kGdtrOrIdtrAccess:
      VmmpHandleGdtrOrIdtrAccess(guest_context);
      break;
    case VmxExitReason::kLdtrOrTrAccess:
      VmmpHandleLdtrOrTrAccess(guest_context);
      break;
    case VmxExitReason::kEptViolation:
      VmmpHandleEptViolation(guest_context);
      break;
    case VmxExitReason::kEptMisconfig:
      VmmpHandleEptMisconfig(guest_context);
      break;
    case VmxExitReason::kVmcall:
      VmmpHandleVmCall(guest_context);
      break;
    case VmxExitReason::kVmclear:
    case VmxExitReason::kVmlaunch:
    case VmxExitReason::kVmptrld:
    case VmxExitReason::kVmptrst:
    case VmxExitReason::kVmread:
    case VmxExitReason::kVmresume:
    case VmxExitReason::kVmwrite:
    case VmxExitReason::kVmoff:
    case VmxExitReason::kVmon:
      VmmpHandleVmx(guest_context);
      break;
    case VmxExitReason::kRdtscp:
      VmmpHandleRdtscp(guest_context);
      break;
    case VmxExitReason::kXsetbv:
      VmmpHandleXsetbv(guest_context);
      break;
    default:
      VmmpHandleUnexpectedExit(guest_context);
      break;
  }
}

// Triple fault VM-exit. Fatal error.
_Use_decl_annotations_ static void VmmpHandleTripleFault(
    GuestContext *guest_context) {
  VmmpDumpGuestSelectors();
  HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kTripleFaultVmExit,
                                 reinterpret_cast<ULONG_PTR>(guest_context),
                                 guest_context->ip, 0);
}

// Unexpected VM-exit. Fatal error.
_Use_decl_annotations_ static void VmmpHandleUnexpectedExit(
    GuestContext *guest_context) {
  VmmpDumpGuestSelectors();
  HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmExit,
                                 reinterpret_cast<ULONG_PTR>(guest_context), 0,
                                 0);
}

// MTF VM-exit
_Use_decl_annotations_ static void VmmpHandleMonitorTrap(
    GuestContext *guest_context) {
  VmmpDumpGuestSelectors();
  HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmExit,
                                 reinterpret_cast<ULONG_PTR>(guest_context), 0,
                                 0);
}

// Interrupt
_Use_decl_annotations_ static void VmmpHandleException(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const VmExitInterruptionInformationField exception = {
      static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo))};

  if (static_cast<interruption_type>(exception.fields.interruption_type) ==
      interruption_type::kHardwareException) {
    // Hardware exception
    if (static_cast<InterruptionVector>(exception.fields.vector) ==
        InterruptionVector::kPageFaultException) {
      // #PF
      const PageFaultErrorCode fault_code = {
          static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode))};
      const auto fault_address = UtilVmRead(VmcsField::kExitQualification);

      VmEntryInterruptionInformationField inject = {};
      inject.fields.interruption_type = exception.fields.interruption_type;
      inject.fields.vector = exception.fields.vector;
      inject.fields.deliver_error_code = true;
      inject.fields.valid = true;
      AsmWriteCR2(fault_address);
      UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, fault_code.all);
      UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);
      HYPERPLATFORM_LOG_INFO_SAFE("GuestIp= %p, #PF Fault= %p Code= 0x%2x",
                                  guest_context->ip, fault_address, fault_code);

    } else if (static_cast<InterruptionVector>(exception.fields.vector) ==
               InterruptionVector::kGeneralProtectionException) {
      // # GP
      const auto error_code =
          static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode));

      VmEntryInterruptionInformationField inject = {};
      inject.fields.interruption_type = exception.fields.interruption_type;
      inject.fields.vector = exception.fields.vector;
      inject.fields.deliver_error_code = true;
      inject.fields.valid = true;
      UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, error_code);
      UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);
      HYPERPLATFORM_LOG_INFO_SAFE("GuestIp= %p, #GP Code= 0x%2x",
                                  guest_context->ip, error_code);

    } else {
      HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                     0);
    }

  } else if (static_cast<interruption_type>(
                 exception.fields.interruption_type) ==
             interruption_type::kSoftwareException) {
    // Software exception
    if (static_cast<InterruptionVector>(exception.fields.vector) ==
        InterruptionVector::kBreakpointException) {
      // #BP
      VmEntryInterruptionInformationField inject = {};
      inject.fields.interruption_type = exception.fields.interruption_type;
      inject.fields.vector = exception.fields.vector;
      inject.fields.deliver_error_code = false;
      inject.fields.valid = true;
      UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);
      UtilVmWrite(VmcsField::kVmEntryInstructionLen, 1);
      HYPERPLATFORM_LOG_INFO_SAFE("GuestIp= %p, #BP ", guest_context->ip);

    } else {
      HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                     0);
    }
  } else {
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                   0);
  }
}

// CPUID
_Use_decl_annotations_ static void VmmpHandleCpuid(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  unsigned int cpu_info[4] = {};
  const auto function_id = static_cast<int>(guest_context->gp_regs->ax);
  const auto sub_function_id = static_cast<int>(guest_context->gp_regs->cx);

  if (function_id == 0 && sub_function_id == kHyperPlatformVmmBackdoorCode) {
    // Say "Pong by VMM!" when the back-door code was given
    guest_context->gp_regs->bx = 'gnoP';
    guest_context->gp_regs->dx = ' yb ';
    guest_context->gp_regs->cx = '!MMV';
  } else {
    __cpuidex(reinterpret_cast<int *>(cpu_info), function_id, sub_function_id);
    guest_context->gp_regs->ax = cpu_info[0];
    guest_context->gp_regs->bx = cpu_info[1];
    guest_context->gp_regs->cx = cpu_info[2];
    guest_context->gp_regs->dx = cpu_info[3];
  }

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// RDTSC
_Use_decl_annotations_ static void VmmpHandleRdtsc(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  ULARGE_INTEGER tsc = {};
  tsc.QuadPart = __rdtsc();
  guest_context->gp_regs->dx = tsc.HighPart;
  guest_context->gp_regs->ax = tsc.LowPart;

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// RDTSCP
_Use_decl_annotations_ static void VmmpHandleRdtscp(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  unsigned int tsc_aux = 0;
  ULARGE_INTEGER tsc = {};
  tsc.QuadPart = __rdtscp(&tsc_aux);
  guest_context->gp_regs->dx = tsc.HighPart;
  guest_context->gp_regs->ax = tsc.LowPart;
  guest_context->gp_regs->cx = tsc_aux;

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// XSETBV. It is executed at the time of system resuming
_Use_decl_annotations_ static void VmmpHandleXsetbv(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  ULARGE_INTEGER value = {};
  value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
  value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
  _xsetbv(static_cast<ULONG>(guest_context->gp_regs->cx), value.QuadPart);

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// RDMSR
_Use_decl_annotations_ static void VmmpHandleMsrReadAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  VmmpHandleMsrAccess(guest_context, true);
}

// WRMSR
_Use_decl_annotations_ static void VmmpHandleMsrWriteAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  VmmpHandleMsrAccess(guest_context, false);
}

// RDMSR and WRMSR
_Use_decl_annotations_ static void VmmpHandleMsrAccess(
    GuestContext *guest_context, bool read_access) {
  // Apply it for VMCS instead of a real MSR if a speficied MSR is either of
  // them.
  const auto msr = static_cast<Msr>(guest_context->gp_regs->cx);

  bool transfer_to_vmcs = false;
  VmcsField vmcs_field = {};
  switch (msr) {
    case Msr::kIa32SysenterCs:
      vmcs_field = VmcsField::kGuestSysenterCs;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32SysenterEsp:
      vmcs_field = VmcsField::kGuestSysenterEsp;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32SysenterEip:
      vmcs_field = VmcsField::kGuestSysenterEip;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32GsBase:
      vmcs_field = VmcsField::kGuestGsBase;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32FsBase:
      vmcs_field = VmcsField::kGuestFsBase;
      break;
    default:
      break;
  }
  // Do not shadow 64bit fields because the current implmentation for x86 is not
  // able to handle it due to a simple use of UtilVmWrite() below.
  NT_ASSERT(UtilIsInBounds(vmcs_field, VmcsField::kIoBitmapA,
                           VmcsField::kHostIa32PerfGlobalCtrlHigh) == false);

  LARGE_INTEGER msr_value = {};
  if (read_access) {
    if (transfer_to_vmcs) {
      msr_value.QuadPart = UtilVmRead(vmcs_field);
    } else {
      msr_value.QuadPart = UtilReadMsr64(msr);
    }
    guest_context->gp_regs->ax = msr_value.LowPart;
    guest_context->gp_regs->dx = msr_value.HighPart;
  } else {
    msr_value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
    msr_value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
    if (transfer_to_vmcs) {
      UtilVmWrite(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
    } else {
      UtilWriteMsr64(msr, msr_value.QuadPart);
    }
  }

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// LIDT, SIDT, LGDT and SGDT
_Use_decl_annotations_ static void VmmpHandleGdtrOrIdtrAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const GdtrOrIdtrAccessQualification exit_qualification = {
      static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo))};

  // Calculate an address to be used for the instruction
  const auto displacement = UtilVmRead(VmcsField::kExitQualification);

  // Base
  ULONG_PTR base_value = 0;
  if (!exit_qualification.fields.base_register_invalid) {
    const auto register_used = VmmpSelectRegister(
        exit_qualification.fields.base_register, guest_context);
    base_value = *register_used;
  }

  // Index
  ULONG_PTR index_value = 0;
  if (!exit_qualification.fields.index_register_invalid) {
    const auto register_used = VmmpSelectRegister(
        exit_qualification.fields.index_register, guest_context);
    index_value = *register_used;
    switch (
        static_cast<GdtrOrIdtrScaling>(exit_qualification.fields.scalling)) {
      case GdtrOrIdtrScaling::kNoScaling:
        index_value = index_value;
        break;
      case GdtrOrIdtrScaling::kScaleBy2:
        index_value = index_value * 2;
        break;
      case GdtrOrIdtrScaling::kScaleBy4:
        index_value = index_value * 4;
        break;
      case GdtrOrIdtrScaling::kScaleBy8:
        index_value = index_value * 8;
        break;
      default:
        break;
    }
  }

  auto operation_address = base_value + index_value + displacement;
  if (static_cast<GdtrOrIdtrAaddressSize>(
          exit_qualification.fields.address_size) ==
      GdtrOrIdtrAaddressSize::k32bit) {
    operation_address &= MAXULONG;
  }

  // Update CR3 with that of the guest since below code is going to access
  // memory.
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto vmm_cr3 = __readcr3();
  __writecr3(guest_cr3);

  // Emulate the instruction
  auto descriptor_table_reg = reinterpret_cast<Idtr *>(operation_address);
  switch (static_cast<GdtrOrIdtrInstructionIdentity>(
      exit_qualification.fields.instruction_identity)) {
    case GdtrOrIdtrInstructionIdentity::kSgdt:
      descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestGdtrBase);
      descriptor_table_reg->limit =
          static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestGdtrLimit));
      break;
    case GdtrOrIdtrInstructionIdentity::kSidt:
      descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestIdtrBase);
      descriptor_table_reg->limit =
          static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestIdtrLimit));
      break;
    case GdtrOrIdtrInstructionIdentity::kLgdt:
      UtilVmWrite(VmcsField::kGuestGdtrBase, descriptor_table_reg->base);
      UtilVmWrite(VmcsField::kGuestGdtrLimit, descriptor_table_reg->limit);
      break;
    case GdtrOrIdtrInstructionIdentity::kLidt:
      UtilVmWrite(VmcsField::kGuestIdtrBase, descriptor_table_reg->base);
      UtilVmWrite(VmcsField::kGuestIdtrLimit, descriptor_table_reg->limit);
      break;
  }

  __writecr3(vmm_cr3);
  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// LLDT, LTR, SLDT, and STR
_Use_decl_annotations_ static void VmmpHandleLdtrOrTrAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const LdtrOrTrAccessQualification exit_qualification = {
      static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo))};

  // Calculate an address or a register to be used for the instruction
  const auto displacement = UtilVmRead(VmcsField::kExitQualification);

  ULONG_PTR operation_address = 0;
  if (exit_qualification.fields.register_access) {
    // Register
    const auto register_used =
        VmmpSelectRegister(exit_qualification.fields.register1, guest_context);
    operation_address = reinterpret_cast<ULONG_PTR>(register_used);
  } else {
    // Base
    ULONG_PTR base_value = 0;
    if (!exit_qualification.fields.base_register_invalid) {
      const auto register_used = VmmpSelectRegister(
          exit_qualification.fields.base_register, guest_context);
      base_value = *register_used;
    }

    // Index
    ULONG_PTR index_value = 0;
    if (!exit_qualification.fields.index_register_invalid) {
      const auto register_used = VmmpSelectRegister(
          exit_qualification.fields.index_register, guest_context);
      index_value = *register_used;
      switch (
          static_cast<GdtrOrIdtrScaling>(exit_qualification.fields.scalling)) {
        case GdtrOrIdtrScaling::kNoScaling:
          index_value = index_value;
          break;
        case GdtrOrIdtrScaling::kScaleBy2:
          index_value = index_value * 2;
          break;
        case GdtrOrIdtrScaling::kScaleBy4:
          index_value = index_value * 4;
          break;
        case GdtrOrIdtrScaling::kScaleBy8:
          index_value = index_value * 8;
          break;
        default:
          break;
      }
    }

    operation_address = base_value + index_value + displacement;
    if (static_cast<GdtrOrIdtrAaddressSize>(
            exit_qualification.fields.address_size) ==
        GdtrOrIdtrAaddressSize::k32bit) {
      operation_address &= MAXULONG;
    }
  }

  // Update CR3 with that of the guest since below code is going to access
  // memory.
  const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
  const auto vmm_cr3 = __readcr3();
  __writecr3(guest_cr3);

  // Emulate the instruction
  auto selector = reinterpret_cast<USHORT *>(operation_address);
  switch (static_cast<LdtrOrTrInstructionIdentity>(
      exit_qualification.fields.instruction_identity)) {
    case LdtrOrTrInstructionIdentity::kSldt:
      *selector =
          static_cast<USHORT>(UtilVmRead(VmcsField::kGuestLdtrSelector));
      break;
    case LdtrOrTrInstructionIdentity::kStr:
      *selector = static_cast<USHORT>(UtilVmRead(VmcsField::kGuestTrSelector));
      break;
    case LdtrOrTrInstructionIdentity::kLldt:
      UtilVmWrite(VmcsField::kGuestLdtrSelector, *selector);
      break;
    case LdtrOrTrInstructionIdentity::kLtr:
      UtilVmWrite(VmcsField::kGuestTrSelector, *selector);
      break;
  }

  __writecr3(vmm_cr3);
  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// MOV to / from DRx
_Use_decl_annotations_ static void VmmpHandleDrAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const MovDrQualification exit_qualification = {
      UtilVmRead(VmcsField::kExitQualification)};
  const auto register_used =
      VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

  // Emulate the instruction
  switch (static_cast<MovDrDirection>(exit_qualification.fields.direction)) {
    case MovDrDirection::kMoveToDr:
      // clang-format off
      switch (exit_qualification.fields.debugl_register) {
        case 0: __writedr(0, *register_used); break;
        case 1: __writedr(1, *register_used); break;
        case 2: __writedr(2, *register_used); break;
        case 3: __writedr(3, *register_used); break;
        case 4: __writedr(4, *register_used); break;
        case 5: __writedr(5, *register_used); break;
        case 6: __writedr(6, *register_used); break;
        case 7: __writedr(7, *register_used); break;
        default: break;
      }
      // clang-format on
      break;
    case MovDrDirection::kMoveFromDr:
      // clang-format off
      switch (exit_qualification.fields.debugl_register) {
        case 0: *register_used = __readdr(0); break;
        case 1: *register_used = __readdr(1); break;
        case 2: *register_used = __readdr(2); break;
        case 3: *register_used = __readdr(3); break;
        case 4: *register_used = __readdr(4); break;
        case 5: *register_used = __readdr(5); break;
        case 6: *register_used = __readdr(6); break;
        case 7: *register_used = __readdr(7); break;
        default: break;
      }
      // clang-format on
      break;
    default:
      HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
                                     0);
      break;
  }

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// MOV to / from CRx
_Use_decl_annotations_ static void VmmpHandleCrAccess(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const MovCrQualification exit_qualification = {
      UtilVmRead(VmcsField::kExitQualification)};

  const auto register_used =
      VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

  switch (static_cast<MovCrAccessType>(exit_qualification.fields.access_type)) {
    case MovCrAccessType::kMoveToCr:
      switch (exit_qualification.fields.control_register) {
        // CR0 <- Reg
        case 0: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          if (UtilIsX86Pae()) {
            UtilLoadPdptes(UtilVmRead(VmcsField::kGuestCr3));
          }
          UtilVmWrite(VmcsField::kGuestCr0, *register_used);
          UtilVmWrite(VmcsField::kCr0ReadShadow, *register_used);
          break;
        }

        // CR3 <- Reg
        case 3: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          if (UtilIsX86Pae()) {
            UtilLoadPdptes(*register_used);
          }
          UtilVmWrite(VmcsField::kGuestCr3, *register_used);
          break;
        }

        // CR4 <- Reg
        case 4: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          if (UtilIsX86Pae()) {
            UtilLoadPdptes(UtilVmRead(VmcsField::kGuestCr3));
          }
          UtilVmWrite(VmcsField::kGuestCr4, *register_used);
          UtilVmWrite(VmcsField::kCr4ReadShadow, *register_used);
          break;
        }

        // CR8 <- Reg
        case 8: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          guest_context->cr8 = *register_used;
          break;
        }

        default:
          HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
                                         0, 0);
          break;
      }
      break;

    case MovCrAccessType::kMoveFromCr:
      switch (exit_qualification.fields.control_register) {
        // Reg <- CR3
        case 3: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          *register_used = UtilVmRead(VmcsField::kGuestCr3);
          break;
        }

        // Reg <- CR8
        case 8: {
          HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
          *register_used = guest_context->cr8;
          break;
        }

        default:
          HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
                                         0, 0);
          break;
      }
      break;

    // Unimplemented
    case MovCrAccessType::kClts:
    case MovCrAccessType::kLmsw:
    default:
      HYPERPLATFORM_COMMON_DBG_BREAK();
      break;
  }

  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// VMX instructions except for VMCALL
_Use_decl_annotations_ static void VmmpHandleVmx(GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  guest_context->flag_reg.fields.cf = true;  // Error without status
  guest_context->flag_reg.fields.pf = false;
  guest_context->flag_reg.fields.af = false;
  guest_context->flag_reg.fields.zf = false;  // Error without status
  guest_context->flag_reg.fields.sf = false;
  guest_context->flag_reg.fields.of = false;
  UtilVmWrite(VmcsField::kGuestRflags, guest_context->flag_reg.all);
  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// VMCALL
_Use_decl_annotations_ static void VmmpHandleVmCall(
    GuestContext *guest_context) {
  // VMCALL for Sushi expects that cx holds a command number, and dx holds an
  // address of a context parameter optionally
  const auto hypercall_number =
      static_cast<HypercallNumber>(guest_context->gp_regs->cx);
  const auto context = reinterpret_cast<void *>(guest_context->gp_regs->dx);

  if (hypercall_number == HypercallNumber::kTerminateVmm) {
    // Unloading requested
    HYPERPLATFORM_COMMON_DBG_BREAK();

    // The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
    // It is not correct value but fine to ignore since vmresume loads correct
    // values from VMCS. But here, we are going to skip vmresume and simply
    // return to where VMCALL is executed. It results in keeping those broken
    // values and ends up with bug check 109, so we should fix them manually.
    const auto gdt_limit = UtilVmRead(VmcsField::kGuestGdtrLimit);
    const auto gdt_base = UtilVmRead(VmcsField::kGuestGdtrBase);
    const auto idt_limit = UtilVmRead(VmcsField::kGuestIdtrLimit);
    const auto idt_base = UtilVmRead(VmcsField::kGuestIdtrBase);
    Gdtr gdtr = {static_cast<USHORT>(gdt_limit), gdt_base};
    Idtr idtr = {static_cast<USHORT>(idt_limit), idt_base};
    __lgdt(&gdtr);
    __lidt(&idtr);

    // Store an address of the management structure to the context parameter
    const auto result_ptr = reinterpret_cast<ProcessorData **>(context);
    *result_ptr = guest_context->stack->processor_data;
    HYPERPLATFORM_LOG_DEBUG_SAFE("Context at %p %p", context,
                                 guest_context->stack->processor_data);

    // Set rip to the next instruction of VMCALL
    const auto exit_instruction_length =
        UtilVmRead(VmcsField::kVmExitInstructionLen);
    const auto return_address = guest_context->ip + exit_instruction_length;

    // Since rflags is overwritten after VMXOFF, we should manually indicates
    // that VMCALL was successful by clearing those flags.
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.zf = false;

    // Set registers used after VMXOFF to recover the context. Volatile
    // registers must be used because those changes are reflected to the
    // guest's context after VMXOFF.
    guest_context->gp_regs->cx = return_address;
    guest_context->gp_regs->dx = guest_context->gp_regs->sp;
    guest_context->gp_regs->ax = guest_context->flag_reg.all;
    guest_context->vm_continue = false;

  } else {
    // Unsupported hypercall. Handle like other VMX instructions
    VmmpHandleVmx(guest_context);
  }
}

// INVD
_Use_decl_annotations_ static void VmmpHandleInvalidateInternalCaches(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  AsmInvalidateInternalCaches();
  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// INVLPG
_Use_decl_annotations_ static void VmmpHandleInvalidateTLBEntry(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  const auto invalidate_address =
      reinterpret_cast<void *>(UtilVmRead(VmcsField::kExitQualification));
  __invlpg(invalidate_address);
  VmmpAdjustGuestInstructionPointer(guest_context->ip);
}

// EXIT_REASON_EPT_VIOLATION
_Use_decl_annotations_ static void VmmpHandleEptViolation(
    GuestContext *guest_context) {
  HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
  auto processor_data = guest_context->stack->processor_data;
  EptHandleEptViolation(processor_data->ept_data);
}

// EXIT_REASON_EPT_MISCONFIG
_Use_decl_annotations_ static void VmmpHandleEptMisconfig(
    GuestContext *guest_context) {
  UNREFERENCED_PARAMETER(guest_context);

  const auto fault_address = UtilVmRead(VmcsField::kGuestPhysicalAddress);
  const auto ept_pt_entry = EptGetEptPtEntry(
      guest_context->stack->processor_data->ept_data, fault_address);
  HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kEptMisconfigVmExit,
                                 fault_address,
                                 reinterpret_cast<ULONG_PTR>(ept_pt_entry), 0);
}

// Selects a register to be used based on the index
_Use_decl_annotations_ static ULONG_PTR *VmmpSelectRegister(
    ULONG index, GuestContext *guest_context) {
  ULONG_PTR *register_used = nullptr;
  // clang-format off
  switch (index) {
    case 0: register_used = &guest_context->gp_regs->ax; break;
    case 1: register_used = &guest_context->gp_regs->cx; break;
    case 2: register_used = &guest_context->gp_regs->dx; break;
    case 3: register_used = &guest_context->gp_regs->bx; break;
    case 4: register_used = &guest_context->gp_regs->sp; break;
    case 5: register_used = &guest_context->gp_regs->bp; break;
    case 6: register_used = &guest_context->gp_regs->si; break;
    case 7: register_used = &guest_context->gp_regs->di; break;
#if defined(_AMD64_)
    case 8: register_used = &guest_context->gp_regs->r8; break;
    case 9: register_used = &guest_context->gp_regs->r9; break;
    case 10: register_used = &guest_context->gp_regs->r10; break;
    case 11: register_used = &guest_context->gp_regs->r11; break;
    case 12: register_used = &guest_context->gp_regs->r12; break;
    case 13: register_used = &guest_context->gp_regs->r13; break;
    case 14: register_used = &guest_context->gp_regs->r14; break;
    case 15: register_used = &guest_context->gp_regs->r15; break;
#endif
    default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
  }
  // clang-format on
  return register_used;
}

// Dumps guest's selectors
/*_Use_decl_annotations_*/ static void VmmpDumpGuestSelectors() {
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "es %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestEsSelector),
      UtilVmRead(VmcsField::kGuestEsBase), UtilVmRead(VmcsField::kGuestEsLimit),
      UtilVmRead(VmcsField::kGuestEsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "cs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestCsSelector),
      UtilVmRead(VmcsField::kGuestCsBase), UtilVmRead(VmcsField::kGuestCsLimit),
      UtilVmRead(VmcsField::kGuestCsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "ss %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestSsSelector),
      UtilVmRead(VmcsField::kGuestSsBase), UtilVmRead(VmcsField::kGuestSsLimit),
      UtilVmRead(VmcsField::kGuestSsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "ds %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestDsSelector),
      UtilVmRead(VmcsField::kGuestDsBase), UtilVmRead(VmcsField::kGuestDsLimit),
      UtilVmRead(VmcsField::kGuestDsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "fs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestFsSelector),
      UtilVmRead(VmcsField::kGuestFsBase), UtilVmRead(VmcsField::kGuestFsLimit),
      UtilVmRead(VmcsField::kGuestFsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "gs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestGsSelector),
      UtilVmRead(VmcsField::kGuestGsBase), UtilVmRead(VmcsField::kGuestGsLimit),
      UtilVmRead(VmcsField::kGuestGsArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE("ld %04x %p %08x %08x",
                               UtilVmRead(VmcsField::kGuestLdtrSelector),
                               UtilVmRead(VmcsField::kGuestLdtrBase),
                               UtilVmRead(VmcsField::kGuestLdtrLimit),
                               UtilVmRead(VmcsField::kGuestLdtrArBytes));
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "tr %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestTrSelector),
      UtilVmRead(VmcsField::kGuestTrBase), UtilVmRead(VmcsField::kGuestTrLimit),
      UtilVmRead(VmcsField::kGuestTrArBytes));
}

// Sets rip to the next instruction
_Use_decl_annotations_ static void VmmpAdjustGuestInstructionPointer(
    ULONG_PTR guest_ip) {
  const auto exit_instruction_length =
      UtilVmRead(VmcsField::kVmExitInstructionLen);
  UtilVmWrite(VmcsField::kGuestRip, guest_ip + exit_instruction_length);
}

// Handle VMRESUME or VMXOFF failure. Fatal error.
_Use_decl_annotations_ void __stdcall VmmVmxFailureHandler(
    AllRegisters *all_regs) {
  const auto vmx_error = (all_regs->flags.fields.zf)
                             ? UtilVmRead(VmcsField::kVmInstructionError)
                             : 0;
  HYPERPLATFORM_COMMON_BUG_CHECK(
      HyperPlatformBugCheck::kCriticalVmxInstructionFailure, vmx_error, 0, 0);
}

}  // extern "C"
