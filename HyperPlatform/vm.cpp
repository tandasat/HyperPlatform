// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements VMM initialization functions.

#include "vm.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#include "vmm.h"

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

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpIsVmxAvailable();

_IRQL_requires_(DISPATCH_LEVEL) static NTSTATUS
    VmpSetLockBitCallback(_In_opt_ void *context);

_IRQL_requires_max_(
    PASSIVE_LEVEL) static SharedProcessorData *VmpInitializeSharedData();

_IRQL_requires_(DISPATCH_LEVEL) static NTSTATUS
    VmpStartVM(_In_opt_ void *context);

static void VmpInitializeVm(_In_ ULONG_PTR guest_stack_pointer,
                            _In_ ULONG_PTR guest_instruction_pointer,
                            _In_opt_ void *context);

static bool VmpEnterVmxMode(_Inout_ ProcessorData *processor_data);

static bool VmpInitializeVMCS(_Inout_ ProcessorData *processor_data);

static bool VmpSetupVMCS(_In_ const ProcessorData *processor_data,
                         _In_ ULONG_PTR guest_stack_pointer,
                         _In_ ULONG_PTR guest_instruction_pointer,
                         _In_ ULONG_PTR vmm_stack_pointer);

static void VmpLaunchVM();

static ULONG VmpGetSegmentAccessRight(_In_ USHORT segment_selector);

static SegmentDesctiptor *VmpGetSegmentDescriptor(
    _In_ ULONG_PTR descriptor_table_base, _In_ USHORT segment_selector);

static ULONG_PTR VmpGetSegmentBaseByDescriptor(
    _In_ const SegmentDesctiptor *segment_descriptor);

static ULONG_PTR VmpGetSegmentBase(_In_ ULONG_PTR gdt_base,
                                   _In_ USHORT segment_selector);

static ULONG VmpAdjustControlValue(_In_ Msr msr, _In_ ULONG requested_value);

static NTSTATUS VmpStopVM(_In_opt_ void *context);

static KSTART_ROUTINE VmpVmxOffThreadRoutine;

static void VmpFreeProcessorData(_In_opt_ ProcessorData *processor_data);

static bool VmpIsVmmInstalled();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, VmInitialization)
#pragma alloc_text(INIT, VmpIsVmxAvailable)
#pragma alloc_text(INIT, VmpSetLockBitCallback)
#pragma alloc_text(INIT, VmpInitializeSharedData)
#pragma alloc_text(INIT, VmpStartVM)
#pragma alloc_text(INIT, VmpInitializeVm)
#pragma alloc_text(INIT, VmpEnterVmxMode)
#pragma alloc_text(INIT, VmpInitializeVMCS)
#pragma alloc_text(INIT, VmpSetupVMCS)
#pragma alloc_text(INIT, VmpLaunchVM)
#pragma alloc_text(INIT, VmpGetSegmentAccessRight)
#pragma alloc_text(INIT, VmpGetSegmentBase)
#pragma alloc_text(INIT, VmpGetSegmentDescriptor)
#pragma alloc_text(INIT, VmpGetSegmentBaseByDescriptor)
#pragma alloc_text(INIT, VmpAdjustControlValue)
#pragma alloc_text(PAGE, VmTermination)
#pragma alloc_text(PAGE, VmpVmxOffThreadRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Define GetSegmentLimit if it is not defined yet (it is only defined on x64)
#if !defined(GetSegmentLimit)
inline ULONG GetSegmentLimit(_In_ ULONG selector) {
  return __segmentlimit(selector);
}
#endif

// Checks if a VMM can be installed, and so, installs it
_Use_decl_annotations_ NTSTATUS VmInitialization() {
  PAGED_CODE();
  if (VmpIsVmmInstalled()) {
    return STATUS_CANCELLED;
  }

  if (!VmpIsVmxAvailable()) {
    return STATUS_HV_FEATURE_UNAVAILABLE;
  }

  const auto shared_data = VmpInitializeSharedData();
  if (!shared_data) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  // Virtualize all processors
  auto status = UtilForEachProcessor(VmpStartVM, shared_data);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(VmpStopVM, nullptr);
    return status;
  }
  return status;
}

// Checks if the system supports virtualization
_Use_decl_annotations_ static bool VmpIsVmxAvailable() {
  PAGED_CODE();

  // See: DISCOVERING SUPPORT FOR VMX
  // If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
  int cpu_info[4] = {};
  __cpuid(cpu_info, 1);
  const CpuFeaturesEcx cpu_features = {static_cast<ULONG_PTR>(cpu_info[2])};
  if (!cpu_features.fields.vmx) {
    HYPERPLATFORM_LOG_ERROR("VMX features are not supported.");
    return false;
  }

  // See: BASIC VMX INFORMATION
  // The first processors to support VMX operation use the write-back type.
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  if (static_cast<memory_type>(vmx_basic_msr.fields.memory_type) !=
      memory_type::kWriteBack) {
    HYPERPLATFORM_LOG_ERROR("Write-back cache type is not supported.");
    return false;
  }

  // See: ENABLING AND ENTERING VMX OPERATION
  Ia32FeatureControlMsr vmx_feature_control = {
      UtilReadMsr64(Msr::kIa32FeatureControl)};
  if (!vmx_feature_control.fields.lock) {
    HYPERPLATFORM_LOG_INFO("The lock bit is clear. Attempting to set 1.");
    const auto status = UtilForEachProcessor(VmpSetLockBitCallback, nullptr);
    if (!NT_SUCCESS(status)) {
      return false;
    }
  }
  if (!vmx_feature_control.fields.enable_vmxon) {
    HYPERPLATFORM_LOG_ERROR("VMX features are not enabled.");
    return false;
  }

  if (!EptIsEptAvailable()) {
    HYPERPLATFORM_LOG_ERROR("EPT features are not fully supported.");
    return false;
  }
  return true;
}

// Sets 1 to the lock bit of the IA32_FEATURE_CONTROL MSR
_Use_decl_annotations_ static NTSTATUS VmpSetLockBitCallback(void *context) {
  UNREFERENCED_PARAMETER(context);

  Ia32FeatureControlMsr vmx_feature_control = {
      UtilReadMsr64(Msr::kIa32FeatureControl)};
  if (vmx_feature_control.fields.lock) {
    return STATUS_SUCCESS;
  }
  vmx_feature_control.fields.lock = true;
  UtilWriteMsr64(Msr::kIa32FeatureControl, vmx_feature_control.all);
  vmx_feature_control.all = UtilReadMsr64(Msr::kIa32FeatureControl);
  if (!vmx_feature_control.fields.lock) {
    HYPERPLATFORM_LOG_ERROR("The lock bit is still clear.");
    return STATUS_DEVICE_CONFIGURATION_ERROR;
  }
  return STATUS_SUCCESS;
}

// Initialize shared processor data
_Use_decl_annotations_ static SharedProcessorData *VmpInitializeSharedData() {
  PAGED_CODE();

  const auto shared_data = reinterpret_cast<SharedProcessorData *>(
      ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(SharedProcessorData),
                            kHyperPlatformCommonPoolTag));
  if (!shared_data) {
    return nullptr;
  }
  RtlZeroMemory(shared_data, sizeof(SharedProcessorData));
  HYPERPLATFORM_LOG_DEBUG("SharedData=        %p", shared_data);

  // Set up the MSR bitmap
  const auto msr_bitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE,
                                                kHyperPlatformCommonPoolTag);
  if (!msr_bitmap) {
    ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(msr_bitmap, PAGE_SIZE);
  shared_data->msr_bitmap = msr_bitmap;

  // Checks MSRs causing #GP and should not cause VM-exit from 0 to 0xfff.
  bool unsafe_msr_map[0x1000] = {};
  for (auto msr = 0ul; msr < RTL_NUMBER_OF(unsafe_msr_map); ++msr) {
    __try {
      UtilReadMsr(static_cast<Msr>(msr));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      unsafe_msr_map[msr] = true;
    }
  }

  // Activate VM-exit for RDMSR against all MSRs
  const auto bitmap_read_low = reinterpret_cast<UCHAR *>(msr_bitmap);
  const auto bitmap_read_high = bitmap_read_low + 1024;
  RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
  RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff

  // But ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)
  RTL_BITMAP bitmap_read_low_header = {};
  RtlInitializeBitMap(&bitmap_read_low_header,
                      reinterpret_cast<PULONG>(bitmap_read_low), 1024 * 8);
  RtlClearBits(&bitmap_read_low_header, 0xe7, 2);

  // Also ignore the unsage MSRs
  for (auto msr = 0ul; msr < RTL_NUMBER_OF(unsafe_msr_map); ++msr) {
    const auto ignore = unsafe_msr_map[msr];
    if (ignore) {
      RtlClearBits(&bitmap_read_low_header, msr, 1);
    }
  }

  // But ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)
  RTL_BITMAP bitmap_read_high_header = {};
  RtlInitializeBitMap(&bitmap_read_high_header,
                      reinterpret_cast<PULONG>(bitmap_read_high), 1024 * 8);
  RtlClearBits(&bitmap_read_high_header, 0x101, 2);

  return shared_data;
}

// Virtualize the current processor
_Use_decl_annotations_ static NTSTATUS VmpStartVM(void *context) {
  HYPERPLATFORM_LOG_INFO("Initializing VMX for the processor %d.",
                         KeGetCurrentProcessorNumberEx(nullptr));
  const auto ok = AsmInitializeVm(VmpInitializeVm, context);
  NT_ASSERT(VmpIsVmmInstalled() == ok);
  if (!ok) {
    return STATUS_UNSUCCESSFUL;
  }
  HYPERPLATFORM_LOG_INFO("Initialized successfully.");
  return STATUS_SUCCESS;
}

// Allocates structures for virtualization, initializes VMCS and virtualizes
// the current processor
_Use_decl_annotations_ static void VmpInitializeVm(
    ULONG_PTR guest_stack_pointer, ULONG_PTR guest_instruction_pointer,
    void *context) {
  const auto shared_data = reinterpret_cast<SharedProcessorData *>(context);
  if (!shared_data) {
    return;
  }

  // Allocate related structures
  const auto processor_data =
      reinterpret_cast<ProcessorData *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, sizeof(ProcessorData), kHyperPlatformCommonPoolTag));
  if (!processor_data) {
    return;
  }
  RtlZeroMemory(processor_data, sizeof(ProcessorData));

  // Set up EPT
  processor_data->ept_data = EptInitialization();
  if (!processor_data->ept_data) {
    goto ReturnFalse;
  }

  const auto vmm_stack_limit = UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
  const auto vmcs_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
  const auto vmxon_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));

  // Initialize the management structure
  processor_data->vmm_stack_limit = vmm_stack_limit;
  processor_data->vmcs_region = vmcs_region;
  processor_data->vmxon_region = vmxon_region;

  if (!vmm_stack_limit || !vmcs_region || !vmxon_region) {
    goto ReturnFalse;
  }
  RtlZeroMemory(vmm_stack_limit, KERNEL_STACK_SIZE);
  RtlZeroMemory(vmcs_region, kVmxMaxVmcsSize);
  RtlZeroMemory(vmxon_region, kVmxMaxVmcsSize);

  // Initialize stack memory for VMM like this:
  //
  // (High)
  // +------------------+  <- vmm_stack_region_base      (eg, AED37000)
  // | processor_data   |
  // +------------------+  <- vmm_stack_data             (eg, AED36FFC)
  // | MAXULONG_PTR     |
  // +------------------+  <- vmm_stack_base (initial SP)(eg, AED36FF8)
  // |                  |    v
  // | (VMM Stack)      |    v (grow)
  // |                  |    v
  // +------------------+  <- vmm_stack_limit            (eg, AED34000)
  // (Low)
  const auto vmm_stack_region_base =
      reinterpret_cast<ULONG_PTR>(vmm_stack_limit) + KERNEL_STACK_SIZE;
  const auto vmm_stack_data = vmm_stack_region_base - sizeof(void *);
  const auto vmm_stack_base = vmm_stack_data - sizeof(void *);
  HYPERPLATFORM_LOG_DEBUG("VmmStackTop=       %p", vmm_stack_limit);
  HYPERPLATFORM_LOG_DEBUG("VmmStackBottom=    %p", vmm_stack_region_base);
  HYPERPLATFORM_LOG_DEBUG("VmmStackData=      %p", vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("ProcessorData=     %p stored at %p", processor_data,
                          vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("VmmStackBase=      %p", vmm_stack_base);
  HYPERPLATFORM_LOG_DEBUG("GuestStackPointer= %p", guest_stack_pointer);
  HYPERPLATFORM_LOG_DEBUG("GuestInstPointer=  %p", guest_instruction_pointer);
  *reinterpret_cast<ULONG_PTR *>(vmm_stack_base) = MAXULONG_PTR;
  *reinterpret_cast<ProcessorData **>(vmm_stack_data) = processor_data;

  processor_data->shared_data = shared_data;
  InterlockedIncrement(&processor_data->shared_data->reference_count);

  // Set up VMCS
  if (!VmpEnterVmxMode(processor_data)) {
    goto ReturnFalse;
  }
  if (!VmpInitializeVMCS(processor_data)) {
    goto ReturnFalseWithVmxOff;
  }
  if (!VmpSetupVMCS(processor_data, guest_stack_pointer,
                    guest_instruction_pointer, vmm_stack_base)) {
    goto ReturnFalseWithVmxOff;
  }

  // Do virtualize the processor
  VmpLaunchVM();

// Here is not be executed with successful vmlaunch. Instead, the context
// jumps to an address specified by guest_instruction_pointer.

ReturnFalseWithVmxOff:;
  __vmx_off();

ReturnFalse:;
  VmpFreeProcessorData(processor_data);
}

// See: VMM SETUP & TEAR DOWN
_Use_decl_annotations_ static bool VmpEnterVmxMode(
    ProcessorData *processor_data) {
  // Apply FIXED bits
  const Cr0 cr0_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed0)};
  const Cr0 cr0_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed1)};
  Cr0 cr0 = {__readcr0()};
  cr0.all &= cr0_fixed1.all;
  cr0.all |= cr0_fixed0.all;
  __writecr0(cr0.all);

  const Cr4 cr4_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed0)};
  const Cr4 cr4_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed1)};
  Cr4 cr4 = {__readcr4()};
  cr4.all &= cr4_fixed1.all;
  cr4.all |= cr4_fixed0.all;
  __writecr4(cr4.all);

  // Write a VMCS revision identifier
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  processor_data->vmxon_region->revision_identifier =
      vmx_basic_msr.fields.revision_identifier;

  auto vmxon_region_pa = UtilPaFromVa(processor_data->vmxon_region);
  if (__vmx_on(&vmxon_region_pa)) {
    return false;
  }

  UtilInveptAll();
  return true;
}

// See: VMM SETUP & TEAR DOWN
_Use_decl_annotations_ static bool VmpInitializeVMCS(
    ProcessorData *processor_data) {
  // Write a VMCS revision identifier
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  processor_data->vmcs_region->revision_identifier =
      vmx_basic_msr.fields.revision_identifier;

  auto vmcs_region_pa = UtilPaFromVa(processor_data->vmcs_region);
  if (__vmx_vmclear(&vmcs_region_pa)) {
    return false;
  }
  if (__vmx_vmptrld(&vmcs_region_pa)) {
    return false;
  }

  // The launch state of current VMCS is "clear"
  return true;
}

// See: PREPARATION AND LAUNCHING A VIRTUAL MACHINE
_Use_decl_annotations_ static bool VmpSetupVMCS(
    const ProcessorData *processor_data, ULONG_PTR guest_stack_pointer,
    ULONG_PTR guest_instruction_pointer, ULONG_PTR vmm_stack_pointer) {
  Gdtr gdtr = {};
  __sgdt(&gdtr);

  Idtr idtr = {};
  __sidt(&idtr);

  // See: Algorithms for Determining VMX Capabilities
  const auto use_true_msrs = Ia32VmxBasicMsr{
      UtilReadMsr64(
          Msr::kIa32VmxBasic)}.fields.vmx_capability_hint;

  VmxVmEntryControls vm_entryctl_requested = {};
  vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();
  VmxVmEntryControls vm_entryctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls,
      vm_entryctl_requested.all)};

  VmxVmExitControls vm_exitctl_requested = {};
  vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = true;
  vm_exitctl_requested.fields.host_address_space_size = IsX64();
  VmxVmExitControls vm_exitctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls,
      vm_exitctl_requested.all)};

  VmxPinBasedControls vm_pinctl_requested = {};
  VmxPinBasedControls vm_pinctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls
                                            : Msr::kIa32VmxPinbasedCtls,
                            vm_pinctl_requested.all)};

  VmxProcessorBasedControls vm_procctl_requested = {};
  vm_procctl_requested.fields.invlpg_exiting = false;
  vm_procctl_requested.fields.rdtsc_exiting = false;
  vm_procctl_requested.fields.cr3_load_exiting = true;
  vm_procctl_requested.fields.cr8_load_exiting = false;  // NB: very frequent
  vm_procctl_requested.fields.mov_dr_exiting = true;
  vm_procctl_requested.fields.use_msr_bitmaps = true;
  vm_procctl_requested.fields.activate_secondary_control = true;
  VmxProcessorBasedControls vm_procctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls
                                            : Msr::kIa32VmxProcBasedCtls,
                            vm_procctl_requested.all)};

  VmxSecondaryProcessorBasedControls vm_procctl2_requested = {};
  vm_procctl2_requested.fields.enable_ept = true;
  vm_procctl2_requested.fields.enable_rdtscp = true;  // required for Win10
  vm_procctl2_requested.fields.descriptor_table_exiting = true;
  // required for Win10
  vm_procctl2_requested.fields.enable_xsaves_xstors = true;
  VmxSecondaryProcessorBasedControls vm_procctl2 = {VmpAdjustControlValue(
      Msr::kIa32VmxProcBasedCtls2, vm_procctl2_requested.all)};

  // Set up CR0 and CR4 bitmaps
  // - Where a bit is     masked, the shadow bit appears
  // - Where a bit is not masked, the actual bit appears
  // VM-exit occurs when a guest modifies any of those fields
  Cr0 cr0_mask = {};
  Cr4 cr4_mask = {};

  // See: PDPTE Registers
  // If PAE paging would be in use following an execution of MOV to CR0 or MOV
  // to CR4 (see Section 4.1.1) and the instruction is modifying any of CR0.CD,
  // CR0.NW, CR0.PG, CR4.PAE, CR4.PGE, CR4.PSE, or CR4.SMEP; then the PDPTEs are
  // loaded from the address in CR3.
  if (UtilIsX86Pae()) {
    cr0_mask.fields.pg = true;
    cr0_mask.fields.cd = true;
    cr0_mask.fields.nw = true;
    cr4_mask.fields.pae = true;
    cr4_mask.fields.pge = true;
    cr4_mask.fields.pse = true;
    cr4_mask.fields.smep = true;
  }

  const auto exception_bitmap =
      // 1 << InterruptionVector::kBreakpointException |
      // 1 << InterruptionVector::kGeneralProtectionException |
      // 1 << InterruptionVector::kPageFaultException |
      0;

  // clang-format off
  /* 16-Bit Control Field */

  /* 16-Bit Guest-State Fields */
  auto error = VmxStatus::kOk;
  error |= UtilVmWrite(VmcsField::kGuestEsSelector, AsmReadES());
  error |= UtilVmWrite(VmcsField::kGuestCsSelector, AsmReadCS());
  error |= UtilVmWrite(VmcsField::kGuestSsSelector, AsmReadSS());
  error |= UtilVmWrite(VmcsField::kGuestDsSelector, AsmReadDS());
  error |= UtilVmWrite(VmcsField::kGuestFsSelector, AsmReadFS());
  error |= UtilVmWrite(VmcsField::kGuestGsSelector, AsmReadGS());
  error |= UtilVmWrite(VmcsField::kGuestLdtrSelector, AsmReadLDTR());
  error |= UtilVmWrite(VmcsField::kGuestTrSelector, AsmReadTR());

  /* 16-Bit Host-State Fields */
  // RPL and TI have to be 0
  error |= UtilVmWrite(VmcsField::kHostEsSelector, AsmReadES() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostCsSelector, AsmReadCS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostSsSelector, AsmReadSS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostDsSelector, AsmReadDS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostFsSelector, AsmReadFS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostGsSelector, AsmReadGS() & 0xf8);
  error |= UtilVmWrite(VmcsField::kHostTrSelector, AsmReadTR() & 0xf8);

  /* 64-Bit Control Fields */
  error |= UtilVmWrite64(VmcsField::kIoBitmapA, 0);
  error |= UtilVmWrite64(VmcsField::kIoBitmapB, 0);
  error |= UtilVmWrite64(VmcsField::kMsrBitmap, UtilPaFromVa(processor_data->shared_data->msr_bitmap));
  error |= UtilVmWrite64(VmcsField::kEptPointer, EptGetEptPointer(processor_data->ept_data));

  /* 64-Bit Guest-State Fields */
  error |= UtilVmWrite64(VmcsField::kVmcsLinkPointer, MAXULONG64);
  error |= UtilVmWrite64(VmcsField::kGuestIa32Debugctl, UtilReadMsr64(Msr::kIa32Debugctl));
  if (UtilIsX86Pae()) {
    UtilLoadPdptes(__readcr3());
  }

  /* 32-Bit Control Fields */
  error |= UtilVmWrite(VmcsField::kPinBasedVmExecControl, vm_pinctl.all);
  error |= UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
  error |= UtilVmWrite(VmcsField::kExceptionBitmap, exception_bitmap);
  error |= UtilVmWrite(VmcsField::kPageFaultErrorCodeMask, 0);
  error |= UtilVmWrite(VmcsField::kPageFaultErrorCodeMatch, 0);
  error |= UtilVmWrite(VmcsField::kCr3TargetCount, 0);
  error |= UtilVmWrite(VmcsField::kVmExitControls, vm_exitctl.all);
  error |= UtilVmWrite(VmcsField::kVmExitMsrStoreCount, 0);
  error |= UtilVmWrite(VmcsField::kVmExitMsrLoadCount, 0);
  error |= UtilVmWrite(VmcsField::kVmEntryControls, vm_entryctl.all);
  error |= UtilVmWrite(VmcsField::kVmEntryMsrLoadCount, 0);
  error |= UtilVmWrite(VmcsField::kVmEntryIntrInfoField, 0);
  error |= UtilVmWrite(VmcsField::kSecondaryVmExecControl, vm_procctl2.all);

  /* 32-Bit Guest-State Fields */
  error |= UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
  error |= UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
  error |= UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestGdtrLimit, gdtr.limit);
  error |= UtilVmWrite(VmcsField::kGuestIdtrLimit, idtr.limit);
  error |= UtilVmWrite(VmcsField::kGuestEsArBytes, VmpGetSegmentAccessRight(AsmReadES()));
  error |= UtilVmWrite(VmcsField::kGuestCsArBytes, VmpGetSegmentAccessRight(AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsArBytes, VmpGetSegmentAccessRight(AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsArBytes, VmpGetSegmentAccessRight(AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsArBytes, VmpGetSegmentAccessRight(AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsArBytes, VmpGetSegmentAccessRight(AsmReadGS()));
  error |= UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmpGetSegmentAccessRight(AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrArBytes, VmpGetSegmentAccessRight(AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestInterruptibilityInfo, 0);
  error |= UtilVmWrite(VmcsField::kGuestActivityState, 0);
  error |= UtilVmWrite(VmcsField::kGuestSysenterCs, UtilReadMsr(Msr::kIa32SysenterCs));

  /* 32-Bit Host-State Field */
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterCs, UtilReadMsr(Msr::kIa32SysenterCs));

  /* Natural-Width Control Fields */
  error |= UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);
  error |= UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all);
  error |= UtilVmWrite(VmcsField::kCr0ReadShadow, __readcr0());
  error |= UtilVmWrite(VmcsField::kCr4ReadShadow, __readcr4());

  /* Natural-Width Guest-State Fields */
  error |= UtilVmWrite(VmcsField::kGuestCr0, __readcr0());
  error |= UtilVmWrite(VmcsField::kGuestCr3, __readcr3());
  error |= UtilVmWrite(VmcsField::kGuestCr4, __readcr4());
#if defined(_AMD64_)
  error |= UtilVmWrite(VmcsField::kGuestEsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestCsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestSsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestDsBase, 0);
  error |= UtilVmWrite(VmcsField::kGuestFsBase, UtilReadMsr(Msr::kIa32FsBase));
  error |= UtilVmWrite(VmcsField::kGuestGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
  error |= UtilVmWrite(VmcsField::kGuestEsBase, VmpGetSegmentBase(gdtr.base, AsmReadES()));
  error |= UtilVmWrite(VmcsField::kGuestCsBase, VmpGetSegmentBase(gdtr.base, AsmReadCS()));
  error |= UtilVmWrite(VmcsField::kGuestSsBase, VmpGetSegmentBase(gdtr.base, AsmReadSS()));
  error |= UtilVmWrite(VmcsField::kGuestDsBase, VmpGetSegmentBase(gdtr.base, AsmReadDS()));
  error |= UtilVmWrite(VmcsField::kGuestFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kGuestGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif
  error |= UtilVmWrite(VmcsField::kGuestLdtrBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
  error |= UtilVmWrite(VmcsField::kGuestTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kGuestGdtrBase, gdtr.base);
  error |= UtilVmWrite(VmcsField::kGuestIdtrBase, idtr.base);
  error |= UtilVmWrite(VmcsField::kGuestDr7, __readdr(7));
  error |= UtilVmWrite(VmcsField::kGuestRsp, guest_stack_pointer);
  error |= UtilVmWrite(VmcsField::kGuestRip, guest_instruction_pointer);
  error |= UtilVmWrite(VmcsField::kGuestRflags, __readeflags());
  error |= UtilVmWrite(VmcsField::kGuestSysenterEsp, UtilReadMsr(Msr::kIa32SysenterEsp));
  error |= UtilVmWrite(VmcsField::kGuestSysenterEip, UtilReadMsr(Msr::kIa32SysenterEip));

  /* Natural-Width Host-State Fields */
  error |= UtilVmWrite(VmcsField::kHostCr0, __readcr0());
  error |= UtilVmWrite(VmcsField::kHostCr3, __readcr3());
  error |= UtilVmWrite(VmcsField::kHostCr4, __readcr4());
#if defined(_AMD64_)
  error |= UtilVmWrite(VmcsField::kHostFsBase, UtilReadMsr(Msr::kIa32FsBase));
  error |= UtilVmWrite(VmcsField::kHostGsBase, UtilReadMsr(Msr::kIa32GsBase));
#else
  error |= UtilVmWrite(VmcsField::kHostFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
  error |= UtilVmWrite(VmcsField::kHostGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif
  error |= UtilVmWrite(VmcsField::kHostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
  error |= UtilVmWrite(VmcsField::kHostGdtrBase, gdtr.base);
  error |= UtilVmWrite(VmcsField::kHostIdtrBase, idtr.base);
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterEsp, UtilReadMsr(Msr::kIa32SysenterEsp));
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterEip, UtilReadMsr(Msr::kIa32SysenterEip));
  error |= UtilVmWrite(VmcsField::kHostRsp, vmm_stack_pointer);
  error |= UtilVmWrite(VmcsField::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));
  // clang-format on

  const auto vmx_status = static_cast<VmxStatus>(error);
  return vmx_status == VmxStatus::kOk;
}

// Executes vmlaunch
/*_Use_decl_annotations_*/ static void VmpLaunchVM() {
  auto error_code = UtilVmRead(VmcsField::kVmInstructionError);
  if (error_code) {
    HYPERPLATFORM_LOG_WARN("VM_INSTRUCTION_ERROR = %d", error_code);
  }
  HYPERPLATFORM_COMMON_DBG_BREAK();
  auto vmx_status = static_cast<VmxStatus>(__vmx_vmlaunch());

  // Here is not be executed with successful vmlaunch. Instead, the context
  // jumps to an address specified by GUEST_RIP.
  if (vmx_status == VmxStatus::kErrorWithStatus) {
    error_code = UtilVmRead(VmcsField::kVmInstructionError);
    HYPERPLATFORM_LOG_ERROR("VM_INSTRUCTION_ERROR = %d", error_code);
  }
  HYPERPLATFORM_COMMON_DBG_BREAK();
}

// Returns access right of the segment specified by the SegmentSelector for VMX
_Use_decl_annotations_ static ULONG VmpGetSegmentAccessRight(
    USHORT segment_selector) {
  VmxRegmentDescriptorAccessRight access_right = {};
  const SegmentSelector ss = {segment_selector};
  if (segment_selector) {
    auto native_access_right = AsmLoadAccessRightsByte(ss.all);
    native_access_right >>= 8;
    access_right.all = static_cast<ULONG>(native_access_right);
    access_right.fields.reserved1 = 0;
    access_right.fields.reserved2 = 0;
    access_right.fields.unusable = false;
  } else {
    access_right.fields.unusable = true;
  }
  return access_right.all;
}

// Returns a base address of the segment specified by SegmentSelector
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBase(
    ULONG_PTR gdt_base, USHORT segment_selector) {
  const SegmentSelector ss = {segment_selector};
  if (!ss.all) {
    return 0;
  }

  if (ss.fields.ti) {
    const auto local_segment_descriptor =
        VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
    const auto ldt_base =
        VmpGetSegmentBaseByDescriptor(local_segment_descriptor);
    const auto segment_descriptor =
        VmpGetSegmentDescriptor(ldt_base, segment_selector);
    return VmpGetSegmentBaseByDescriptor(segment_descriptor);
  } else {
    const auto segment_descriptor =
        VmpGetSegmentDescriptor(gdt_base, segment_selector);
    return VmpGetSegmentBaseByDescriptor(segment_descriptor);
  }
}

// Returns the segment descriptor corresponds to the SegmentSelector
_Use_decl_annotations_ static SegmentDesctiptor *VmpGetSegmentDescriptor(
    ULONG_PTR descriptor_table_base, USHORT segment_selector) {
  const SegmentSelector ss = {segment_selector};
  return reinterpret_cast<SegmentDesctiptor *>(
      descriptor_table_base + ss.fields.index * sizeof(SegmentDesctiptor));
}

// Returns a base address of segment_descriptor
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBaseByDescriptor(
    const SegmentDesctiptor *segment_descriptor) {
  // Caluculate a 32bit base address
  const auto base_high = segment_descriptor->fields.base_high << (6 * 4);
  const auto base_middle = segment_descriptor->fields.base_mid << (4 * 4);
  const auto base_low = segment_descriptor->fields.base_low;
  ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
  // Get upper 32bit of the base address if needed
  if (IsX64() && !segment_descriptor->fields.system) {
    auto desc64 =
        reinterpret_cast<const SegmentDesctiptorX64 *>(segment_descriptor);
    ULONG64 base_upper32 = desc64->base_upper32;
    base |= (base_upper32 << 32);
  }
  return base;
}

// Adjust the requested control value with consulting a value of related MSR
_Use_decl_annotations_ static ULONG VmpAdjustControlValue(
    Msr msr, ULONG requested_value) {
  LARGE_INTEGER msr_value = {};
  msr_value.QuadPart = UtilReadMsr64(msr);
  auto adjusted_value = requested_value;

  // bit == 0 in high word ==> must be zero
  adjusted_value &= msr_value.HighPart;
  // bit == 1 in low word  ==> must be one
  adjusted_value |= msr_value.LowPart;
  return adjusted_value;
}

// Terminates VM
_Use_decl_annotations_ void VmTermination() {
  PAGED_CODE();
  // Create a thread dedicated to de-virtualizing processors. For some reasons,
  // de-virtualizing processors from this thread makes the system stop
  // processing all timer related events and functioning properly.
  HANDLE thread_handle = nullptr;
  auto status =
      PsCreateSystemThread(&thread_handle, GENERIC_ALL, nullptr, nullptr,
                           nullptr, VmpVmxOffThreadRoutine, nullptr);
  if (NT_SUCCESS(status)) {
    // Wait until the thread ends its work.
    status = ZwWaitForSingleObject(thread_handle, FALSE, nullptr);
    status = ZwClose(thread_handle);
  } else {
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
  NT_ASSERT(!VmpIsVmmInstalled());
}

// De-virtualizing all processors
_Use_decl_annotations_ static void VmpVmxOffThreadRoutine(void *start_context) {
  UNREFERENCED_PARAMETER(start_context);
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Uninstalling VMM.");
  auto status = UtilForEachProcessor(VmpStopVM, nullptr);
  if (NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_INFO("The VMM has been uninstalled.");
  } else {
    HYPERPLATFORM_LOG_WARN("The VMM has not been uninstalled (%08x).", status);
  }
  PsTerminateSystemThread(status);
}

// Stops virtualization through a hypercall and frees all related memory
_Use_decl_annotations_ static NTSTATUS VmpStopVM(void *context) {
  UNREFERENCED_PARAMETER(context);

  HYPERPLATFORM_LOG_INFO("Terminating VMX for the processor %d.",
                         KeGetCurrentProcessorNumberEx(nullptr));

  // Stop virtualization and get an address of the management structure
  ProcessorData *processor_data = nullptr;
  auto status = UtilVmCall(HypercallNumber::kTerminateVmm, &processor_data);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  VmpFreeProcessorData(processor_data);
  return STATUS_SUCCESS;
}

// Frees all related memory
_Use_decl_annotations_ static void VmpFreeProcessorData(
    ProcessorData *processor_data) {
  if (!processor_data) {
    return;
  }
  if (processor_data->vmm_stack_limit) {
    UtilFreeContiguousMemory(processor_data->vmm_stack_limit);
  }
  if (processor_data->vmcs_region) {
    ExFreePoolWithTag(processor_data->vmcs_region, kHyperPlatformCommonPoolTag);
  }
  if (processor_data->vmxon_region) {
    ExFreePoolWithTag(processor_data->vmxon_region,
                      kHyperPlatformCommonPoolTag);
  }
  if (processor_data->ept_data) {
    EptTermination(processor_data->ept_data);
  }

  // Free shared data if this is the last reference
  if (processor_data->shared_data &&
      InterlockedDecrement(&processor_data->shared_data->reference_count) ==
          0) {
    HYPERPLATFORM_LOG_DEBUG("Freeing shared data...");
    if (processor_data->shared_data->msr_bitmap) {
      ExFreePoolWithTag(processor_data->shared_data->msr_bitmap,
                        kHyperPlatformCommonPoolTag);
    }
    ExFreePoolWithTag(processor_data->shared_data, kHyperPlatformCommonPoolTag);
  }

  ExFreePoolWithTag(processor_data, kHyperPlatformCommonPoolTag);
}

// Tests if the VMM is already installed using a backdoor command
/*_Use_decl_annotations_*/ static bool VmpIsVmmInstalled() {
  int cpu_info[4] = {};
  __cpuidex(cpu_info, 0, kHyperPlatformVmmBackdoorCode);
  char vendor_id[13] = {};
  RtlCopyMemory(&vendor_id[0], &cpu_info[1], 4);  // ebx
  RtlCopyMemory(&vendor_id[4], &cpu_info[3], 4);  // edx
  RtlCopyMemory(&vendor_id[8], &cpu_info[2], 4);  // ecx
  return RtlCompareMemory(vendor_id, "Pong by VMM!\0", sizeof(vendor_id)) ==
         sizeof(vendor_id);
}

}  // extern "C"
