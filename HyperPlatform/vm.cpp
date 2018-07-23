// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements VMM initialization functions.

#include "vm.h"
#include <limits.h>
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

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    VmpSetLockBitCallback(_In_opt_ void *context);

_IRQL_requires_max_(
    PASSIVE_LEVEL) static SharedProcessorData *VmpInitializeSharedData();

_IRQL_requires_max_(PASSIVE_LEVEL) static void *VmpBuildMsrBitmap();

_IRQL_requires_max_(PASSIVE_LEVEL) static UCHAR *VmpBuildIoBitmaps();

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    VmpStartVm(_In_opt_ void *context);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpInitializeVm(
    _In_ ULONG_PTR guest_stack_pointer,
    _In_ ULONG_PTR guest_instruction_pointer, _In_opt_ void *context);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpEnterVmxMode(
    _Inout_ ProcessorData *processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpInitializeVmcs(
    _Inout_ ProcessorData *processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpSetupVmcs(
    _In_ const ProcessorData *processor_data,
    _In_ ULONG_PTR guest_stack_pointer,
    _In_ ULONG_PTR guest_instruction_pointer, _In_ ULONG_PTR vmm_stack_pointer);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpLaunchVm();

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG
    VmpGetSegmentAccessRight(_In_ USHORT segment_selector);

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR
    VmpGetSegmentBase(_In_ ULONG_PTR gdt_base, _In_ USHORT segment_selector);

_IRQL_requires_max_(PASSIVE_LEVEL) static SegmentDescriptor
    *VmpGetSegmentDescriptor(_In_ ULONG_PTR descriptor_table_base,
                             _In_ USHORT segment_selector);

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG_PTR
    VmpGetSegmentBaseByDescriptor(
        _In_ const SegmentDescriptor *segment_descriptor);

_IRQL_requires_max_(PASSIVE_LEVEL) static ULONG
    VmpAdjustControlValue(_In_ Msr msr, _In_ ULONG requested_value);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    VmpStopVm(_In_opt_ void *context);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpFreeProcessorData(
    _In_opt_ ProcessorData *processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpFreeSharedData(
    _In_ ProcessorData *processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) static bool VmpIsHyperPlatformInstalled();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, VmInitialization)
#pragma alloc_text(PAGE, VmTermination)
#pragma alloc_text(PAGE, VmpIsVmxAvailable)
#pragma alloc_text(PAGE, VmpSetLockBitCallback)
#pragma alloc_text(PAGE, VmpInitializeSharedData)
#pragma alloc_text(PAGE, VmpBuildMsrBitmap)
#pragma alloc_text(PAGE, VmpBuildIoBitmaps)
#pragma alloc_text(PAGE, VmpStartVm)
#pragma alloc_text(PAGE, VmpInitializeVm)
#pragma alloc_text(PAGE, VmpEnterVmxMode)
#pragma alloc_text(PAGE, VmpInitializeVmcs)
#pragma alloc_text(PAGE, VmpSetupVmcs)
#pragma alloc_text(PAGE, VmpLaunchVm)
#pragma alloc_text(PAGE, VmpGetSegmentAccessRight)
#pragma alloc_text(PAGE, VmpGetSegmentBase)
#pragma alloc_text(PAGE, VmpGetSegmentDescriptor)
#pragma alloc_text(PAGE, VmpGetSegmentBaseByDescriptor)
#pragma alloc_text(PAGE, VmpAdjustControlValue)
#pragma alloc_text(PAGE, VmpStopVm)
#pragma alloc_text(PAGE, VmpFreeProcessorData)
#pragma alloc_text(PAGE, VmpFreeSharedData)
#pragma alloc_text(PAGE, VmpIsHyperPlatformInstalled)
#pragma alloc_text(PAGE, VmHotplugCallback)
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

  if (VmpIsHyperPlatformInstalled()) {
    return STATUS_CANCELLED;
  }

  if (!VmpIsVmxAvailable()) {
    return STATUS_HV_FEATURE_UNAVAILABLE;
  }

  const auto shared_data = VmpInitializeSharedData();
  if (!shared_data) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  // Read and store all MTRRs to set a correct memory type for EPT
  EptInitializeMtrrEntries();

  // Virtualize all processors
  auto status = UtilForEachProcessor(VmpStartVm, shared_data);
  if (!NT_SUCCESS(status)) {
    UtilForEachProcessor(VmpStopVm, nullptr);
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
  PAGED_CODE();

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
      ExAllocatePoolWithTag(NonPagedPool, sizeof(SharedProcessorData),
                            kHyperPlatformCommonPoolTag));
  if (!shared_data) {
    return nullptr;
  }
  RtlZeroMemory(shared_data, sizeof(SharedProcessorData));
  HYPERPLATFORM_LOG_DEBUG("shared_data           = %p", shared_data);

  // Setup MSR bitmap
  shared_data->msr_bitmap = VmpBuildMsrBitmap();
  if (!shared_data->msr_bitmap) {
    ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }

  // Setup IO bitmaps
  const auto io_bitmaps = VmpBuildIoBitmaps();
  if (!io_bitmaps) {
    ExFreePoolWithTag(shared_data->msr_bitmap, kHyperPlatformCommonPoolTag);
    ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  shared_data->io_bitmap_a = io_bitmaps;
  shared_data->io_bitmap_b = io_bitmaps + PAGE_SIZE;
  return shared_data;
}

// Build MSR bitmap
_Use_decl_annotations_ static void *VmpBuildMsrBitmap() {
  PAGED_CODE();

  const auto msr_bitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE,
                                                kHyperPlatformCommonPoolTag);
  if (!msr_bitmap) {
    return nullptr;
  }
  RtlZeroMemory(msr_bitmap, PAGE_SIZE);

  // Activate VM-exit for RDMSR against all MSRs
  const auto bitmap_read_low = reinterpret_cast<UCHAR *>(msr_bitmap);
  const auto bitmap_read_high = bitmap_read_low + 1024;
  RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
  RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff

  // Ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)
  RTL_BITMAP bitmap_read_low_header = {};
  RtlInitializeBitMap(&bitmap_read_low_header,
                      reinterpret_cast<PULONG>(bitmap_read_low), 1024 * 8);
  RtlClearBits(&bitmap_read_low_header, 0xe7, 2);

  // Checks MSRs that cause #GP from 0 to 0xfff, and ignore all of them
  for (auto msr = 0ul; msr < 0x1000; ++msr) {
    __try {
      UtilReadMsr(static_cast<Msr>(msr));

#pragma prefast(suppress: __WARNING_EXCEPTIONEXECUTEHANDLER, "Catch all.");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      RtlClearBits(&bitmap_read_low_header, msr, 1);
    }
  }

  // Ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)
  RTL_BITMAP bitmap_read_high_header = {};
  RtlInitializeBitMap(&bitmap_read_high_header,
                      reinterpret_cast<PULONG>(bitmap_read_high),
                      1024 * CHAR_BIT);
  RtlClearBits(&bitmap_read_high_header, 0x101, 2);

  return msr_bitmap;
}

// Build IO bitmaps
_Use_decl_annotations_ static UCHAR *VmpBuildIoBitmaps() {
  PAGED_CODE();

  // Allocate two IO bitmaps as one contiguous 4K+4K page
  const auto io_bitmaps = reinterpret_cast<UCHAR *>(ExAllocatePoolWithTag(
      NonPagedPool, PAGE_SIZE * 2, kHyperPlatformCommonPoolTag));
  if (!io_bitmaps) {
    return nullptr;
  }

  const auto io_bitmap_a = io_bitmaps;              // for    0x0 - 0x7fff
  const auto io_bitmap_b = io_bitmaps + PAGE_SIZE;  // for 0x8000 - 0xffff
  RtlFillMemory(io_bitmap_a, PAGE_SIZE, 0);
  RtlFillMemory(io_bitmap_b, PAGE_SIZE, 0);

  // Activate VM-exit for IO port 0x10 - 0x2010 as an example
  RTL_BITMAP bitmap_a_header = {};
  RtlInitializeBitMap(&bitmap_a_header, reinterpret_cast<PULONG>(io_bitmap_a),
                      PAGE_SIZE * CHAR_BIT);
  // RtlSetBits(&bitmap_a_header, 0x10, 0x2000);

  RTL_BITMAP bitmap_b_header = {};
  RtlInitializeBitMap(&bitmap_b_header, reinterpret_cast<PULONG>(io_bitmap_b),
                      PAGE_SIZE * CHAR_BIT);
  // RtlSetBits(&bitmap_b_header, 0, 0x8000);
  return io_bitmaps;
}

// Virtualize the current processor
_Use_decl_annotations_ static NTSTATUS VmpStartVm(void *context) {
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Initializing VMX for the processor %lu.",
                         KeGetCurrentProcessorNumberEx(nullptr));
  const auto ok = AsmInitializeVm(VmpInitializeVm, context);
  NT_ASSERT(VmpIsHyperPlatformInstalled() == ok);
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
  PAGED_CODE();

  const auto shared_data = reinterpret_cast<SharedProcessorData *>(context);
  if (!shared_data) {
    return;
  }

  // Allocate related structures
  const auto processor_data =
      reinterpret_cast<ProcessorData *>(ExAllocatePoolWithTag(
          NonPagedPool, sizeof(ProcessorData), kHyperPlatformCommonPoolTag));
  if (!processor_data) {
    return;
  }
  RtlZeroMemory(processor_data, sizeof(ProcessorData));
  processor_data->shared_data = shared_data;
  InterlockedIncrement(&processor_data->shared_data->reference_count);

  // Set up EPT
  processor_data->ept_data = EptInitialization();
  if (!processor_data->ept_data) {
    goto ReturnFalse;
  }

  // Allocate other processor data fields
  processor_data->vmm_stack_limit =
      UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
  if (!processor_data->vmm_stack_limit) {
    goto ReturnFalse;
  }
  RtlZeroMemory(processor_data->vmm_stack_limit, KERNEL_STACK_SIZE);

  processor_data->vmcs_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPool, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
  if (!processor_data->vmcs_region) {
    goto ReturnFalse;
  }
  RtlZeroMemory(processor_data->vmcs_region, kVmxMaxVmcsSize);

  processor_data->vmxon_region =
      reinterpret_cast<VmControlStructure *>(ExAllocatePoolWithTag(
          NonPagedPool, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
  if (!processor_data->vmxon_region) {
    goto ReturnFalse;
  }
  RtlZeroMemory(processor_data->vmxon_region, kVmxMaxVmcsSize);

  // Initialize stack memory for VMM like this:
  //
  // (High)
  // +------------------+  <- vmm_stack_region_base      (eg, AED37000)
  // | processor_data   |  <- vmm_stack_data             (eg, AED36FFC)
  // +------------------+
  // | MAXULONG_PTR     |  <- vmm_stack_base (initial SP)(eg, AED36FF8)
  // +------------------+    v
  // |                  |    v
  // | (VMM Stack)      |    v (grow)
  // |                  |    v
  // +------------------+  <- vmm_stack_limit            (eg, AED34000)
  // (Low)
  const auto vmm_stack_region_base =
      reinterpret_cast<ULONG_PTR>(processor_data->vmm_stack_limit) +
      KERNEL_STACK_SIZE;
  const auto vmm_stack_data = vmm_stack_region_base - sizeof(void *);
  const auto vmm_stack_base = vmm_stack_data - sizeof(void *);
  HYPERPLATFORM_LOG_DEBUG("vmm_stack_limit       = %p",
                          processor_data->vmm_stack_limit);
  HYPERPLATFORM_LOG_DEBUG("vmm_stack_region_base = %016Ix",
                          vmm_stack_region_base);
  HYPERPLATFORM_LOG_DEBUG("vmm_stack_data        = %016Ix", vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("vmm_stack_base        = %016Ix", vmm_stack_base);
  HYPERPLATFORM_LOG_DEBUG("processor_data        = %p stored at %016Ix",
                          processor_data, vmm_stack_data);
  HYPERPLATFORM_LOG_DEBUG("guest_stack_pointer   = %016Ix",
                          guest_stack_pointer);
  HYPERPLATFORM_LOG_DEBUG("guest_inst_pointer    = %016Ix",
                          guest_instruction_pointer);
  *reinterpret_cast<ULONG_PTR *>(vmm_stack_base) = MAXULONG_PTR;
  *reinterpret_cast<ProcessorData **>(vmm_stack_data) = processor_data;

  // Set up VMCS
  if (!VmpEnterVmxMode(processor_data)) {
    goto ReturnFalse;
  }
  if (!VmpInitializeVmcs(processor_data)) {
    goto ReturnFalseWithVmxOff;
  }
  if (!VmpSetupVmcs(processor_data, guest_stack_pointer,
                    guest_instruction_pointer, vmm_stack_base)) {
    goto ReturnFalseWithVmxOff;
  }

  // Do virtualize the processor
  VmpLaunchVm();

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
  PAGED_CODE();

  // Apply FIXED bits
  // See: VMX-FIXED BITS IN CR0

  //        IA32_VMX_CRx_FIXED0 IA32_VMX_CRx_FIXED1 Meaning
  // Values 1                   *                   bit of CRx is fixed to 1
  // Values 0                   1                   bit of CRx is flexible
  // Values *                   0                   bit of CRx is fixed to 0
  const Cr0 cr0_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed0)};
  const Cr0 cr0_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr0Fixed1)};
  Cr0 cr0 = {__readcr0()};
  Cr0 cr0_original = cr0;
  cr0.all &= cr0_fixed1.all;
  cr0.all |= cr0_fixed0.all;
  __writecr0(cr0.all);

  HYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR0_FIXED0   = %08Ix", cr0_fixed0.all);
  HYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR0_FIXED1   = %08Ix", cr0_fixed1.all);
  HYPERPLATFORM_LOG_DEBUG("Original CR0          = %08Ix", cr0_original.all);
  HYPERPLATFORM_LOG_DEBUG("Fixed CR0             = %08Ix", cr0.all);

  // See: VMX-FIXED BITS IN CR4
  const Cr4 cr4_fixed0 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed0)};
  const Cr4 cr4_fixed1 = {UtilReadMsr(Msr::kIa32VmxCr4Fixed1)};
  Cr4 cr4 = {__readcr4()};
  Cr4 cr4_original = cr4;
  cr4.all &= cr4_fixed1.all;
  cr4.all |= cr4_fixed0.all;
  __writecr4(cr4.all);

  HYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR4_FIXED0   = %08Ix", cr4_fixed0.all);
  HYPERPLATFORM_LOG_DEBUG("IA32_VMX_CR4_FIXED1   = %08Ix", cr4_fixed1.all);
  HYPERPLATFORM_LOG_DEBUG("Original CR4          = %08Ix", cr4_original.all);
  HYPERPLATFORM_LOG_DEBUG("Fixed CR4             = %08Ix", cr4.all);

  // Write a VMCS revision identifier
  const Ia32VmxBasicMsr vmx_basic_msr = {UtilReadMsr64(Msr::kIa32VmxBasic)};
  processor_data->vmxon_region->revision_identifier =
      vmx_basic_msr.fields.revision_identifier;

  auto vmxon_region_pa = UtilPaFromVa(processor_data->vmxon_region);
  if (__vmx_on(&vmxon_region_pa)) {
    return false;
  }

  // See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
  // of the INVEPT Instruction
  UtilInveptGlobal();
  UtilInvvpidAllContext();
  return true;
}

// See: VMM SETUP & TEAR DOWN
_Use_decl_annotations_ static bool VmpInitializeVmcs(
    ProcessorData *processor_data) {
  PAGED_CODE();

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
_Use_decl_annotations_ static bool VmpSetupVmcs(
    const ProcessorData *processor_data, ULONG_PTR guest_stack_pointer,
    ULONG_PTR guest_instruction_pointer, ULONG_PTR vmm_stack_pointer) {
  PAGED_CODE();

  Gdtr gdtr = {};
  __sgdt(&gdtr);

  Idtr idtr = {};
  __sidt(&idtr);

  // See: Algorithms for Determining VMX Capabilities
  const auto use_true_msrs = Ia32VmxBasicMsr{UtilReadMsr64(Msr::kIa32VmxBasic)}
                                 .fields.vmx_capability_hint;

  VmxVmEntryControls vm_entryctl_requested = {};
  vm_entryctl_requested.fields.load_debug_controls = true;
  vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();
  VmxVmEntryControls vm_entryctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls,
      vm_entryctl_requested.all)};

  VmxVmExitControls vm_exitctl_requested = {};
  vm_exitctl_requested.fields.host_address_space_size = IsX64();
  vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = true;
  VmxVmExitControls vm_exitctl = {VmpAdjustControlValue(
      (use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls,
      vm_exitctl_requested.all)};

  VmxPinBasedControls vm_pinctl_requested = {};
  VmxPinBasedControls vm_pinctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls
                                            : Msr::kIa32VmxPinbasedCtls,
                            vm_pinctl_requested.all)};

  VmxProcessorBasedControls vm_procctl_requested = {};
  vm_procctl_requested.fields.cr3_load_exiting = true;
  vm_procctl_requested.fields.mov_dr_exiting = true;
  vm_procctl_requested.fields.use_io_bitmaps = true;
  vm_procctl_requested.fields.use_msr_bitmaps = true;
  vm_procctl_requested.fields.activate_secondary_control = true;
  VmxProcessorBasedControls vm_procctl = {
      VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls
                                            : Msr::kIa32VmxProcBasedCtls,
                            vm_procctl_requested.all)};

  VmxSecondaryProcessorBasedControls vm_procctl2_requested = {};
  vm_procctl2_requested.fields.enable_ept = true;
  vm_procctl2_requested.fields.descriptor_table_exiting = true;
  vm_procctl2_requested.fields.enable_rdtscp = true;  // for Win10
  vm_procctl2_requested.fields.enable_vpid = true;
  vm_procctl2_requested.fields.enable_invpcid = true;        // for Win10
  vm_procctl2_requested.fields.enable_xsaves_xstors = true;  // for Win10
  VmxSecondaryProcessorBasedControls vm_procctl2 = {VmpAdjustControlValue(
      Msr::kIa32VmxProcBasedCtls2, vm_procctl2_requested.all)};

  HYPERPLATFORM_LOG_DEBUG("VmEntryControls                  = %08x",
                          vm_entryctl.all);
  HYPERPLATFORM_LOG_DEBUG("VmExitControls                   = %08x",
                          vm_exitctl.all);
  HYPERPLATFORM_LOG_DEBUG("PinBasedControls                 = %08x",
                          vm_pinctl.all);
  HYPERPLATFORM_LOG_DEBUG("ProcessorBasedControls           = %08x",
                          vm_procctl.all);
  HYPERPLATFORM_LOG_DEBUG("SecondaryProcessorBasedControls  = %08x",
                          vm_procctl2.all);

  // NOTE: Comment in any of those as needed
  const auto exception_bitmap =
      // 1 << InterruptionVector::kBreakpointException |
      // 1 << InterruptionVector::kGeneralProtectionException |
      // 1 << InterruptionVector::kPageFaultException |
      0;

  // Set up CR0 and CR4 bitmaps
  // - Where a bit is     masked, the shadow bit appears
  // - Where a bit is not masked, the actual bit appears
  // VM-exit occurs when a guest modifies any of those fields
  Cr0 cr0_mask = {};
  Cr0 cr0_shadow = {__readcr0()};

  Cr4 cr4_mask = {};
  Cr4 cr4_shadow = {__readcr4()};
  // For example, when we want to hide CR4.VMXE from the guest, comment in below
  // cr4_mask.fields.vmxe = true;
  // cr4_shadow.fields.vmxe = false;

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

  // clang-format off
  auto error = VmxStatus::kOk;

  /* 16-Bit Control Field */
  error |= UtilVmWrite(VmcsField::kVirtualProcessorId, KeGetCurrentProcessorNumberEx(nullptr) + 1);

  /* 16-Bit Guest-State Fields */
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
  error |= UtilVmWrite64(VmcsField::kIoBitmapA, UtilPaFromVa(processor_data->shared_data->io_bitmap_a));
  error |= UtilVmWrite64(VmcsField::kIoBitmapB, UtilPaFromVa(processor_data->shared_data->io_bitmap_b));
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
  error |= UtilVmWrite(VmcsField::kVmExitControls, vm_exitctl.all);
  error |= UtilVmWrite(VmcsField::kVmEntryControls, vm_entryctl.all);
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
  error |= UtilVmWrite(VmcsField::kGuestSysenterCs, UtilReadMsr(Msr::kIa32SysenterCs));

  /* 32-Bit Host-State Field */
  error |= UtilVmWrite(VmcsField::kHostIa32SysenterCs, UtilReadMsr(Msr::kIa32SysenterCs));

  /* Natural-Width Control Fields */
  error |= UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);
  error |= UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all);
  error |= UtilVmWrite(VmcsField::kCr0ReadShadow, cr0_shadow.all);
  error |= UtilVmWrite(VmcsField::kCr4ReadShadow, cr4_shadow.all);

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
_Use_decl_annotations_ static void VmpLaunchVm() {
  PAGED_CODE();

  auto error_code = UtilVmRead(VmcsField::kVmInstructionError);
  if (error_code) {
    HYPERPLATFORM_LOG_WARN("VM_INSTRUCTION_ERROR = %Iu", error_code);
  }

  auto vmx_status = static_cast<VmxStatus>(__vmx_vmlaunch());

  // Here should not executed with successful vmlaunch. Instead, the context
  // jumps to an address specified by GUEST_RIP.
  if (vmx_status == VmxStatus::kErrorWithStatus) {
    error_code = UtilVmRead(VmcsField::kVmInstructionError);
    HYPERPLATFORM_LOG_ERROR("VM_INSTRUCTION_ERROR = %Iu", error_code);
  }
  HYPERPLATFORM_COMMON_DBG_BREAK();
}

// Returns access right of the segment specified by the SegmentSelector for VMX
_Use_decl_annotations_ static ULONG VmpGetSegmentAccessRight(
    USHORT segment_selector) {
  PAGED_CODE();

  VmxRegmentDescriptorAccessRight access_right = {};
  if (segment_selector) {
    const SegmentSelector ss = {segment_selector};
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
  PAGED_CODE();

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
_Use_decl_annotations_ static SegmentDescriptor *VmpGetSegmentDescriptor(
    ULONG_PTR descriptor_table_base, USHORT segment_selector) {
  PAGED_CODE();

  const SegmentSelector ss = {segment_selector};
  return reinterpret_cast<SegmentDescriptor *>(
      descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}

// Returns a base address of segment_descriptor
_Use_decl_annotations_ static ULONG_PTR VmpGetSegmentBaseByDescriptor(
    const SegmentDescriptor *segment_descriptor) {
  PAGED_CODE();

  // Calculate a 32bit base address
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
  PAGED_CODE();

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

  HYPERPLATFORM_LOG_INFO("Uninstalling VMM.");
  auto status = UtilForEachProcessor(VmpStopVm, nullptr);
  if (NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_INFO("The VMM has been uninstalled.");
  } else {
    HYPERPLATFORM_LOG_WARN("The VMM has not been uninstalled (%08x).", status);
  }
  NT_ASSERT(!VmpIsHyperPlatformInstalled());
}

// Stops virtualization through a hypercall and frees all related memory
_Use_decl_annotations_ static NTSTATUS VmpStopVm(void *context) {
  UNREFERENCED_PARAMETER(context);
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("Terminating VMX for the processor %lu.",
                         KeGetCurrentProcessorNumberEx(nullptr));

  // Stop virtualization and get an address of the management structure
  ProcessorData *processor_data = nullptr;
  auto status = UtilVmCall(HypercallNumber::kTerminateVmm, &processor_data);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Clear CR4.VMXE, as there is no reason to leave the bit after vmxoff
  Cr4 cr4 = {__readcr4()};
  cr4.fields.vmxe = false;
  __writecr4(cr4.all);

  VmpFreeProcessorData(processor_data);
  return STATUS_SUCCESS;
}

// Frees all related memory
_Use_decl_annotations_ static void VmpFreeProcessorData(
    ProcessorData *processor_data) {
  PAGED_CODE();

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

  VmpFreeSharedData(processor_data);

  ExFreePoolWithTag(processor_data, kHyperPlatformCommonPoolTag);
}

// Decrement reference count of shared data and free it if no reference
_Use_decl_annotations_ static void VmpFreeSharedData(
    ProcessorData *processor_data) {
  PAGED_CODE();

  if (!processor_data->shared_data) {
    return;
  }

  if (InterlockedDecrement(&processor_data->shared_data->reference_count) !=
      0) {
    return;
  }

  HYPERPLATFORM_LOG_DEBUG("Freeing shared data...");
  if (processor_data->shared_data->io_bitmap_a) {
    ExFreePoolWithTag(processor_data->shared_data->io_bitmap_a,
                      kHyperPlatformCommonPoolTag);
  }
  if (processor_data->shared_data->msr_bitmap) {
    ExFreePoolWithTag(processor_data->shared_data->msr_bitmap,
                      kHyperPlatformCommonPoolTag);
  }
  ExFreePoolWithTag(processor_data->shared_data, kHyperPlatformCommonPoolTag);
}

// Tests if HyperPlatform is already installed
_Use_decl_annotations_ static bool VmpIsHyperPlatformInstalled() {
  PAGED_CODE();

  int cpu_info[4] = {};
  __cpuid(cpu_info, 1);
  const CpuFeaturesEcx cpu_features = {static_cast<ULONG_PTR>(cpu_info[2])};
  if (!cpu_features.fields.not_used) {
    return false;
  }

  __cpuid(cpu_info, kHyperVCpuidInterface);
  return cpu_info[0] == 'PpyH';
}

// Virtualizes the specified processor
_Use_decl_annotations_ NTSTATUS
VmHotplugCallback(const PROCESSOR_NUMBER &proc_num) {
  PAGED_CODE();

  // Switch to the processor 0 to get SharedProcessorData
  GROUP_AFFINITY affinity = {};
  GROUP_AFFINITY previous_affinity = {};
  KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

  SharedProcessorData *shared_data = nullptr;
  auto status =
      UtilVmCall(HypercallNumber::kGetSharedProcessorData, &shared_data);

  KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (!shared_data) {
    return STATUS_UNSUCCESSFUL;
  }

  // Switch to the newly added processor to virtualize it
  affinity.Group = proc_num.Group;
  affinity.Mask = 1ull << proc_num.Number;
  KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

  status = VmpStartVm(shared_data);

  KeRevertToUserGroupAffinityThread(&previous_affinity);
  return status;
}

}  // extern "C"
