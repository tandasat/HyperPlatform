// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements primitive utility functions.

#include "util.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "log.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Use RtlPcToFileHeader if available. Using the API causes a broken font bug
// on the 64 bit Windows 10 and should be avoided. This flag exist for only
// futher investigation.
static const auto kUtilpUseRtlPcToFileHeader = false;

#if defined(_AMD64_)

// Base addresses of page structures. Use !pte to obtain them.
static const auto kUtilpPxeBase = 0xfffff6fb7dbed000ull;
static const auto kUtilpPpeBase = 0xfffff6fb7da00000ull;
static const auto kUtilpPdeBase = 0xfffff6fb40000000ull;
static const auto kUtilpPteBase = 0xfffff68000000000ull;

// Get the highest 25 bits
static const auto kUtilpPxiShift = 39ull;

// Get the highest 34 bits
static const auto kUtilpPpiShift = 30ull;

// Get the highest 43 bits
static const auto kUtilpPdiShift = 21ull;

// Get the highest 52 bits
static const auto kUtilpPtiShift = 12ull;

// Use  9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const auto kUtilpPxiMask = 0x1ffull;

// Use 18 bits; 0b0000_0000_0000_0000_0011_1111_1111_1111_1111
static const auto kUtilpPpiMask = 0x3ffffull;

// Use 27 bits; 0b0000_0000_0111_1111_1111_1111_1111_1111_1111
static const auto kUtilpPdiMask = 0x7ffffffull;

// Use 36 bits; 0b1111_1111_1111_1111_1111_1111_1111_1111_1111
static const auto kUtilpPtiMask = 0xfffffffffull;

#elif defined(_X86_)

// Base addresses of page structures. Use !pte to obtain them.
static const auto kUtilpPdeBase = 0xc0300000;
static const auto kUtilpPteBase = 0xc0000000;

// Get the highest 10 bits
static const auto kUtilpPdiShift = 22;

// Get the highest 20 bits
static const auto kUtilpPtiShift = 12;

// Use 10 bits; 0b0000_0000_0000_0000_0000_0000_0011_1111_1111
static const auto kUtilpPdiMask = 0x3ff;

// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
static const auto kUtilpPtiMask = 0xfffff;

#endif

// Base addresses of page structures. Use !pte to obtain them.
static const auto kUtilpPdeBasePae = 0xc0600000;
static const auto kUtilpPteBasePae = 0xc0000000;

// Get the highest 11 bits
static const auto kUtilpPdiShiftPae = 21;

// Get the highest 20 bits
static const auto kUtilpPtiShiftPae = 12;

// Use 11 bits; 0b0000_0000_0000_0000_0000_0000_0111_1111_1111
static const auto kUtilpPdiMaskPae = 0x7ff;

// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
static const auto kUtilpPtiMaskPae = 0xfffff;

////////////////////////////////////////////////////////////////////////////////
//
// types
//

PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

using RtlPcToFileHeaderType = decltype(RtlPcToFileHeader);

_Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) NTKERNELAPI
    _When_(return != NULL, _Post_writable_byte_size_(NumberOfBytes)) PVOID
    MmAllocateContiguousNodeMemory(
        _In_ SIZE_T NumberOfBytes,
        _In_ PHYSICAL_ADDRESS LowestAcceptableAddress,
        _In_ PHYSICAL_ADDRESS HighestAcceptableAddress,
        _In_opt_ PHYSICAL_ADDRESS BoundaryAddressMultiple, _In_ ULONG Protect,
        _In_ NODE_REQUIREMENT PreferredNode);

using MmAllocateContiguousNodeMemoryType =
    decltype(MmAllocateContiguousNodeMemory);

// dt nt!_LDR_DATA_TABLE_ENTRY
struct LdrDataTableEntry {
  LIST_ENTRY in_load_order_links;
  LIST_ENTRY in_memory_order_links;
  LIST_ENTRY in_initialization_order_links;
  void *dll_base;
  void *entry_point;
  ULONG size_of_image;
  UNICODE_STRING full_dll_name;
  // ...
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    UtilpInitializeRtlPcToFileHeader(_In_ PDRIVER_OBJECT driver_object);

_Success_(return != nullptr) static PVOID NTAPI
    UtilpUnsafePcToFileHeader(_In_ PVOID pc_value, _Out_ PVOID *base_of_image);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    UtilpInitializePhysicalMemoryRanges();

_IRQL_requires_max_(PASSIVE_LEVEL) static PhysicalMemoryDescriptor
    *UtilpBuildPhysicalMemoryRanges();

#if defined(_AMD64_)
static HardwarePte *UtilpAddressToPxe(_In_ const void *address);

static HardwarePte *UtilpAddressToPpe(_In_ const void *address);
#endif

static HardwarePte *UtilpAddressToPde(_In_ const void *address);

static HardwarePte *UtilpAddressToPte(_In_ const void *address);

static HardwarePte *UtilpAddressToPdePAE(_In_ const void *address);

static HardwarePte *UtilpAddressToPtePAE(_In_ const void *address);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, UtilInitialization)
#pragma alloc_text(PAGE, UtilTermination)
#pragma alloc_text(INIT, UtilpInitializeRtlPcToFileHeader)
#pragma alloc_text(INIT, UtilpInitializePhysicalMemoryRanges)
#pragma alloc_text(INIT, UtilpBuildPhysicalMemoryRanges)
#pragma alloc_text(PAGE, UtilSleep)
#pragma alloc_text(PAGE, UtilGetSystemProcAddress)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static RtlPcToFileHeaderType *g_utilp_RtlPcToFileHeader;

static LIST_ENTRY *g_utilp_PsLoadedModuleList;

static PhysicalMemoryDescriptor *g_utilp_physical_memory_ranges;

static MmAllocateContiguousNodeMemoryType
    *g_utilp_MmAllocateContiguousNodeMemory;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initializes utility functions
_Use_decl_annotations_ NTSTATUS
UtilInitialization(PDRIVER_OBJECT driver_object) {
  PAGED_CODE();

  auto status = UtilpInitializeRtlPcToFileHeader(driver_object);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = UtilpInitializePhysicalMemoryRanges();
  if (!NT_SUCCESS(status)) {
    return status;
  }

  g_utilp_MmAllocateContiguousNodeMemory =
      reinterpret_cast<MmAllocateContiguousNodeMemoryType *>(
          UtilGetSystemProcAddress(L"MmAllocateContiguousNodeMemory"));
  return status;
}

// Terminates utility functions
_Use_decl_annotations_ void UtilTermination() {
  PAGED_CODE();

  if (g_utilp_physical_memory_ranges) {
    ExFreePoolWithTag(g_utilp_physical_memory_ranges,
                      kHyperPlatformCommonPoolTag);
  }
}

// Locates RtlPcToFileHeader
_Use_decl_annotations_ static NTSTATUS UtilpInitializeRtlPcToFileHeader(
    PDRIVER_OBJECT driver_object) {
  PAGED_CODE();

  if (kUtilpUseRtlPcToFileHeader) {
    const auto p_RtlPcToFileHeader =
        UtilGetSystemProcAddress(L"RtlPcToFileHeader");
    if (p_RtlPcToFileHeader) {
      g_utilp_RtlPcToFileHeader =
          reinterpret_cast<RtlPcToFileHeaderType *>(p_RtlPcToFileHeader);
      return STATUS_SUCCESS;
    }
  }

#pragma warning(push)
#pragma warning(disable : 28175)
  auto module =
      reinterpret_cast<LdrDataTableEntry *>(driver_object->DriverSection);
#pragma warning(pop)

  g_utilp_PsLoadedModuleList = module->in_load_order_links.Flink;
  g_utilp_RtlPcToFileHeader = UtilpUnsafePcToFileHeader;
  return STATUS_SUCCESS;
}

// A fake RtlPcToFileHeader without accquireing PsLoadedModuleSpinLock. Thus, it
// is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.
_Use_decl_annotations_ static PVOID NTAPI
UtilpUnsafePcToFileHeader(PVOID pc_value, PVOID *base_of_image) {
  if (pc_value < MmSystemRangeStart) {
    return nullptr;
  }

  const auto head = g_utilp_PsLoadedModuleList;
  for (auto current = head->Flink; current != head; current = current->Flink) {
    const auto module =
        CONTAINING_RECORD(current, LdrDataTableEntry, in_load_order_links);
    const auto driver_end = reinterpret_cast<void *>(
        reinterpret_cast<ULONG_PTR>(module->dll_base) + module->size_of_image);
    if (UtilIsInBounds(pc_value, module->dll_base, driver_end)) {
      *base_of_image = module->dll_base;
      return module->dll_base;
    }
  }
  return nullptr;
}

// A wrapper of RtlPcToFileHeader
_Use_decl_annotations_ PVOID UtilPcToFileHeader(PVOID pc_value) {
  void *base = nullptr;
  return g_utilp_RtlPcToFileHeader(pc_value, &base);
}

// Initializes the physical memory ranges
_Use_decl_annotations_ static NTSTATUS UtilpInitializePhysicalMemoryRanges() {
  PAGED_CODE();

  const auto ranges = UtilpBuildPhysicalMemoryRanges();
  if (!ranges) {
    return STATUS_UNSUCCESSFUL;
  }

  g_utilp_physical_memory_ranges = ranges;

  for (auto i = 0ul; i < ranges->number_of_runs; ++i) {
    const auto base_addr =
        static_cast<ULONG64>(ranges->run[i].base_page) * PAGE_SIZE;
    HYPERPLATFORM_LOG_DEBUG("Physical Memory Range: %016llx - %016llx",
                            base_addr,
                            base_addr + ranges->run[i].page_count * PAGE_SIZE);
  }

  const auto pm_size =
      static_cast<ULONG64>(ranges->number_of_pages) * PAGE_SIZE;
  HYPERPLATFORM_LOG_DEBUG("Physical Memory Total: %llu KB", pm_size / 1024);

  return STATUS_SUCCESS;
}

// Builds the physical memory ranges
_Use_decl_annotations_ static PhysicalMemoryDescriptor *
UtilpBuildPhysicalMemoryRanges() {
  PAGED_CODE();

  const auto pm_ranges = MmGetPhysicalMemoryRanges();
  if (!pm_ranges) {
    return nullptr;
  }

  PFN_COUNT number_of_runs = 0;
  PFN_NUMBER number_of_pages = 0;
  for (/**/; /**/; ++number_of_runs) {
    const auto range = &pm_ranges[number_of_runs];
    if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
      break;
    }
    number_of_pages +=
        static_cast<PFN_NUMBER>(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
  }
  if (number_of_runs == 0) {
    ExFreePoolWithTag(pm_ranges, 'hPmM');
    return nullptr;
  }

  const auto memory_block_size =
      sizeof(PhysicalMemoryDescriptor) +
      sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
  const auto pm_block =
      reinterpret_cast<PhysicalMemoryDescriptor *>(ExAllocatePoolWithTag(
          NonPagedPoolNx, memory_block_size, kHyperPlatformCommonPoolTag));
  if (!pm_block) {
    ExFreePoolWithTag(pm_ranges, 'hPmM');
    return nullptr;
  }
  RtlZeroMemory(pm_block, memory_block_size);

  pm_block->number_of_runs = number_of_runs;
  pm_block->number_of_pages = number_of_pages;

  for (auto run_index = 0ul; run_index < number_of_runs; run_index++) {
    auto current_run = &pm_block->run[run_index];
    auto current_block = &pm_ranges[run_index];
    current_run->base_page = static_cast<ULONG_PTR>(
        UtilPfnFromPa(current_block->BaseAddress.QuadPart));
    current_run->page_count = static_cast<ULONG_PTR>(
        BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
  }

  ExFreePoolWithTag(pm_ranges, 'hPmM');
  return pm_block;
}

// Returns the physical memory ranges
/*_Use_decl_annotations_*/ const PhysicalMemoryDescriptor *
UtilGetPhysicalMemoryRanges() {
  return g_utilp_physical_memory_ranges;
}

// Execute a given callback routine on all processors in DPC_LEVEL. Returns
// STATUS_SUCCESS when all callback returned STATUS_SUCCESS as well. When
// one of callbacks returns anything but STATUS_SUCCESS, this function stops
// to call remaining callbacks and returns the value.
_Use_decl_annotations_ NTSTATUS
UtilForEachProcessor(NTSTATUS (*callback_routine)(void *), void *context) {
  const auto number_of_processors =
      KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
  for (ULONG processor_index = 0; processor_index < number_of_processors;
       processor_index++) {
    PROCESSOR_NUMBER processor_number = {};
    auto status =
        KeGetProcessorNumberFromIndex(processor_index, &processor_number);
    if (!NT_SUCCESS(status)) {
      return status;
    }

    // Switch the current processor
    GROUP_AFFINITY affinity = {};
    affinity.Group = processor_number.Group;
    affinity.Mask = 1ull << processor_number.Number;
    GROUP_AFFINITY previous_affinity = {};
    KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

    // Execute callback
    status = callback_routine(context);

    KeRevertToUserGroupAffinityThread(&previous_affinity);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }
  return STATUS_SUCCESS;
}

// Sleep the current thread's execution for Millisecond milli-seconds.
_Use_decl_annotations_ NTSTATUS UtilSleep(LONG Millisecond) {
  PAGED_CODE();

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000 * Millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

// memmem().
_Use_decl_annotations_ void *UtilMemMem(const void *search_base,
                                        SIZE_T search_size, const void *pattern,
                                        SIZE_T pattern_size) {
  if (pattern_size > search_size) {
    return nullptr;
  }
  auto base = static_cast<const char *>(search_base);
  for (SIZE_T i = 0; i <= search_size - pattern_size; i++) {
    if (RtlCompareMemory(pattern, &base[i], pattern_size) == pattern_size) {
      return const_cast<char *>(&base[i]);
    }
  }
  return nullptr;
}

// A wrapper of MmGetSystemRoutineAddress
_Use_decl_annotations_ void *UtilGetSystemProcAddress(
    const wchar_t *proc_name) {
  PAGED_CODE();

  UNICODE_STRING proc_name_U = {};
  RtlInitUnicodeString(&proc_name_U, proc_name);
  return MmGetSystemRoutineAddress(&proc_name_U);
}

// Returns true when a system is on the x86 PAE mode
/*_Use_decl_annotations_*/ bool UtilIsX86Pae() {
  return (!IsX64() && Cr4{__readcr4()}.fields.pae);
}

// Return true if the given address is accessible. It does not prevent a race
// condition.
_Use_decl_annotations_ bool UtilIsAccessibleAddress(void *address) {
#if defined(_AMD64_)
  const auto pxe = UtilpAddressToPxe(address);
  const auto ppe = UtilpAddressToPpe(address);
  if (!pxe->valid || !ppe->valid) {
    return false;
  }
#endif

  const auto is_x86_pae = UtilIsX86Pae();
  const auto pde =
      (is_x86_pae) ? UtilpAddressToPdePAE(address) : UtilpAddressToPde(address);
  const auto pte =
      (is_x86_pae) ? UtilpAddressToPtePAE(address) : UtilpAddressToPte(address);
  if (!pde->valid) {
    return false;
  }
  if (pde->large_page) {
    return true;  // A large page is always memory resident
  }
  if (!pte || !pte->valid) {
    return false;
  }
  return true;
}

// Virtual Address Interpretation For Handling PTEs
//
// -- On x64
// Sign extension                     16 bits
// Page map level 4 selector           9 bits
// Page directory pointer selector     9 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
// ^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
// Sign extension    PML4      PDPT      PD        PT        Offset
//
// -- On x86(PAE)
// Page directory pointer selector     2 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 10 000011011 000001101 001001110101
// ^^ ~~~~~~~~~ ^^^^^^^^^ ~~~~~~~~~~~~
// PDPT PD      PT        Offset
//
// -- On x86 and ARM
// Page directory selector            10 bits
// Page table selector                10 bits
// Byte within page                   12 bits
// 1000001101 1000001101 001001110101
// ~~~~~~~~~~ ^^^^^^^^^^ ~~~~~~~~~~~~
// PD         PT         Offset
//
//
//                                   x64   x86(PAE)  x86   ARM
// Page map level 4 selector           9          -    -     -
// Page directory pointer selector     9          2    -     -
// Page directory selector             9          9   10    10
// Page table selector                 9          9   10    10
// Byte within page                   12         12   12    12
//
// 6666555555555544444444443333333333222222222211111111110000000000
// 3210987654321098765432109876543210987654321098765432109876543210
// ----------------------------------------------------------------
// aaaaaaaaaaaaaaaabbbbbbbbbcccccccccdddddddddeeeeeeeeeffffffffffff  x64
// ................................ccdddddddddeeeeeeeeeffffffffffff  x86(PAE)
// ................................ddddddddddeeeeeeeeeeffffffffffff  x86
// ................................ddddddddddeeeeeeeeeeffffffffffff  ARM
//
// a = Sign extension, b = PML4, c = PDPT, d = PD, e = PT, f = Offset

#if defined(_AMD64_)
// Return an address of PXE
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPxe(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto pxe_index = (addr >> kUtilpPxiShift) & kUtilpPxiMask;
  const auto offset = pxe_index * sizeof(HardwarePte);
  return reinterpret_cast<HardwarePte *>(kUtilpPxeBase + offset);
}

// Return an address of PPE
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPpe(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto ppe_index = (addr >> kUtilpPpiShift) & kUtilpPpiMask;
  const auto offset = ppe_index * sizeof(HardwarePte);
  return reinterpret_cast<HardwarePte *>(kUtilpPpeBase + offset);
}
#endif

// Return an address of PDE
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPde(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto pde_index = (addr >> kUtilpPdiShift) & kUtilpPdiMask;
  const auto offset = pde_index * sizeof(HardwarePte);
  return reinterpret_cast<HardwarePte *>(kUtilpPdeBase + offset);
}

// Return an address of PTE
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPte(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto pte_index = (addr >> kUtilpPtiShift) & kUtilpPtiMask;
  const auto offset = pte_index * sizeof(HardwarePte);
  return reinterpret_cast<HardwarePte *>(kUtilpPteBase + offset);
}

// Return an address of PDE for PAE enabled x86
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPdePAE(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto pde_index = (addr >> kUtilpPdiShiftPae) & kUtilpPdiMaskPae;
  const auto offset = pde_index * sizeof(HardwarePteX86Pae);
  return reinterpret_cast<HardwarePte *>(kUtilpPdeBasePae + offset);
}

// Return an address of PTE for PAE enabled x86
_Use_decl_annotations_ static HardwarePte *UtilpAddressToPtePAE(
    const void *address) {
  const auto addr = reinterpret_cast<ULONG_PTR>(address);
  const auto pte_index = (addr >> kUtilpPtiShiftPae) & kUtilpPtiMaskPae;
  const auto offset = pte_index * sizeof(HardwarePteX86Pae);
  return reinterpret_cast<HardwarePte *>(kUtilpPteBasePae + offset);
}

// VA -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromVa(void *va) {
  const auto pa = MmGetPhysicalAddress(va);
  return pa.QuadPart;
}

// VA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromVa(void *va) {
  return UtilPfnFromPa(UtilPaFromVa(va));
}

// PA -> PFN
_Use_decl_annotations_ PFN_NUMBER UtilPfnFromPa(ULONG64 pa) {
  return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
}

// PA -> VA
_Use_decl_annotations_ void *UtilVaFromPa(ULONG64 pa) {
  PHYSICAL_ADDRESS pa2 = {};
  pa2.QuadPart = pa;
  return MmGetVirtualForPhysical(pa2);
}

// PNF -> PA
_Use_decl_annotations_ ULONG64 UtilPaFromPfn(PFN_NUMBER pfn) {
  return pfn << PAGE_SHIFT;
}

// PFN -> VA
_Use_decl_annotations_ void *UtilVaFromPfn(PFN_NUMBER pfn) {
  return UtilVaFromPa(UtilPaFromPfn(pfn));
}

// Allocates continuous physical memory
_Use_decl_annotations_ void *UtilAllocateContiguousMemory(
    SIZE_T number_of_bytes) {
  PHYSICAL_ADDRESS highest_acceptable_address = {};
  highest_acceptable_address.QuadPart = -1;
  if (g_utilp_MmAllocateContiguousNodeMemory) {
    // Allocate NX physical memory
    PHYSICAL_ADDRESS lowest_acceptable_address = {};
    PHYSICAL_ADDRESS boundary_address_multiple = {};
    return g_utilp_MmAllocateContiguousNodeMemory(
        number_of_bytes, lowest_acceptable_address, highest_acceptable_address,
        boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
  } else {
#pragma warning(push)
#pragma warning(disable : 30029)
    return MmAllocateContiguousMemory(number_of_bytes,
                                      highest_acceptable_address);
#pragma warning(pop)
  }
}

// Frees an address allocated by UtilAllocateContiguousMemory()
_Use_decl_annotations_ void UtilFreeContiguousMemory(void *base_address) {
  MmFreeContiguousMemory(base_address);
}

// Executes VMCALL
_Use_decl_annotations_ NTSTATUS UtilVmCall(HypercallNumber hypercall_number,
                                           void *context) {
  EXCEPTION_POINTERS *exp_info = nullptr;
  __try {
    const auto vmx_status = static_cast<VmxStatus>(
        AsmVmxCall(static_cast<ULONG>(hypercall_number), context));
    return (vmx_status == VmxStatus::kOk) ? STATUS_SUCCESS
                                          : STATUS_UNSUCCESSFUL;
  } __except (exp_info = GetExceptionInformation(), EXCEPTION_EXECUTE_HANDLER) {
    const auto status = GetExceptionCode();
    HYPERPLATFORM_COMMON_DBG_BREAK();
    HYPERPLATFORM_LOG_WARN_SAFE("Exception %08x at %p",
                                exp_info->ExceptionRecord->ExceptionCode,
                                exp_info->ExceptionRecord->ExceptionAddress);
    return status;
  }
}

// Debug prints registers
_Use_decl_annotations_ void UtilDumpGpRegisters(const AllRegisters *all_regs,
                                                ULONG_PTR stack_pointer) {
  const auto current_irql = KeGetCurrentIrql();
  if (current_irql < DISPATCH_LEVEL) {
    KeRaiseIrqlToDpcLevel();
  }

#if defined(_AMD64_)
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "Context at %p: "
      "rax= %p rbx= %p rcx= %p "
      "rdx= %p rsi= %p rdi= %p "
      "rsp= %p rbp= %p "
      " r8= %p  r9= %p r10= %p "
      "r11= %p r12= %p r13= %p "
      "r14= %p r15= %p efl= %08x",
      _ReturnAddress(), all_regs->gp.ax, all_regs->gp.bx, all_regs->gp.cx,
      all_regs->gp.dx, all_regs->gp.si, all_regs->gp.di, stack_pointer,
      all_regs->gp.bp, all_regs->gp.r8, all_regs->gp.r9, all_regs->gp.r10,
      all_regs->gp.r11, all_regs->gp.r12, all_regs->gp.r13, all_regs->gp.r14,
      all_regs->gp.r15, all_regs->flags.all);
#else
  HYPERPLATFORM_LOG_DEBUG_SAFE(
      "Context at %p: "
      "eax= %p ebx= %p ecx= %p "
      "edx= %p esi= %p edi= %p "
      "esp= %p ebp= %p efl= %08x",
      _ReturnAddress(), all_regs->gp.ax, all_regs->gp.bx, all_regs->gp.cx,
      all_regs->gp.dx, all_regs->gp.si, all_regs->gp.di, stack_pointer,
      all_regs->gp.bp, all_regs->flags.all);
#endif

  if (current_irql < DISPATCH_LEVEL) {
    KeLowerIrql(current_irql);
  }
}

// Reads natural-width VMCS
_Use_decl_annotations_ ULONG_PTR UtilVmRead(VmcsField field) {
  size_t field_value = 0;
  const auto vmx_status = static_cast<VmxStatus>(
      __vmx_vmread(static_cast<size_t>(field), &field_value));
  if (vmx_status != VmxStatus::kOk) {
    HYPERPLATFORM_LOG_ERROR_SAFE("__vmx_vmread(0x%08x) failed with an error %d",
                                 field, vmx_status);
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
  return field_value;
}

// Reads 64bit-width VMCS
_Use_decl_annotations_ ULONG64 UtilVmRead64(VmcsField field) {
#if defined(_AMD64_)
  return UtilVmRead(field);
#else
  // Only 64bit fields should be given on x86 because it access field + 1 too.
  NT_ASSERT(UtilIsInBounds(field, VmcsField::kIoBitmapA,
                           VmcsField::kHostIa32PerfGlobalCtrlHigh));

  ULARGE_INTEGER value64 = {};
  value64.LowPart = UtilVmRead(field);
  value64.HighPart =
      UtilVmRead(static_cast<VmcsField>(static_cast<ULONG>(field) + 1));
  return value64.QuadPart;
#endif
}

// Writes natural-width VMCS
_Use_decl_annotations_ VmxStatus UtilVmWrite(VmcsField field,
                                             ULONG_PTR field_value) {
  const auto vmx_status = static_cast<VmxStatus>(
      __vmx_vmwrite(static_cast<size_t>(field), field_value));
  if (vmx_status != VmxStatus::kOk) {
    HYPERPLATFORM_LOG_ERROR_SAFE(
        "__vmx_vmwrite(0x%08x) failed with an error %d", field, vmx_status);
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
  return vmx_status;
}

// Writes 64bit-width VMCS
_Use_decl_annotations_ VmxStatus UtilVmWrite64(VmcsField field,
                                               ULONG64 field_value) {
#if defined(_AMD64_)
  return UtilVmWrite(field, field_value);
#else
  // Only 64bit fields should be given on x86 because it access field + 1 too.
  NT_ASSERT(UtilIsInBounds(field, VmcsField::kIoBitmapA,
                           VmcsField::kHostIa32PerfGlobalCtrlHigh));

  ULARGE_INTEGER value64 = {};
  value64.QuadPart = field_value;
  const auto vmx_status = UtilVmWrite(field, value64.LowPart);
  if (vmx_status != VmxStatus::kOk) {
    return vmx_status;
  }
  return UtilVmWrite(static_cast<VmcsField>(static_cast<ULONG>(field) + 1),
                     value64.HighPart);
#endif
}

// Reads natural-width MSR
_Use_decl_annotations_ ULONG_PTR UtilReadMsr(Msr msr) {
  return static_cast<ULONG_PTR>(__readmsr(static_cast<unsigned long>(msr)));
}

// Reads 64bit-width MSR
_Use_decl_annotations_ ULONG64 UtilReadMsr64(Msr msr) {
  return __readmsr(static_cast<unsigned long>(msr));
}

// Writes natural-width MSR
_Use_decl_annotations_ void UtilWriteMsr(Msr msr, ULONG_PTR value) {
  __writemsr(static_cast<unsigned long>(msr), value);
}

// Writes 64bit-width MSR
_Use_decl_annotations_ void UtilWriteMsr64(Msr msr, ULONG64 value) {
  __writemsr(static_cast<unsigned long>(msr), value);
}

// Executes the INVEPT instruction and invalidates EPT entry cache
/*_Use_decl_annotations_*/ VmxStatus UtilInveptAll() {
  InvEptDescriptor desc = {};
  const auto vmx_status =
      static_cast<VmxStatus>(AsmInvept(InvEptType::kGlobalInvalidation, &desc));
  if (vmx_status != VmxStatus::kOk) {
    HYPERPLATFORM_LOG_ERROR_SAFE(
        "UtilInveptAll(Global) failed with an error %d", vmx_status);
    HYPERPLATFORM_COMMON_DBG_BREAK();
  }
  return vmx_status;
}

// Loads the PDPTE registers from CR3 to VMCS
_Use_decl_annotations_ void UtilLoadPdptes(ULONG_PTR cr3_value) {
  const auto current_cr3 = __readcr3();

  // Have to load cr3 to make UtilPfnFromVa() work properly.
  __writecr3(cr3_value);

  // Gets PDPTEs fomr CR3
  PdptrRegister pd_pointers[4] = {};
  for (auto i = 0ul; i < 4; ++i) {
    const auto pd_addr = kUtilpPdeBasePae + i * PAGE_SIZE;
    pd_pointers[i].fields.present = true;
    pd_pointers[i].fields.page_directory_pa =
        UtilPfnFromVa(reinterpret_cast<void *>(pd_addr));
  }

  __writecr3(current_cr3);
  UtilVmWrite64(VmcsField::kGuestPdptr0, pd_pointers[0].all);
  UtilVmWrite64(VmcsField::kGuestPdptr1, pd_pointers[1].all);
  UtilVmWrite64(VmcsField::kGuestPdptr2, pd_pointers[2].all);
  UtilVmWrite64(VmcsField::kGuestPdptr3, pd_pointers[3].all);
}

// Does RtlCopyMemory safely even if destination is a read only region
_Use_decl_annotations_ NTSTATUS UtilForceCopyMemory(void *destination,
                                                    const void *source,
                                                    SIZE_T length) {
  auto mdl = IoAllocateMdl(destination, static_cast<ULONG>(length), FALSE,
                           FALSE, nullptr);
  if (!mdl) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  MmBuildMdlForNonPagedPool(mdl);

#pragma warning(push)
#pragma warning(disable : 28145)
  // Following MmMapLockedPagesSpecifyCache() call causes bug check in case
  // you are using Driver Verifier. The reason is explained as followings:
  //
  // A driver must not try to create more than one system-address-space
  // mapping for an MDL. Additionally, because an MDL that is built by the
  // MmBuildMdlForNonPagedPool routine is already mapped to the system
  // address space, a driver must not try to map this MDL into the system
  // address space again by using the MmMapLockedPagesSpecifyCache routine.
  // -- MSDN
  //
  // This flag modification hacks Driver Verifier's check and prevent leading
  // bug check.
  mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
  mdl->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

  const auto writable_dest =
      MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE,
                                   NormalPagePriority | MdlMappingNoExecute);
  if (!writable_dest) {
    IoFreeMdl(mdl);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlCopyMemory(writable_dest, source, length);
  MmUnmapLockedPages(writable_dest, mdl);
  IoFreeMdl(mdl);
  return STATUS_SUCCESS;
}

}  // extern "C"
