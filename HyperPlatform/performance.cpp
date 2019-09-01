// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements performance measurement functions.

#include "common.h"
#include "performance.h"
#include "log.h"

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

static PerfCollector::InitialOutputRoutine PerfpInitialOutputRoutine;
static PerfCollector::OutputRoutine PerfpOutputRoutine;
static PerfCollector::FinalOutputRoutine PerfpFinalOutputRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PerfInitialization)
#pragma alloc_text(PAGE, PerfTermination)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

PerfCollector* g_performance_collector;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS PerfInitialization() {
  PAGED_CODE()
  auto status = STATUS_SUCCESS;

  const auto perf_collector = static_cast<PerfCollector*>(ExAllocatePoolWithTag(
      NonPagedPool, sizeof(PerfCollector), kHyperPlatformCommonPoolTag));
  if (!perf_collector) {
    return STATUS_MEMORY_NOT_ALLOCATED;
  }

  // No lock to avoid calling kernel APIs from VMM and race condition here is
  // not an issue.
  perf_collector->Initialize(PerfpOutputRoutine, PerfpInitialOutputRoutine,
                             PerfpFinalOutputRoutine);

  g_performance_collector = perf_collector;
  return status;
}

_Use_decl_annotations_ void PerfTermination() {
  PAGED_CODE()

  if (g_performance_collector) {
    g_performance_collector->Terminate();
    ExFreePoolWithTag(g_performance_collector, kHyperPlatformCommonPoolTag);
    g_performance_collector = nullptr;
  }
}

/*_Use_decl_annotations_*/ ULONG64 PerfGetTime() {
  LARGE_INTEGER counter = KeQueryPerformanceCounter(nullptr);
  return static_cast<ULONG64>(counter.QuadPart);
}

_Use_decl_annotations_ static void PerfpInitialOutputRoutine(
    void* output_context) {
  UNREFERENCED_PARAMETER(output_context);
  HYPERPLATFORM_LOG_INFO("%-45s,%-20s,%-20s", "FunctionName(Line)",
                         "Execution Count", "Elapsed Time");
}

_Use_decl_annotations_ static void PerfpOutputRoutine(
    const char* location_name, ULONG64 total_execution_count,
    ULONG64 total_elapsed_time, void* output_context) {
  UNREFERENCED_PARAMETER(output_context);
  HYPERPLATFORM_LOG_INFO("%-45s,%20I64u,%20I64u,", location_name,
                         total_execution_count, total_elapsed_time);
}

_Use_decl_annotations_ static void PerfpFinalOutputRoutine(
    void* output_context) {
  UNREFERENCED_PARAMETER(output_context);
}
