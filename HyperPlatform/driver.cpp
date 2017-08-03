// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "../../Hypervisor/Hypervisor.h"

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

DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// A driver entry point



NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) 
{

#ifndef _DRIVEROBJECT
  UNREFERENCED_PARAMETER(driver_object);
#endif

  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();

  HYPERPLATFORM_LOG_INFO("DriverEntry");

  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\Hypervisor.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;



  auto status = STATUS_UNSUCCESSFUL;
#ifdef _DRIVEROBJECT
  driver_object->DriverUnload = DriverpDriverUnload;
#endif
  HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

#ifdef _LOGGING
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (!NT_SUCCESS(status)) {
    return status;
  }
#endif

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }

  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization();
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  //status = PowerCallbackInitialization();
  //if (!NT_SUCCESS(status)) {
  //  UtilTermination();
  //  PerfTermination();
  //  GlobalObjectTermination();
  //  LogTermination();
  //  return status;
  //}

  //// Initialize hot-plug callback
  //status = HotplugCallbackInitialization();
  //if (!NT_SUCCESS(status)) {
  //  PowerCallbackTermination();
  //  UtilTermination();
  //  PerfTermination();
  //  GlobalObjectTermination();
  //  LogTermination();
  //  return status;
  //}

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Register re-initialization for the log functions if needed
//  if (need_reinitialization) {
//    LogRegisterReinitialization(driver_object);
//  }

  HYPERPLATFORM_LOG_INFO("The VMM has been installed.");
  return status;
}

// Unload handler
#ifdef _DRIVEROBJECT
_Use_decl_annotations_ static void DriverpDriverUnload(PDRIVER_OBJECT driver_object) 
{
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  VmTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
}
#endif

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
