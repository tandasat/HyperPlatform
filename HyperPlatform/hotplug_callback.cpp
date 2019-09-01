// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements hot-plug callback functions.

#include "hotplug_callback.h"
#include "common.h"
#include "log.h"
#include "vm.h"

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

static PROCESSOR_CALLBACK_FUNCTION HotplugCallbackpCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, HotplugCallbackInitialization)
#pragma alloc_text(PAGE, HotplugCallbackTermination)
#pragma alloc_text(PAGE, HotplugCallbackpCallbackRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PVOID g_hpp_callback_handle = nullptr;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Registers power callback
_Use_decl_annotations_ NTSTATUS HotplugCallbackInitialization() {
  PAGED_CODE()

  auto callback_handle = KeRegisterProcessorChangeCallback(
      HotplugCallbackpCallbackRoutine, nullptr, 0);
  if (!callback_handle) {
    return STATUS_UNSUCCESSFUL;
  }

  g_hpp_callback_handle = callback_handle;
  return STATUS_SUCCESS;
}

// Unregister power callback
_Use_decl_annotations_ void HotplugCallbackTermination() {
  PAGED_CODE()

  if (g_hpp_callback_handle) {
    KeDeregisterProcessorChangeCallback(g_hpp_callback_handle);
  }
}

_Use_decl_annotations_ static void HotplugCallbackpCallbackRoutine(
    PVOID callback_context, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT change_context,
    PNTSTATUS operation_status) {
  PAGED_CODE()
  UNREFERENCED_PARAMETER(callback_context);
  UNREFERENCED_PARAMETER(operation_status);

  if (change_context->State != KeProcessorAddCompleteNotify) {
    return;
  }

  HYPERPLATFORM_LOG_DEBUG("A new processor %hu:%hu has been added.",
                          change_context->ProcNumber.Group,
                          change_context->ProcNumber.Number);
  HYPERPLATFORM_COMMON_DBG_BREAK();

  auto status = VmHotplugCallback(change_context->ProcNumber);
  if (!NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_ERROR("Failed to virtualize the new processors.");
  }
}

}  // extern "C"
