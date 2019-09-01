// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements power callback functions.

#include "power_callback.h"
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

static CALLBACK_FUNCTION PowerCallbackpCallbackRoutine;

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, PowerCallbackInitialization)
#pragma alloc_text(PAGE, PowerCallbackTermination)
#pragma alloc_text(PAGE, PowerCallbackpCallbackRoutine)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static PCALLBACK_OBJECT g_pcp_callback_object = nullptr;
static PVOID g_pcp_registration = nullptr;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Registers power callback
_Use_decl_annotations_ NTSTATUS PowerCallbackInitialization() {
  PAGED_CODE()

  UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
  OBJECT_ATTRIBUTES oa =
      RTL_CONSTANT_OBJECT_ATTRIBUTES(&name, OBJ_CASE_INSENSITIVE);

  auto status = ExCreateCallback(&g_pcp_callback_object, &oa, FALSE, TRUE);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  g_pcp_registration = ExRegisterCallback(
      g_pcp_callback_object, PowerCallbackpCallbackRoutine, nullptr);
  if (!g_pcp_registration) {
    ObDereferenceObject(g_pcp_callback_object);
    g_pcp_callback_object = nullptr;
    return STATUS_UNSUCCESSFUL;
  }
  return status;
}

// Unregister power callback
_Use_decl_annotations_ void PowerCallbackTermination() {
  PAGED_CODE()

  if (g_pcp_registration) {
    ExUnregisterCallback(g_pcp_registration);
  }
  if (g_pcp_callback_object) {
    ObDereferenceObject(g_pcp_callback_object);
  }
}

// Power callback routine dealing with hibernate and sleep
_Use_decl_annotations_ static void PowerCallbackpCallbackRoutine(
    PVOID callback_context, PVOID argument1, PVOID argument2) {
  UNREFERENCED_PARAMETER(callback_context);
  PAGED_CODE()

  HYPERPLATFORM_LOG_DEBUG("PowerCallback %p:%p", argument1, argument2);

  if (argument1 != reinterpret_cast<void*>(PO_CB_SYSTEM_STATE_LOCK)) {
    return;
  }

  HYPERPLATFORM_COMMON_DBG_BREAK();

  if (argument2) {
    // the computer has just reentered S0.
    HYPERPLATFORM_LOG_INFO("Resuming the system...");
    auto status = VmInitialization();
    if (!NT_SUCCESS(status)) {
      HYPERPLATFORM_LOG_ERROR(
          "Failed to re-virtualize processors. Please unload the driver.");
    }
  } else {
    // the computer is about to exit system power state S0
    HYPERPLATFORM_LOG_INFO("Suspending the system...");
    VmTermination();
  }
}

}  // extern "C"
