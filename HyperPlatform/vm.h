// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to VMM initialization functions

#ifndef HYPERPLATFORM_VM_H_
#define HYPERPLATFORM_VM_H_

#include <ntddk.h>

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

/// Virtualizes all processors
/// @return STATUS_SUCCESS on success
///
/// Initializes a VMCS region and virtualizes (ie, enters the VMX non-root
/// operation mode) for each processor. Returns non STATUS_SUCCESS value if any
/// of processors failed to do so. In that case, this function de-virtualize
/// already virtualized processors.
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS VmInitialization();

/// De-virtualize all processors
_IRQL_requires_max_(PASSIVE_LEVEL) void VmTermination();

/// Virtualizes the specified processor
/// @param proc_num   A processor number to virtualize
/// @return STATUS_SUCCESS on success
///
/// The processor 0 must have already been virtualized, or it fails.
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS
    VmHotplugCallback(const PROCESSOR_NUMBER& proc_num);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // HYPERPLATFORM_VM_H_
