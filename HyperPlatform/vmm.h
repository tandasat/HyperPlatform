// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to VMM functions.

#ifndef HYPERPLATFORM_VMM_H_
#define HYPERPLATFORM_VMM_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// A backdoor code to tell the VMM that a caller knows about the VMM
static const ULONG kHyperPlatformVmmBackdoorCode = 'gniP';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

/// Represents VMM related data shared across all processors
struct SharedProcessorData {
  volatile long reference_count;  ///< Number of processors sharing this data
  void* msr_bitmap;               ///< A bitmap to suppress MSR I/O VM-exit
};

/// Represents VMM related data associated with each processor
struct ProcessorData {
  SharedProcessorData* shared_data;         ///< Shared data
  void* vmm_stack_limit;                    ///< A head of VA for VMM stack
  struct VmControlStructure* vmxon_region;  ///< VA of a VMXON region
  struct VmControlStructure* vmcs_region;   ///< VA of a VMCS region
  struct EptData* ept_data;                 ///< A pointer to EPT related data
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // HYPERPLATFORM_VMM_H_
