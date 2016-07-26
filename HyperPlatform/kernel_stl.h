// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Provides code to use STL in a driver project

#ifndef HYPERPLATFORM_KERNEL_STL_H_
#define HYPERPLATFORM_KERNEL_STL_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// Disabling exception in headers included after this file
#ifdef _HAS_EXCEPTIONS
#undef _HAS_EXCEPTIONS
#endif
#define _HAS_EXCEPTIONS 0

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Calls all constructors and register all destructor
/// @return STATUS_SUCCESS on success
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C NTSTATUS KernelStlInitialization();

/// Calls all destructors
_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C void KerenlStlTermination();

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

#endif  // HYPERPLATFORM_KERNEL_STL_H_
