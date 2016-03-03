// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to EPT functions.

#ifndef HYPERPLATFORM_EPT_H_
#define HYPERPLATFORM_EPT_H_

#include <fltKernel.h>

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

struct EptData;

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// Checks if the system supports EPT technology sufficient enough
/// @return true if the system supports EPT
_IRQL_requires_max_(PASSIVE_LEVEL) bool EptIsEptAvailable();

/// Returns an EPT pointer from \a ept_data
/// @param ept_data   EptData to get an EPT pointer
/// @return An EPT pointer
ULONG64 EptGetEptPointer(_In_ EptData* ept_data);

/// Builds EPT, allocates pre-allocated enties, initializes and returns EptData
/// @return An allocated EptData on success, or nullptr
///
/// A driver must call EptTermination() with a returned value when this function
/// succeeded.
_IRQL_requires_max_(PASSIVE_LEVEL) EptData* EptInitialization();

/// De-allocates \a ept_data and all resources referenced in it
/// @param ept_data   A returned value of EptInitialization()
void EptTermination(_In_ EptData* ept_data);

/// Handles VM-exit triggered by EPT violation
/// @param ept_data   EptData to get an EPT pointer
_IRQL_requires_min_(DISPATCH_LEVEL) void EptHandleEptViolation(
    _In_ EptData* ept_data);

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

}  // extern "C"

#endif  // HYPERPLATFORM_EPT_H_
