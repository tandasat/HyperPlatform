// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares and implements common things across the project

/// @mainpage
/// @section whats About
/// These pages serve as a programmer's reference manual for HyperPlatform and
/// were automatically generated from the source using Doxygen.
///
/// For compilation and installation of HyperPlatform, see the HyperPlatform
/// project page. For more general information about development using
/// HyperPlatform, see User's Documents in the project page.
/// @li https://github.com/tandasat/HyperPlatform
///
/// Some of good places to start are the files page that provides a brief
/// description of each files, the DriverEntry() function where is an entry
/// point
/// of HyperPlatform, and the VmmVmExitHandler() function, a high-level entry
/// point of VM-exit handlers.
///
/// @subsection links External Document
/// This document often refers to the Intel 64 and IA-32 Architectures Software
/// Developer Manuals (Intel SDM). Any descriptions like
/// "See: CONTROL REGISTERS" implies that details are explained in a page or a
/// table titled as "CONTROL REGISTERS" in the Intel SDM.
/// @li
/// http://www.intel.com/content/www/us/en/processors/architectures-software-developer-manuals.html
///
/// @copyright Use of this source code is governed by a MIT-style license that
///            can be found in the LICENSE file.

#ifndef HYPERPLATFORM_COMMON_H_
#define HYPERPLATFORM_COMMON_H_

#include <ntddk.h>

// C30030: Calling a memory allocating function and passing a parameter that
// indicates executable memory
//
// Disable C30030 since POOL_NX_OPTIN + ExInitializeDriverRuntime is in place.
// This warning is false positive and can be seen when Target Platform Version
// equals to 10.0.14393.0.
#pragma prefast(disable : 30030)

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

/// Sets a break point that works only when a debugger is present
#if !defined(HYPERPLATFORM_COMMON_DBG_BREAK)
#define HYPERPLATFORM_COMMON_DBG_BREAK() \
  if (KD_DEBUGGER_NOT_PRESENT) {         \
  } else {                               \
    __debugbreak();                      \
  }                                      \
  reinterpret_cast<void*>(0)
#endif

/// Issues a bug check
/// @param hp_bug_check_code  Type of a bug
/// @param param1   1st parameter for KeBugCheckEx()
/// @param param2   2nd parameter for KeBugCheckEx()
/// @param param3   3rd parameter for KeBugCheckEx()
#if !defined(HYPERPLATFORM_COMMON_BUG_CHECK)
#define HYPERPLATFORM_COMMON_BUG_CHECK(hp_bug_check_code, param1, param2,    \
                                       param3)                               \
  HYPERPLATFORM_COMMON_DBG_BREAK();                                          \
  const HyperPlatformBugCheck code = (hp_bug_check_code);                    \
  __pragma(warning(push))                                                    \
  __pragma(warning(disable: __WARNING_USE_OTHER_FUNCTION))                   \
  KeBugCheckEx(MANUALLY_INITIATED_CRASH, static_cast<ULONG>(code), (param1), \
               (param2), (param3))                                           \
  __pragma(warning(pop))
#endif

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// Enable or disable performance monitoring globally
///
/// Enables #HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE() which measures
/// an elapsed time of the scope when set to non 0. Enabling it introduces
/// negative performance impact.
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 0

/// A pool tag
static const ULONG kHyperPlatformCommonPoolTag = 'PpyH';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

/// BugCheck codes for #HYPERPLATFORM_COMMON_BUG_CHECK().
enum class HyperPlatformBugCheck : ULONG {
  kUnspecified,                    //!< An unspecified bug occurred
  kUnexpectedVmExit,               //!< An unexpected VM-exit occurred
  kTripleFaultVmExit,              //!< A triple fault VM-exit occurred
  kExhaustedPreallocatedEntries,   //!< All pre-allocated entries are used
  kCriticalVmxInstructionFailure,  //!< VMRESUME or VMXOFF has failed
  kEptMisconfigVmExit,             //!< EPT misconfiguration VM-exit occurred
  kCritialPoolAllocationFailure,   //!< Critical pool allocation failed
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

/// Checks if a system is x64
/// @return true if a system is x64
constexpr bool IsX64() {
#if defined(_AMD64_)
  return true;
#else
  return false;
#endif
}

/// Checks if the project is compiled as Release
/// @return true if the project is compiled as Release
constexpr bool IsReleaseBuild() {
#if defined(DBG)
  return false;
#else
  return true;
#endif
}

#endif  // HYPERPLATFORM_COMMON_H_
