// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements code to use STL in a driver project

#include <ntddk.h>
#undef _HAS_EXCEPTIONS

// This enables use of STL in kernel-mode.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-macros"
#define _HAS_EXCEPTIONS 0
#pragma clang diagnostic pop

// See common.h for details
#pragma prefast(disable : 30030)

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// A pool tag for this module
static const ULONG kKstlpPoolTag = 'LTSK';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

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

// An alternative implementation of a C++ exception handler. Issues a bug check.
DECLSPEC_NORETURN static void KernelStlpRaiseException(
    _In_ ULONG bug_check_code) {
  KdBreakPoint();
#pragma warning(push)
#pragma warning(disable : 28159)
  KeBugCheck(bug_check_code);
#pragma warning(pop)
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

DECLSPEC_NORETURN void __cdecl _invalid_parameter_noinfo_noreturn() {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

namespace std {

DECLSPEC_NORETURN void __cdecl _Xbad_alloc() {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN void __cdecl _Xinvalid_argument(_In_z_ const char *) {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN void __cdecl _Xlength_error(_In_z_ const char *) {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN void __cdecl _Xout_of_range(_In_z_ const char *) {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN void __cdecl _Xoverflow_error(_In_z_ const char *) {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN void __cdecl _Xruntime_error(_In_z_ const char *) {
  KernelStlpRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

}  // namespace std

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) void *__cdecl operator new(
    _In_ size_t size) {
  if (size == 0) {
    size = 1;
  }

  const auto p = ExAllocatePoolWithTag(NonPagedPool, size, kKstlpPoolTag);
  if (!p) {
    KernelStlpRaiseException(MUST_SUCCEED_POOL_EMPTY);
  }
  return p;
}

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) void __cdecl operator delete(_In_ void *p) {
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

// An alternative implementation of the new operator
_IRQL_requires_max_(DISPATCH_LEVEL) void __cdecl operator delete(
    _In_ void *p, _In_ size_t size) {
  UNREFERENCED_PARAMETER(size);
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

// overload new[] and delete[] operator
_IRQL_requires_max_(DISPATCH_LEVEL) void *__cdecl operator new[](
    _In_ size_t size) {
  if (size == 0) {
    size = 1;
  }

  const auto p = ExAllocatePoolWithTag(NonPagedPool, size, kKstlpPoolTag);
  if (!p) {
    KernelStlpRaiseException(MUST_SUCCEED_POOL_EMPTY);
  }
  return p;
}

_IRQL_requires_max_(DISPATCH_LEVEL) void __cdecl operator delete[](
    _In_ void *p) {
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

_IRQL_requires_max_(DISPATCH_LEVEL) void __cdecl operator delete[](
    _In_ void *p, _In_ size_t size) {
  UNREFERENCED_PARAMETER(size);
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

#pragma clang diagnostic pop
