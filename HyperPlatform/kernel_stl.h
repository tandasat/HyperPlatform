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

/// A pool tag for this module
static const ULONG kKstlPoolTag = 'LTSK';

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

/// An alternative implmentation of a C++ exception handler. Issues a bug check.
/// @param bug_check_code   A bug check code
DECLSPEC_NORETURN inline void KernelStlRaiseException(
    _In_ ULONG bug_check_code) {
  KdBreakPoint();
#pragma warning(push)
#pragma warning(disable : 28159)
  KeBugCheck(bug_check_code);
#pragma warning(pop)
}

// Followings are definitions of functions needed to link successfully.

DECLSPEC_NORETURN inline void __cdecl _invalid_parameter_noinfo_noreturn() {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

namespace std {

DECLSPEC_NORETURN inline void __cdecl _Xbad_alloc() {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN inline void __cdecl _Xinvalid_argument(_In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN inline void __cdecl _Xlength_error(_In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN inline void __cdecl _Xout_of_range(_In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN inline void __cdecl _Xoverflow_error(_In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
DECLSPEC_NORETURN inline void __cdecl _Xruntime_error(_In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

}  // namespace std

/// An alternative implmentation of the new operator
/// @param size   A size to allocate in bytes
/// @return An allocated pointer. The operator delete should be used to free it
inline void *__cdecl operator new(_In_ size_t size) {
  if (size == 0) {
    size = 1;
  }

  void *p = ExAllocatePoolWithTag(NonPagedPool, size, kKstlPoolTag);
  if (!p) {
    KernelStlRaiseException(MUST_SUCCEED_POOL_EMPTY);
  }
  return p;
}

/// An alternative implmentation of the new operator
/// @param p   A pointer to delete
inline void __cdecl operator delete(_In_ void *p) {
  if (p) {
    ExFreePoolWithTag(p, kKstlPoolTag);
  }
}

/// An alternative implmentation of the new operator
/// @param p   A pointer to delete
/// @param size   Ignored
inline void __cdecl operator delete(_In_ void *p, _In_ size_t size) {
  UNREFERENCED_PARAMETER(size);
  if (p) {
    ExFreePoolWithTag(p, kKstlPoolTag);
  }
}

/// An alternative implmentation of __stdio_common_vsprintf_s
/// @param _Options   Ignored
/// @param _Buffer  Storage location for output
/// @param _BufferCount   Maximum number of characters to write
/// @param _Format  Format specification
/// @param _Locale  Ignored
/// @param _ArgList   Pointer to list of arguments
/// @return The number of characters written, not including the terminating null
///         character, or a negative value if an output error occurs
_Success_(return >= 0) EXTERN_C inline int __cdecl __stdio_common_vsprintf_s(
    _In_ unsigned __int64 _Options, _Out_writes_z_(_BufferCount) char *_Buffer,
    _In_ size_t _BufferCount,
    _In_z_ _Printf_format_string_params_(2) char const *_Format,
    _In_opt_ _locale_t _Locale, va_list _ArgList) {
  UNREFERENCED_PARAMETER(_Options);
  UNREFERENCED_PARAMETER(_Locale);

  // Calls _vsnprintf exported by ntoskrnl
  using _vsnprintf_type = int __cdecl(char *, size_t, const char *, va_list);
  static _vsnprintf_type *local__vsnprintf = nullptr;
  if (!local__vsnprintf) {
    UNICODE_STRING proc_name_U = {};
    RtlInitUnicodeString(&proc_name_U, L"_vsnprintf");
    local__vsnprintf = reinterpret_cast<_vsnprintf_type *>(
        MmGetSystemRoutineAddress(&proc_name_U));
  }

  return local__vsnprintf(_Buffer, _BufferCount, _Format, _ArgList);
}

/// An alternative implmentation of __stdio_common_vswprintf_s
/// @param _Options   Ignored
/// @param _Buffer  Storage location for output
/// @param _BufferCount   Maximum number of characters to write
/// @param _Format  Format specification
/// @param _Locale  Ignored
/// @param _ArgList   Pointer to list of arguments
/// @return The number of characters written, not including the terminating null
///         character, or a negative value if an output error occurs
_Success_(return >= 0) _Check_return_opt_ EXTERN_C
    inline int __cdecl __stdio_common_vswprintf_s(
        _In_ unsigned __int64 _Options,
        _Out_writes_z_(_BufferCount) wchar_t *_Buffer, _In_ size_t _BufferCount,
        _In_z_ _Printf_format_string_params_(2) wchar_t const *_Format,
        _In_opt_ _locale_t _Locale, va_list _ArgList) {
  UNREFERENCED_PARAMETER(_Options);
  UNREFERENCED_PARAMETER(_Locale);

  // Calls _vsnwprintf exported by ntoskrnl
  using _vsnwprintf_type =
      int __cdecl(wchar_t *, size_t, const wchar_t *, va_list);
  static _vsnwprintf_type *local__vsnwprintf = nullptr;
  if (!local__vsnwprintf) {
    UNICODE_STRING proc_name_U = {};
    RtlInitUnicodeString(&proc_name_U, L"_vsnwprintf");
    local__vsnwprintf = reinterpret_cast<_vsnwprintf_type *>(
        MmGetSystemRoutineAddress(&proc_name_U));
  }

  return local__vsnwprintf(_Buffer, _BufferCount, _Format, _ArgList);
}

#endif  // HYPERPLATFORM_KERNEL_STL_H_
