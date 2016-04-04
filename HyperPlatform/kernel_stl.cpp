// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements code to use STL in a driver project

#include "kernel_stl.h"

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

// An alternative implmentation of a C++ exception handler. Issues a bug check.
_Use_decl_annotations_ DECLSPEC_NORETURN void KernelStlRaiseException(
    ULONG bug_check_code) {
  KdBreakPoint();
#pragma warning(push)
#pragma warning(disable : 28159)
  KeBugCheck(bug_check_code);
#pragma warning(pop)
}

// Followings are definitions of functions needed to link successfully.

/*_Use_decl_annotations_*/ DECLSPEC_NORETURN void __cdecl _invalid_parameter_noinfo_noreturn() {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

namespace std {

/*_Use_decl_annotations_*/ DECLSPEC_NORETURN void __cdecl _Xbad_alloc() {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
_Use_decl_annotations_ DECLSPEC_NORETURN void __cdecl _Xinvalid_argument(
    _In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
_Use_decl_annotations_ DECLSPEC_NORETURN void __cdecl _Xlength_error(
    _In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
_Use_decl_annotations_ DECLSPEC_NORETURN void __cdecl _Xout_of_range(
    _In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
_Use_decl_annotations_ DECLSPEC_NORETURN void __cdecl _Xoverflow_error(
    _In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}
_Use_decl_annotations_ DECLSPEC_NORETURN void __cdecl _Xruntime_error(
    _In_z_ const char *) {
  KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
}

}  // namespace std

// An alternative implmentation of the new operator
_Use_decl_annotations_ void *__cdecl operator new(size_t size) {
  if (size == 0) {
    size = 1;
  }

  void *p = ExAllocatePoolWithTag(NonPagedPool, size, kKstlpPoolTag);
  if (!p) {
    KernelStlRaiseException(MUST_SUCCEED_POOL_EMPTY);
  }
  return p;
}

// An alternative implmentation of the new operator
_Use_decl_annotations_ void __cdecl operator delete(void *p) {
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

// An alternative implmentation of the new operator
/*_Use_decl_annotations_*/ void __cdecl operator delete(void *p, size_t size) {
  UNREFERENCED_PARAMETER(size);
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

// An alternative implmentation of __stdio_common_vsprintf_s
_Use_decl_annotations_ EXTERN_C int __cdecl __stdio_common_vsprintf_s(
    unsigned __int64 _Options, char *_Buffer, size_t _BufferCount,
    char const *_Format, _locale_t _Locale, va_list _ArgList) {
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

// An alternative implmentation of __stdio_common_vswprintf_s
_Use_decl_annotations_ EXTERN_C int __cdecl __stdio_common_vswprintf_s(
    unsigned __int64 _Options, wchar_t *_Buffer, size_t _BufferCount,
    wchar_t const *_Format, _locale_t _Locale, va_list _ArgList) {
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
