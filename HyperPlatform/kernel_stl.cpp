// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements code to use STL in a driver project

#include "kernel_stl.h"
#include <stack>

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

using Destructor = void(__cdecl *)();

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

_IRQL_requires_max_(PASSIVE_LEVEL) EXTERN_C
    int __cdecl atexit(_In_ Destructor dtor);

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, KernelStlInitialization)
#pragma alloc_text(INIT, atexit)
#pragma alloc_text(PAGE, KerenlStlTermination)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

// .CRT section is required to invoke ctors and dtors. This pragma embeds a .CRT
// section into the .rdata section. Or else, a LNK warning would be raised.
#pragma comment(linker, "/merge:.CRT=.rdata")

// Create two sections that are used by MSVC to place an array of ctors at a
// compile time. It is important to be ordered in alphabetical order.
#pragma section(".CRT$XCA", read)
#pragma section(".CRT$XCZ", read)

// Place markers pointing to the beginning and end of the ctors arrays embeded
// by MSVC.
__declspec(allocate(".CRT$XCA")) Destructor g_kstlp_ctors_begin[1] = {};
__declspec(allocate(".CRT$XCZ")) Destructor g_kstlp_ctors_end[1] = {};

// Stores pointers to dtors to be called at the exit.
static std::stack<Destructor> *g_kstlp_dtors;

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Calls all constructors and register all destructor to \a g_kstlp_dtors
_Use_decl_annotations_ EXTERN_C NTSTATUS KernelStlInitialization() {
  PAGED_CODE();

  g_kstlp_dtors = new std::stack<Destructor>();

  // Call all constructors
  for (auto ctor = g_kstlp_ctors_begin + 1; ctor < g_kstlp_ctors_end; ++ctor) {
    (*ctor)();
  }
  return STATUS_SUCCESS;
}

// Calls all destructors registered to \a g_kstlp_dtors
_Use_decl_annotations_ EXTERN_C void KerenlStlTermination() {
  PAGED_CODE();

  for (auto &dump = *g_kstlp_dtors; !dump.empty(); dump.pop()) {
    auto dtor = dump.top();
    dtor();
  }

  delete g_kstlp_dtors;
}

// Registers destructor; this is called through a call to constructor
_Use_decl_annotations_ EXTERN_C int __cdecl atexit(Destructor dtor) {
  PAGED_CODE();

  g_kstlp_dtors->push(dtor);
  return 1;
}

// Followings are definitions of functions needed to link successfully.

// An alternative implmentation of a C++ exception handler. Issues a bug check.
DECLSPEC_NORETURN static void KernelStlpRaiseException(
    _In_ ULONG bug_check_code) {
  KdBreakPoint();
#pragma warning(push)
#pragma warning(disable : 28159)
  KeBugCheck(bug_check_code);
#pragma warning(pop)
}

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

// An alternative implmentation of the new operator
_Use_decl_annotations_ void *__cdecl operator new(size_t size) {
  if (size == 0) {
    size = 1;
  }

  void *p = ExAllocatePoolWithTag(NonPagedPool, size, kKstlpPoolTag);
  if (!p) {
    KernelStlpRaiseException(MUST_SUCCEED_POOL_EMPTY);
  }
  return p;
}

// An alternative implmentation of the new operator
void __cdecl operator delete(void *p) {
  if (p) {
    ExFreePoolWithTag(p, kKstlpPoolTag);
  }
}

// An alternative implmentation of the new operator
void __cdecl operator delete(void *p, size_t size) {
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
