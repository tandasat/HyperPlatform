// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements logging functions.

#include <ntifs.h>
#include "log.h"

// Tells the CRT not to use a inline version of CRT functions, which use
// internal functions that lead to linker errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-macros"
#define _NO_CRT_STDIO_INLINE
#pragma clang diagnostic pop

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

// See common.h for details
#pragma prefast(disable : 30030)

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constant and macro
//

// A size for log buffer in NonPagedPool. Two buffers are allocated with this
// size. Exceeded logs are ignored silently. Make it bigger if a buffered log
// size often reach this size.
static const auto kLogpBufferSizeInPages = 16ul;

// An actual log buffer size in bytes.
static const auto kLogpBufferSize = PAGE_SIZE * kLogpBufferSizeInPages;

// A size that is usable for logging. Minus one because the last byte is kept
// for \0.
static const auto kLogpBufferUsableSize = kLogpBufferSize - 1;

// An interval to flush buffered log entries into a log file.
static const auto kLogpLogFlushIntervalMsec = 50;

static const ULONG kLogpPoolTag = ' gol';

////////////////////////////////////////////////////////////////////////////////
//
// types
//

struct LogBufferInfo {
  // A pointer to buffer currently used. It is either log_buffer1 or
  // log_buffer2.
  volatile char *log_buffer_head;

  // A pointer to where the next log should be written.
  volatile char *log_buffer_tail;

  char *log_buffer1;
  char *log_buffer2;

  // Holds the biggest buffer usage to determine a necessary buffer size.
  SIZE_T log_max_usage;

  HANDLE log_file_handle;
  KSPIN_LOCK spin_lock;
  ERESOURCE resource;
  bool resource_initialized;
  volatile bool buffer_flush_thread_should_be_alive;
  volatile bool buffer_flush_thread_started;
  HANDLE buffer_flush_thread_handle;
  wchar_t log_file_path[200];
};

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

NTKERNELAPI UCHAR *NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    LogpInitializeBufferInfo(_In_ const wchar_t *log_file_path,
                             _Inout_ LogBufferInfo *info);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    LogpInitializeLogFile(_Inout_ LogBufferInfo *info);

static DRIVER_REINITIALIZE LogpReinitializationRoutine;

_IRQL_requires_max_(PASSIVE_LEVEL) static void LogpFinalizeBufferInfo(
    _In_ LogBufferInfo *info);

static NTSTATUS LogpMakePrefix(_In_ ULONG level,
                               _In_z_ const char *function_name,
                               _In_z_ const char *log_message,
                               _Out_ char *log_buffer,
                               _In_ SIZE_T log_buffer_length);

static const char *LogpFindBaseFunctionName(_In_z_ const char *function_name);

static NTSTATUS LogpPut(_In_z_ char *message, _In_ ULONG attribute);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    LogpFlushLogBuffer(_Inout_ LogBufferInfo *info);

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    LogpWriteMessageToFile(_In_z_ const char *message,
                           _In_ const LogBufferInfo &info);

static NTSTATUS LogpBufferMessage(_In_z_ const char *message,
                                  _Inout_ LogBufferInfo *info);

static void LogpDoDbgPrint(_In_z_ char *message);

static bool LogpIsLogFileEnabled(_In_ const LogBufferInfo &info);

static bool LogpIsLogFileActivated(_In_ const LogBufferInfo &info);

static bool LogpIsLogNeeded(_In_ ULONG level);

static bool LogpIsDbgPrintNeeded();

static KSTART_ROUTINE LogpBufferFlushThreadRoutine;

_IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS
    LogpSleep(_In_ LONG millisecond);

static void LogpSetPrintedBit(_In_z_ char *message, _In_ bool on);

static bool LogpIsPrinted(_In_z_ char *message);

static void LogpDbgBreak();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, LogInitialization)
#pragma alloc_text(INIT, LogpInitializeBufferInfo)
#pragma alloc_text(PAGE, LogpInitializeLogFile)
#pragma alloc_text(INIT, LogRegisterReinitialization)
#pragma alloc_text(PAGE, LogpReinitializationRoutine)
#pragma alloc_text(PAGE, LogIrpShutdownHandler)
#pragma alloc_text(PAGE, LogTermination)
#pragma alloc_text(PAGE, LogpFinalizeBufferInfo)
#pragma alloc_text(PAGE, LogpBufferFlushThreadRoutine)
#pragma alloc_text(PAGE, LogpSleep)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

static auto g_logp_debug_flag = kLogPutLevelDisable;
static LogBufferInfo g_logp_log_buffer_info = {};

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ NTSTATUS
LogInitialization(ULONG flag, const wchar_t *log_file_path) {
  PAGED_CODE()

  auto status = STATUS_SUCCESS;

  g_logp_debug_flag = flag;

  // Initialize a log file if a log file path is specified.
  bool need_reinitialization = false;
  if (log_file_path) {
    status = LogpInitializeBufferInfo(log_file_path, &g_logp_log_buffer_info);
    if (status == STATUS_REINITIALIZATION_NEEDED) {
      need_reinitialization = true;
    } else if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Test the log.
  status = HYPERPLATFORM_LOG_INFO("Log has been %sinitialized.",
                                  (need_reinitialization ? "partially " : ""));
  if (!NT_SUCCESS(status)) {
    goto Fail;
  }
  HYPERPLATFORM_LOG_DEBUG("Info= %p, Buffer= %p %p, File= %S",
                          &g_logp_log_buffer_info,
                          g_logp_log_buffer_info.log_buffer1,
                          g_logp_log_buffer_info.log_buffer2, log_file_path);
  return (need_reinitialization ? STATUS_REINITIALIZATION_NEEDED
                                : STATUS_SUCCESS);

Fail:;
  if (log_file_path) {
    LogpFinalizeBufferInfo(&g_logp_log_buffer_info);
  }
  return status;
}

// Initialize a log file related code such as a flushing thread.
_Use_decl_annotations_ static NTSTATUS LogpInitializeBufferInfo(
    const wchar_t *log_file_path, LogBufferInfo *info) {
  PAGED_CODE()
  NT_ASSERT(log_file_path);
  NT_ASSERT(info);

  KeInitializeSpinLock(&info->spin_lock);

  auto status = RtlStringCchCopyW(
      info->log_file_path, RTL_NUMBER_OF_FIELD(LogBufferInfo, log_file_path),
      log_file_path);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = ExInitializeResourceLite(&info->resource);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  info->resource_initialized = true;

  // Allocate two log buffers on NonPagedPool.
  info->log_buffer1 = static_cast<char *>(
      ExAllocatePoolWithTag(NonPagedPool, kLogpBufferSize, kLogpPoolTag));
  if (!info->log_buffer1) {
    LogpFinalizeBufferInfo(info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  info->log_buffer2 = static_cast<char *>(
      ExAllocatePoolWithTag(NonPagedPool, kLogpBufferSize, kLogpPoolTag));
  if (!info->log_buffer2) {
    LogpFinalizeBufferInfo(info);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  // Initialize these buffers
  RtlFillMemory(info->log_buffer1, kLogpBufferSize, 0xff);  // for diagnostic
  info->log_buffer1[0] = '\0';
  info->log_buffer1[kLogpBufferSize - 1] = '\0';  // at the end

  RtlFillMemory(info->log_buffer2, kLogpBufferSize, 0xff);  // for diagnostic
  info->log_buffer2[0] = '\0';
  info->log_buffer2[kLogpBufferSize - 1] = '\0';  // at the end

  // Buffer should be used is log_buffer1, and location should be written logs
  // is the head of the buffer.
  info->log_buffer_head = info->log_buffer1;
  info->log_buffer_tail = info->log_buffer1;

  status = LogpInitializeLogFile(info);
  if (status == STATUS_OBJECT_PATH_NOT_FOUND) {
    HYPERPLATFORM_LOG_INFO("The log file needs to be activated later.");
    status = STATUS_REINITIALIZATION_NEEDED;
  } else if (!NT_SUCCESS(status)) {
    LogpFinalizeBufferInfo(info);
  }
  return status;
}

// Initializes a log file and starts a log buffer thread.
_Use_decl_annotations_ static NTSTATUS LogpInitializeLogFile(
    LogBufferInfo *info) {
  PAGED_CODE()

  if (info->log_file_handle) {
    return STATUS_SUCCESS;
  }

  // Initialize a log file
  UNICODE_STRING log_file_path_u = {};
  RtlInitUnicodeString(&log_file_path_u, info->log_file_path);

  OBJECT_ATTRIBUTES oa = {};
  InitializeObjectAttributes(&oa, &log_file_path_u,
                             OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
                             nullptr)

  IO_STATUS_BLOCK io_status = {};
  auto status = ZwCreateFile(
      &info->log_file_handle, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &io_status,
      nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Initialize a log buffer flush thread.
  info->buffer_flush_thread_should_be_alive = true;
  status = PsCreateSystemThread(&info->buffer_flush_thread_handle, GENERIC_ALL,
                                nullptr, nullptr, nullptr,
                                LogpBufferFlushThreadRoutine, info);
  if (!NT_SUCCESS(status)) {
    ZwClose(info->log_file_handle);
    info->log_file_handle = nullptr;
    info->buffer_flush_thread_should_be_alive = false;
    return status;
  }

  // Wait until the thread has started
  while (!info->buffer_flush_thread_started) {
    LogpSleep(100);
  }
  return status;
}

// Registers LogpReinitializationRoutine() for re-initialization.
_Use_decl_annotations_ void LogRegisterReinitialization(
    PDRIVER_OBJECT driver_object) {
  PAGED_CODE()
  IoRegisterBootDriverReinitialization(
      driver_object, LogpReinitializationRoutine, &g_logp_log_buffer_info);
  HYPERPLATFORM_LOG_INFO("The log file will be activated later.");
}

// Initializes a log file at the re-initialization phase.
_Use_decl_annotations_ VOID static LogpReinitializationRoutine(
    _DRIVER_OBJECT *driver_object, PVOID context, ULONG count) {
  PAGED_CODE()
  UNREFERENCED_PARAMETER(driver_object);
  UNREFERENCED_PARAMETER(count);
  NT_ASSERT(context);
  _Analysis_assume_(context);

  auto info = static_cast<LogBufferInfo *>(context);
  auto status = LogpInitializeLogFile(info);
  NT_ASSERT(NT_SUCCESS(status));
  if (NT_SUCCESS(status)) {
    HYPERPLATFORM_LOG_INFO("The log file has been activated.");
  }
}

// Terminates the log functions without releasing resources.
_Use_decl_annotations_ void LogIrpShutdownHandler() {
  PAGED_CODE()

  HYPERPLATFORM_LOG_DEBUG("Flushing... (Max log usage = %Iu/%lu bytes)",
                          g_logp_log_buffer_info.log_max_usage,
                          kLogpBufferSize);
  HYPERPLATFORM_LOG_INFO("Bye!");
  g_logp_debug_flag = kLogPutLevelDisable;

  // Wait until the log buffer is emptied.
  auto &info = g_logp_log_buffer_info;
  while (info.log_buffer_head[0]) {
    LogpSleep(kLogpLogFlushIntervalMsec);
  }
}

// Terminates the log functions.
_Use_decl_annotations_ void LogTermination() {
  PAGED_CODE()

  HYPERPLATFORM_LOG_DEBUG("Finalizing... (Max log usage = %Iu/%lu bytes)",
                          g_logp_log_buffer_info.log_max_usage,
                          kLogpBufferSize);
  HYPERPLATFORM_LOG_INFO("Bye!");
  g_logp_debug_flag = kLogPutLevelDisable;
  LogpFinalizeBufferInfo(&g_logp_log_buffer_info);
}

// Terminates a log file related code.
_Use_decl_annotations_ static void LogpFinalizeBufferInfo(LogBufferInfo *info) {
  PAGED_CODE()
  NT_ASSERT(info);

  // Closing the log buffer flush thread.
  if (info->buffer_flush_thread_handle) {
    info->buffer_flush_thread_should_be_alive = false;
    auto status =
        ZwWaitForSingleObject(info->buffer_flush_thread_handle, FALSE, nullptr);
    if (!NT_SUCCESS(status)) {
      LogpDbgBreak();
    }
    ZwClose(info->buffer_flush_thread_handle);
    info->buffer_flush_thread_handle = nullptr;
  }

  // Cleaning up other things.
  if (info->log_file_handle) {
    ZwClose(info->log_file_handle);
    info->log_file_handle = nullptr;
  }
  if (info->log_buffer2) {
    ExFreePoolWithTag(info->log_buffer2, kLogpPoolTag);
    info->log_buffer2 = nullptr;
  }
  if (info->log_buffer1) {
    ExFreePoolWithTag(info->log_buffer1, kLogpPoolTag);
    info->log_buffer1 = nullptr;
  }

  if (info->resource_initialized) {
    ExDeleteResourceLite(&info->resource);
    info->resource_initialized = false;
  }
}

// Actual implementation of logging API.
_Use_decl_annotations_ NTSTATUS LogpPrint(ULONG level,
                                          const char *function_name,
                                          const char *format, ...) {
  auto status = STATUS_SUCCESS;

  if (!LogpIsLogNeeded(level)) {
    return status;
  }

  va_list args;
  va_start(args, format);
  char log_message[412];
  status = RtlStringCchVPrintfA(log_message, RTL_NUMBER_OF(log_message), format,
                                args);
  va_end(args);
  if (!NT_SUCCESS(status)) {
    LogpDbgBreak();
    return status;
  }
  if (log_message[0] == '\0') {
    LogpDbgBreak();
    return STATUS_INVALID_PARAMETER;
  }

  const auto pure_level = level & 0xf0;
  const auto attribute = level & 0x0f;

  // A single entry of log should not exceed 512 bytes. See
  // Reading and Filtering Debugging Messages in MSDN for details.
  char message[512];
  static_assert(RTL_NUMBER_OF(message) <= 512,
                "One log message should not exceed 512 bytes.");
  status = LogpMakePrefix(pure_level, function_name, log_message, message,
                          RTL_NUMBER_OF(message));
  if (!NT_SUCCESS(status)) {
    LogpDbgBreak();
    return status;
  }

  status = LogpPut(message, attribute);
  if (!NT_SUCCESS(status)) {
    LogpDbgBreak();
  }
  return status;
}

// Concatenates meta information such as the current time and a process ID to
// user given log message.
_Use_decl_annotations_ static NTSTATUS LogpMakePrefix(
    ULONG level, const char *function_name, const char *log_message,
    char *log_buffer, SIZE_T log_buffer_length) {
  char const *level_string = nullptr;
  switch (level) {
    case kLogpLevelDebug:
      level_string = "DBG\t";
      break;
    case kLogpLevelInfo:
      level_string = "INF\t";
      break;
    case kLogpLevelWarn:
      level_string = "WRN\t";
      break;
    case kLogpLevelError:
      level_string = "ERR\t";
      break;
    default:
      return STATUS_INVALID_PARAMETER;
  }

  auto status = STATUS_SUCCESS;

  char time_buffer[20] = {};
  if ((g_logp_debug_flag & kLogOptDisableTime) == 0) {
    // Want the current time.
    TIME_FIELDS time_fields;
    LARGE_INTEGER system_time, local_time;
    KeQuerySystemTime(&system_time);
    ExSystemTimeToLocalTime(&system_time, &local_time);
    RtlTimeToTimeFields(&local_time, &time_fields);

    status = RtlStringCchPrintfA(time_buffer, RTL_NUMBER_OF(time_buffer),
                                 "%02hd:%02hd:%02hd.%03hd\t", time_fields.Hour,
                                 time_fields.Minute, time_fields.Second,
                                 time_fields.Milliseconds);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Want the function name
  char function_name_buffer[50] = {};
  if ((g_logp_debug_flag & kLogOptDisableFunctionName) == 0) {
    const auto base_function_name = LogpFindBaseFunctionName(function_name);
    status = RtlStringCchPrintfA(function_name_buffer,
                                 RTL_NUMBER_OF(function_name_buffer), "%-40s\t",
                                 base_function_name);
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // Want the processor number
  char processro_number[10] = {};
  if ((g_logp_debug_flag & kLogOptDisableProcessorNumber) == 0) {
    status =
        RtlStringCchPrintfA(processro_number, RTL_NUMBER_OF(processro_number),
                            "#%lu\t", KeGetCurrentProcessorNumberEx(nullptr));
    if (!NT_SUCCESS(status)) {
      return status;
    }
  }

  // It uses PsGetProcessId(PsGetCurrentProcess()) instead of
  // PsGetCurrentThreadProcessId() because the later sometimes returns
  // unwanted value, for example:
  //  PID == 4 but its image name != ntoskrnl.exe
  // The author is guessing that it is related to attaching processes but
  // not quite sure. The former way works as expected.
  status = RtlStringCchPrintfA(
      log_buffer, log_buffer_length, "%s%s%s%5Iu\t%5Iu\t%-15s\t%s%s\r\n",
      time_buffer, level_string, processro_number,
      reinterpret_cast<ULONG_PTR>(PsGetProcessId(PsGetCurrentProcess())),
      reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()),
      PsGetProcessImageFileName(PsGetCurrentProcess()), function_name_buffer,
      log_message);
  return status;
}

// Returns the function's base name, for example,
// NamespaceName::ClassName::MethodName will be returned as MethodName.
_Use_decl_annotations_ static const char *LogpFindBaseFunctionName(
    const char *function_name) {
  if (!function_name) {
    return nullptr;
  }

  auto ptr = function_name;
  auto name = function_name;
  while (*(ptr++)) {
    if (*ptr == ':') {
      name = ptr + 1;
    }
  }
  return name;
}

// Logs the entry according to attribute and the thread condition.
_Use_decl_annotations_ static NTSTATUS LogpPut(char *message, ULONG attribute) {
  auto status = STATUS_SUCCESS;

  auto do_DbgPrint = ((attribute & kLogpLevelOptSafe) == 0 &&
                      KeGetCurrentIrql() < CLOCK_LEVEL);

  // Log the entry to a file or buffer.
  auto &info = g_logp_log_buffer_info;
  if (LogpIsLogFileEnabled(info)) {
    // Can it log it to a file now?
    if (((attribute & kLogpLevelOptSafe) == 0) &&
        KeGetCurrentIrql() == PASSIVE_LEVEL && LogpIsLogFileActivated(info)) {
#pragma warning(push)
#pragma warning(disable : 28123)
      if (!KeAreAllApcsDisabled()) {
        // Yes, it can. Do it.
        LogpFlushLogBuffer(&info);
        status = LogpWriteMessageToFile(message, info);
      }
#pragma warning(pop)
    } else {
      // No, it cannot. Set the printed bit if needed, and then buffer it.
      if (do_DbgPrint) {
        LogpSetPrintedBit(message, true);
      }
      status = LogpBufferMessage(message, &info);
      LogpSetPrintedBit(message, false);
    }
  }

  // Can it safely be printed?
  if (do_DbgPrint) {
    LogpDoDbgPrint(message);
  }
  return status;
}

// Switches the current log buffer, saves the contents of old buffer to the log
// file, and prints them out as necessary. This function does not flush the log
// file, so code should call LogpWriteMessageToFile() or ZwFlushBuffersFile()
// later.
_Use_decl_annotations_ static NTSTATUS LogpFlushLogBuffer(LogBufferInfo *info) {
  NT_ASSERT(info);
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  auto status = STATUS_SUCCESS;

  // Enter a critical section and acquire a reader lock for info in order to
  // write a log file safely.
  ExEnterCriticalRegionAndAcquireResourceExclusive(&info->resource);

  // Acquire a spin lock for info.log_buffer(s) in order to switch its head
  // safely.
  KLOCK_QUEUE_HANDLE lock_handle = {};
  KeAcquireInStackQueuedSpinLock(&info->spin_lock, &lock_handle);
  const auto old_log_buffer = const_cast<char *>(info->log_buffer_head);
  info->log_buffer_head = (old_log_buffer == info->log_buffer1)
                              ? info->log_buffer2
                              : info->log_buffer1;
  info->log_buffer_head[0] = '\0';
  info->log_buffer_tail = info->log_buffer_head;
  KeReleaseInStackQueuedSpinLock(&lock_handle);

  // Write all log entries in old log buffer.
  IO_STATUS_BLOCK io_status = {};
  for (auto current_log_entry = old_log_buffer; current_log_entry[0]; /**/) {
    // Check the printed bit and clear it
    const auto printed_out = LogpIsPrinted(current_log_entry);
    LogpSetPrintedBit(current_log_entry, false);

    const auto current_log_entry_length = strlen(current_log_entry);
    status = ZwWriteFile(info->log_file_handle, nullptr, nullptr, nullptr,
                         &io_status, current_log_entry,
                         static_cast<ULONG>(current_log_entry_length), nullptr,
                         nullptr);
    if (!NT_SUCCESS(status)) {
      // It could happen when you did not register IRP_SHUTDOWN and call
      // LogIrpShutdownHandler() and the system tried to log to a file after
      // a file system was unmounted.
      LogpDbgBreak();
    }

    // Print it out if requested and the message is not already printed out
    if (!printed_out) {
      LogpDoDbgPrint(current_log_entry);
    }

    current_log_entry += current_log_entry_length + 1;
  }
  old_log_buffer[0] = '\0';

  ExReleaseResourceAndLeaveCriticalRegion(&info->resource);
  return status;
}

// Logs the current log entry to and flush the log file.
_Use_decl_annotations_ static NTSTATUS LogpWriteMessageToFile(
    const char *message, const LogBufferInfo &info) {
  NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

  IO_STATUS_BLOCK io_status = {};
  auto status =
      ZwWriteFile(info.log_file_handle, nullptr, nullptr, nullptr, &io_status,
                  const_cast<char *>(message),
                  static_cast<ULONG>(strlen(message)), nullptr, nullptr);
  if (!NT_SUCCESS(status)) {
    // It could happen when you did not register IRP_SHUTDOWN and call
    // LogIrpShutdownHandler() and the system tried to log to a file after
    // a file system was unmounted.
    LogpDbgBreak();
  }
  status = ZwFlushBuffersFile(info.log_file_handle, &io_status);
  return status;
}

// Buffer the log entry to the log buffer.
_Use_decl_annotations_ static NTSTATUS LogpBufferMessage(const char *message,
                                                         LogBufferInfo *info) {
  NT_ASSERT(info);

  // Acquire a spin lock to add the log safely.
  KLOCK_QUEUE_HANDLE lock_handle = {};
  const auto old_irql = KeGetCurrentIrql();
  if (old_irql < DISPATCH_LEVEL) {
    KeAcquireInStackQueuedSpinLock(&info->spin_lock, &lock_handle);
  } else {
    KeAcquireInStackQueuedSpinLockAtDpcLevel(&info->spin_lock, &lock_handle);
  }
  NT_ASSERT(KeGetCurrentIrql() >= DISPATCH_LEVEL);

  // Copy the current log to the buffer.
  SIZE_T used_buffer_size = info->log_buffer_tail - info->log_buffer_head;
  auto status =
      RtlStringCchCopyA(const_cast<char *>(info->log_buffer_tail),
                        kLogpBufferUsableSize - used_buffer_size, message);

  // Update info.log_max_usage if necessary.
  if (NT_SUCCESS(status)) {
    const auto message_length = strlen(message) + 1;
    info->log_buffer_tail += message_length;
    used_buffer_size += message_length;
    if (used_buffer_size > info->log_max_usage) {
      info->log_max_usage = used_buffer_size;  // Update
    }
  } else {
    info->log_max_usage = kLogpBufferSize;  // Indicates overflow
  }
  *info->log_buffer_tail = '\0';

  if (old_irql < DISPATCH_LEVEL) {
    KeReleaseInStackQueuedSpinLock(&lock_handle);
  } else {
    KeReleaseInStackQueuedSpinLockFromDpcLevel(&lock_handle);
  }
  return status;
}

// Calls DbgPrintEx() while converting \r\n to \n\0
_Use_decl_annotations_ static void LogpDoDbgPrint(char *message) {
  if (!LogpIsDbgPrintNeeded()) {
    return;
  }
  const auto location_of_cr = strlen(message) - 2;
  message[location_of_cr] = '\n';
  message[location_of_cr + 1] = '\0';
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", message);
}

// Returns true when a log file is enabled.
_Use_decl_annotations_ static bool LogpIsLogFileEnabled(
    const LogBufferInfo &info) {
  if (info.log_buffer1) {
    NT_ASSERT(info.log_buffer2);
    NT_ASSERT(info.log_buffer_head);
    NT_ASSERT(info.log_buffer_tail);
    return true;
  }
  NT_ASSERT(!info.log_buffer2);
  NT_ASSERT(!info.log_buffer_head);
  NT_ASSERT(!info.log_buffer_tail);
  return false;
}

// Returns true when a log file is opened.
_Use_decl_annotations_ static bool LogpIsLogFileActivated(
    const LogBufferInfo &info) {
  if (info.buffer_flush_thread_should_be_alive) {
    NT_ASSERT(info.buffer_flush_thread_handle);
    NT_ASSERT(info.log_file_handle);
    return true;
  }
  NT_ASSERT(!info.buffer_flush_thread_handle);
  NT_ASSERT(!info.log_file_handle);
  return false;
}

// Returns true when logging is necessary according to the log's severity and
// a set log level.
_Use_decl_annotations_ static bool LogpIsLogNeeded(ULONG level) {
  return !!(g_logp_debug_flag & level);
}

// Returns true when DbgPrint is requested
/*_Use_decl_annotations_*/ static bool LogpIsDbgPrintNeeded() {
  return (g_logp_debug_flag & kLogOptDisableDbgPrint) == 0;
}

// A thread runs as long as info.buffer_flush_thread_should_be_alive is true and
// flushes a log buffer to a log file every kLogpLogFlushIntervalMsec msec.
_Use_decl_annotations_ static VOID LogpBufferFlushThreadRoutine(
    void *start_context) {
  PAGED_CODE()
  auto status = STATUS_SUCCESS;
  auto info = static_cast<LogBufferInfo *>(start_context);
  info->buffer_flush_thread_started = true;
  HYPERPLATFORM_LOG_DEBUG("Log thread started (TID= %p).",
                          PsGetCurrentThreadId());

  while (info->buffer_flush_thread_should_be_alive) {
    NT_ASSERT(LogpIsLogFileActivated(*info));
    if (info->log_buffer_head[0]) {
      NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
      NT_ASSERT(!KeAreAllApcsDisabled());
      status = LogpFlushLogBuffer(info);
      // Do not flush the file for overall performance. Even a case of
      // bug check, we should be able to recover logs by looking at both
      // log buffers.
    }
    LogpSleep(kLogpLogFlushIntervalMsec);
  }
  PsTerminateSystemThread(status);
}

// Sleep the current thread's execution for milliseconds.
_Use_decl_annotations_ static NTSTATUS LogpSleep(LONG millisecond) {
  PAGED_CODE()

  LARGE_INTEGER interval = {};
  interval.QuadPart = -(10000ll * millisecond);  // msec
  return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

// Marks the message as it is already printed out, or clears the printed bit and
// restores it to the original
_Use_decl_annotations_ static void LogpSetPrintedBit(char *message, bool on) {
  if (on) {
    message[0] |= 0x80;
  } else {
    message[0] &= 0x7f;
  }
}

// Tests if the printed bit is on
_Use_decl_annotations_ static bool LogpIsPrinted(char *message) {
  return (message[0] & 0x80) != 0;
}

// Sets a break point that works only when a debugger is present
/*_Use_decl_annotations_*/ static void LogpDbgBreak() {
  if (!KD_DEBUGGER_NOT_PRESENT) {
    __debugbreak();
  }
}

}  // extern "C"
