// Copyright (c) 2015-2019, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Declares interfaces to performance measurement primitives.
///
/// @warning
/// All exposed interfaces but #HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME are meant
/// to be for internal use only. Also, the macro is only used by a wrapper code.
///
/// @see performance.h

#ifndef HYPERPLATFORM_PERF_COUNTER_H_
#define HYPERPLATFORM_PERF_COUNTER_H_

#include <ntddk.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

#define HYPERPLATFORM_PERFCOUNTER_P_JOIN2(x, y) x##y
#define HYPERPLATFORM_PERFCOUNTER_P_JOIN1(x, y) \
  HYPERPLATFORM_PERFCOUNTER_P_JOIN2(x, y)

/// Concatenates two tokens
/// @param x  1st token
/// @param y  2nd token
#define HYPERPLATFORM_PERFCOUNTER_P_JOIN(x, y) \
  HYPERPLATFORM_PERFCOUNTER_P_JOIN1(x, y)

#define HYPERPLATFORM_PERFCOUNTER_P_TO_STRING1(n) #n

/// Converts a token to a string literal
/// @param n  A token to convert to a string literal
#define HYPERPLATFORM_PERFCOUNTER_P_TO_STRING(n) \
  HYPERPLATFORM_PERFCOUNTER_P_TO_STRING1(n)

/// Creates an instance of PerfCounter to measure an elapsed time of this scope
/// @param collector  A pointer to a PerfCollector instance
/// @param query_time_routine   A function pointer to get an elapsed time
/// @see HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME
///
/// This macro should not be used directly. Instead use
/// #HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME.
///
/// This macro creates an instance of PerfCounter named perf_obj_N where N is
/// a sequential number starting at 0. A current function name and a source line
/// number are converted into a string literal and passed to the instance to
/// uniquely identify a location of measurement. The instance gets "counters" in
//  its constructor and destructor with \a query_time_routine, calculates an
/// elapsed time and passes it to \a collector as well as the created string
/// literal. In pseudo code, for example:
///
/// @code{.cpp}
/// Hello.cpp:233 | {
/// Hello.cpp:234 |   HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME(collector, fn);
/// Hello.cpp:235 |   // do stuff
/// Hello.cpp:236 | }
/// @endcode
///
/// This works as if below:
///
/// @code{.cpp}
/// {
///   begin_time = fn();    //perf_obj_0.ctor();
///   // do stuff
///   elapsed_time = fn();  //perf_obj_0.dtor();
///   collector->AddTime(elapsed_time, "Hello.cpp(234)");
/// }
/// @endcode
///
/// @warning
/// Do not use this macro in where going to be unavailable at the time of a
/// call of PerfCollector::Terminate(). This causes access violation because
/// this macro builds a string literal in a used section, and the string is
/// referenced in the PerfCollector::Terminate(), while it is no longer
/// accessible if the section is already destroyed. In other words, do not use
/// it in any functions in the INIT section.
#define HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME(collector, query_time_routine) \
  const PerfCounter HYPERPLATFORM_PERFCOUNTER_P_JOIN(perf_obj_, __COUNTER__)( \
      (collector), (query_time_routine),                                      \
      __FUNCTION__ "(" HYPERPLATFORM_PERFCOUNTER_P_TO_STRING(__LINE__) ")")

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

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

/// Responsible for collecting and saving data supplied by PerfCounter.
class PerfCollector {
 public:
  /// A function type for printing out a header line of results
  using InitialOutputRoutine = void(_In_opt_ void* output_context);

  /// A function type for printing out a footer line of results
  using FinalOutputRoutine = void(_In_opt_ void* output_context);

  /// A function type for printing out results
  using OutputRoutine = void(_In_ const char* location_name,
                             _In_ ULONG64 total_execution_count,
                             _In_ ULONG64 total_elapsed_time,
                             _In_opt_ void* output_context);

  /// A function type for acquiring and releasing a lock
  using LockRoutine = void(_In_opt_ void* lock_context);

  /// Constructor; call this only once before any other code in this module runs
  /// @param output_routine   A function pointer for printing out results
  /// @param initial_output_routine A function pointer for printing a header
  ///        line of results
  /// @param final_output_routine   A function pointer for printing a footer
  ///        line of results
  /// @param lock_enter_routine   A function pointer for acquiring a lock
  /// @param lock_leave_routine   A function pointer for releasing a lock
  /// @param lock_context   An arbitrary parameter for \a lock_enter_routine and
  ///        \a lock_leave_routine
  /// @param output_context   An arbitrary parameter for \a output_routine,
  ///        \a initial_output_routine and \a final_output_routine.
  void Initialize(
      _In_ OutputRoutine* output_routine,
      _In_opt_ InitialOutputRoutine* initial_output_routine = NoOutputRoutine,
      _In_opt_ FinalOutputRoutine* final_output_routine = NoOutputRoutine,
      _In_opt_ LockRoutine* lock_enter_routine = NoLockRoutine,
      _In_opt_ LockRoutine* lock_leave_routine = NoLockRoutine,
      _In_opt_ void* lock_context = nullptr,
      _In_opt_ void* output_context = nullptr) {
    initial_output_routine_ = initial_output_routine;
    final_output_routine_ = final_output_routine;
    output_routine_ = output_routine;
    lock_enter_routine_ = lock_enter_routine;
    lock_leave_routine_ = lock_leave_routine;
    lock_context_ = lock_context;
    output_context_ = output_context;
    memset(data_, 0, sizeof(data_));
  }

  /// Destructor; prints out accumulated performance results.
  void Terminate() {
    if (data_[0].key) {
      initial_output_routine_(output_context_);
    }

    for (auto i = 0ul; i < kMaxNumberOfDataEntries; i++) {
      if (data_[i].key == nullptr) {
        break;
      }

      output_routine_(data_[i].key, data_[i].total_execution_count,
                      data_[i].total_elapsed_time, output_context_);
    }
    if (data_[0].key) {
      final_output_routine_(output_context_);
    }
  }

  /// Saves performance data taken by PerfCounter.
  bool AddData(_In_ const char* location_name, _In_ ULONG64 elapsed_time) {
    ScopedLock lock(lock_enter_routine_, lock_leave_routine_, lock_context_);

    const auto data_index = GetPerfDataIndex(location_name);
    if (data_index == kInvalidDataIndex) {
      return false;
    }

    data_[data_index].total_execution_count++;
    data_[data_index].total_elapsed_time += elapsed_time;
    return true;
  }

 private:
  static const ULONG kInvalidDataIndex = MAXULONG;
  static const ULONG kMaxNumberOfDataEntries = 200;

  /// Represents performance data for each location
  struct PerfDataEntry {
    const char* key;                //!< Identifies a subject matter location
    ULONG64 total_execution_count;  //!< How many times executed
    ULONG64 total_elapsed_time;     //!< An accumulated elapsed time
  };

  /// Scoped lock
  class ScopedLock {
   public:
    /// Acquires a lock using \a lock_routine.
    /// @param lock_routine  A function pointer for acquiring a lock
    /// @param leave_routine A function pointer for releasing a lock
    /// @param lock_context  An arbitrary parameter for \a lock_enter_routine
    ///        and \a lock_leave_routine
    ScopedLock(_In_ LockRoutine* lock_routine, _In_ LockRoutine* leave_routine,
               _In_opt_ void* lock_context)
        : lock_routine_(lock_routine),
          leave_routine_(leave_routine),
          lock_context_(lock_context) {
      lock_routine_(lock_context_);
    }

    /// Releases a lock using ScopedLock::leave_routine_.
    ~ScopedLock() { leave_routine_(lock_context_); }

   private:
    LockRoutine* lock_routine_;
    LockRoutine* leave_routine_;
    void* lock_context_;
  };

  /// Default empty output routine
  /// @param output_context   Ignored
  static void NoOutputRoutine(_In_opt_ void* output_context) {
    UNREFERENCED_PARAMETER(output_context);
  }

  /// Default empty lock and release routine
  /// @param lock_context   Ignored
  static void NoLockRoutine(_In_opt_ void* lock_context) {
    UNREFERENCED_PARAMETER(lock_context);
  }

  /// Returns an index of data corresponds to the location_name.
  /// @param key   A location to get an index of corresponding data entry
  /// @return   An index of data or kInvalidDataIndex
  ///
  /// It adds a new entry when the key is not found in existing entries. Returns
  /// kInvalidDataIndex if a corresponding entry is not found and there is no
  /// room to add a new entry.
  ULONG GetPerfDataIndex(_In_ const char* key) {
    if (!key) {
      return kInvalidDataIndex;
    }

    for (auto i = 0ul; i < kMaxNumberOfDataEntries; i++) {
      if (data_[i].key == key) {
        return i;
      }

      if (data_[i].key == nullptr) {
        data_[i].key = key;
        return i;
      }
    }
    return kInvalidDataIndex;
  }

  InitialOutputRoutine* initial_output_routine_;
  FinalOutputRoutine* final_output_routine_;
  OutputRoutine* output_routine_;
  LockRoutine* lock_enter_routine_;
  LockRoutine* lock_leave_routine_;
  void* lock_context_;
  void* output_context_;
  PerfDataEntry data_[kMaxNumberOfDataEntries];
};

/// Measure elapsed time of the scope
class PerfCounter {
 public:
  using QueryTimeRoutine = ULONG64();

  /// Gets the current time using \a query_time_routine.
  /// @param collector  PerfCollector instance to store performance data
  /// @param query_time_routine  A function pointer for getting times
  /// @param location_name  A function name where being measured
  ///
  /// #HYPERPLATFORM_PERFCOUNTER_MEASURE_TIME() should be used to create an
  /// instance of this class.
  PerfCounter(_In_ PerfCollector* collector,
              _In_opt_ QueryTimeRoutine* query_time_routine,
              _In_ const char* location_name)
      : collector_(collector),
        query_time_routine_((query_time_routine) ? query_time_routine : RdTsc),
        location_name_(location_name),
        before_time_(query_time_routine_()) {}

  /// Measures an elapsed time and stores it to PerfCounter::collector_.
  ~PerfCounter() {
    if (collector_) {
      const auto elapsed_time = query_time_routine_() - before_time_;
      collector_->AddData(location_name_, elapsed_time);
    }
  }

 private:
  /// Gets the current time using the RDTSC instruction
  /// @return the current time
  static ULONG64 RdTsc() { return __rdtsc(); }

  PerfCollector* collector_;
  QueryTimeRoutine* query_time_routine_;
  const char* location_name_;
  const ULONG64 before_time_;
};

#endif  // HYPERPLATFORM_PERF_COUNTER_H_
