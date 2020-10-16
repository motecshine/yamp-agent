#include <linux/ptrace.h>

#define MAX_STRING_LENGTH 80
DEFINE_NOLANG
DEFINE_LATENCY
DEFINE_SYSCALLS

struct method_t {
    char clazz[MAX_STRING_LENGTH];
    char method[MAX_STRING_LENGTH];
};
struct entry_t {
    u64 pid;
    struct method_t method;
};
struct info_t {
    u64 num_calls;
    u64 total_ns;
};
struct syscall_entry_t {
    u64 timestamp;
    u64 id;
};

#ifndef LATENCY
  BPF_HASH(counts, struct method_t, u64);            // number of calls
  #ifdef SYSCALLS
    BPF_HASH(syscounts, u64, u64);                   // number of calls per IP
  #endif  // SYSCALLS
#else
  BPF_HASH(times, struct method_t, struct info_t);
  BPF_HASH(entry, struct entry_t, u64);              // timestamp at entry
  #ifdef SYSCALLS
    BPF_HASH(systimes, u64, struct info_t);          // latency per IP
    BPF_HASH(sysentry, u64, struct syscall_entry_t); // ts + IP at entry
  #endif  // SYSCALLS
#endif

#ifndef NOLANG
int trace_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0, val = 0;
    u64 *valp;
    struct entry_t data = {0};
#ifdef LATENCY
    u64 timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
#endif
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
#ifndef LATENCY
    valp = counts.lookup_or_init(&data.method, &val);
    if (valp) {
        ++(*valp);
    }
#endif
#ifdef LATENCY
    entry.update(&data, &timestamp);
#endif
    return 0;
}

#ifdef LATENCY
int trace_return(struct pt_regs *ctx) {
    u64 *entry_timestamp, clazz = 0, method = 0;
    struct info_t *info, zero = {};
    struct entry_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    READ_CLASS
    READ_METHOD
    bpf_probe_read(&data.method.clazz, sizeof(data.method.clazz),
                   (void *)clazz);
    bpf_probe_read(&data.method.method, sizeof(data.method.method),
                   (void *)method);
    entry_timestamp = entry.lookup(&data);
    if (!entry_timestamp) {
        return 0;   // missed the entry event
    }
    info = times.lookup_or_init(&data.method, &zero);
    if (info) {
        info->num_calls += 1;
        info->total_ns += bpf_ktime_get_ns() - *entry_timestamp;
    }
    entry.delete(&data);
    return 0;
}
#endif  // LATENCY
#endif  // NOLANG

#ifdef SYSCALLS
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *valp, id = args->id, val = 0;
    PID_FILTER
#ifdef LATENCY
    struct syscall_entry_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    data.id = id;
    sysentry.update(&pid, &data);
#endif
#ifndef LATENCY
    valp = syscounts.lookup_or_init(&id, &val);
    if (valp) {
        ++(*valp);
    }
#endif
    return 0;
}

#ifdef LATENCY
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    struct syscall_entry_t *e;
    struct info_t *info, zero = {};
    u64 pid = bpf_get_current_pid_tgid(), id;
    PID_FILTER
    e = sysentry.lookup(&pid);
    if (!e) {
        return 0;   // missed the entry event
    }
    id = e->id;
    info = systimes.lookup_or_init(&id, &zero);
    if (info) {
        info->num_calls += 1;
        info->total_ns += bpf_ktime_get_ns() - e->timestamp;
    }
    sysentry.delete(&pid);
    return 0;
}
#endif  // LATENCY
#endif  // SYSCALLS