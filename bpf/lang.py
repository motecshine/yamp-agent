import sched
import time
from subprocess import check_output

from bcc import BPF, USDT, utils
from bcc.syscall import syscall_name


class LangBPFProducer():
    process = []
    usdt = []
    attached_bpf = []
    scheduler = {}
    bpf = []
    def __init__(self, config, queue):
        self.config = config
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.queue = queue
  
    def gen_prog(self):
        for lang, _ in self.config.items():
            c = self.config[lang]
            if lang == 'DEFAULT':
                continue

            pids = [int(n) for n in check_output(
                ["pidof", "-s", c['proccess_name_or_path']]).split()]

            self.process.append({
                lang: pids
            })
            usdts = []
            for pid in pids:
                program = self.render(
                    prog=c['prog'], 
                    pid=pid, 
                    read_class=c['read_class'], 
                    read_method=c['read_method'],
                )
                usdt = USDT(pid=pid)
                usdt.enable_probe_or_bail(c['entry_probe'], 'trace_entry')
                usdt.enable_probe_or_bail(c['return_probe'], 'trace_return')
                usdts.append(usdt)
            if len(usdts) > 0:
                self.attached_bpf.append({
                    lang:  BPF(text=program, usdt_contexts=usdts)
                })
    

    def producer(self):
        for bpf_collections in self.attached_bpf:
            for lang, bpf in bpf_collections.items():
                data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                            + "." + \
                                            kv[0].method.decode('utf-8', 'replace'),
                                           (kv[1].num_calls, kv[1].total_ns)),
                            bpf["times"].items()))    
          
                syscalls = map(lambda kv: (syscall_name(kv[0].value).decode('utf-8', 'replace'),
                                       (kv[1].num_calls, kv[1].total_ns)),
                           bpf["systimes"].items())
                data.extend(syscalls)
                result = {'lang': lang, "event": []}
                for k, v in data:
                    term = {
                        lang: {
                            'function': k,
                            'call_count': v[0],
                            'call_time_avg': (v[1]/1000000.0)/v[0],
                            'call_time_total': (v[1]/1000000.0),
                        }
                    } 
                    result["event"].append(term)
                if len(result["event"]) > 0:
                    self.queue.put(result)
                bpf['systimes'].clear()
                bpf['times'].clear()
            
                
    def render(self, prog, pid, read_class, read_method):
        prog = open(prog, 'r').read()
        return prog.replace("READ_CLASS", read_class) \
            .replace("READ_METHOD", read_method) \
            .replace("PID_FILTER", "if ((pid >> 32) != %d) { return 0; }" % pid) \
            .replace("DEFINE_NOLANG", '') \
            .replace("DEFINE_LATENCY", '#define LATENCY') \
            .replace("DEFINE_SYSCALLS", '#define SYSCALLS')

    def run(self):
        self.gen_prog()
        while True:
            self.producer()
            time.sleep(1)
        