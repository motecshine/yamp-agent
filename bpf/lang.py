from bcc import BPF, USDT, utils
from subprocess import check_output
import sched, time
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

            print(usdts)    
            bpf = {
                pid: BPF(text=program, usdt_contexts=[usdts]),
            }
            self.attached_bpf.append({
                lang: bpf
            })

    def producer(self):
        for v in self.attached_bpf:
           print(v)
                

       

    def render(self, prog, pid, read_class, read_method):
        prog = open(prog, 'r').read()
        return prog.replace("READ_CLASS", read_class) \
            .replace("READ_METHOD", read_method) \
            .replace("PID_FILTER", "if ((pid >> 32) != %d) { return 0; }" % pid) \
            .replace("DEFINE_NOLANG", '') \
            .replace("DEFINE_LATENCY", '#define LATENCY') \
            .replace("DEFINE_SYSCALLS", '#define SYSCALLS')

    def run(self):
        while True: 
            self.scheduler.enter(1, 1, self.producer)
            self.scheduler.run(blocking=True)
            time.sleep(3)
        