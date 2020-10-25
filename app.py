import argparse
from bcc import BPF
from configparser import ConfigParser
from bpf import lang
import queue
import threading
import logging
from bcc.syscall import syscall_name

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] (%(threadName)-10s) %(message)s')

def load_config(path="./conf/bcc.yaml"):
    config = ConfigParser()
    config.read('conf/bcc.ini')
    return config

def start_bpf_producer(queue: queue.Queue):
    logging.info("start producer")
    lbp = lang.LangBPFProducer(load_config(), queue)
    lbp.gen_prog()
    lbp.run()

def start_bpf_consumer(queue: queue.Queue):
    logging.info("start consumer")
    while True:
        collection = queue.get()
        for lang, bpf in collection.items():
            data = list(map(lambda kv: (kv[0].clazz.decode('utf-8', 'replace') \
                                    + "." + \
                                    kv[0].method.decode('utf-8', 'replace'),
                                   (kv[1].num_calls, kv[1].total_ns)), bpf["times"].items()))
            for k, v in data:
                term = {
                    lang: {
                        'function': k,
                        'call_count': v[0],
                        'call_time_avg': (v[1]/1000000.0)/v[0],
                        'call_time_total': (v[1]/1000000.0),
                    }
                }        
                print(term)
            bpf['systimes'].clear()
            bpf['times'].clear()
if __name__ == '__main__':
    queue = queue.Queue()
    producer = threading.Thread(name="bpf_producer_worker", target=start_bpf_producer, args=[queue,])
    consumer = threading.Thread(name="bpf_consumer_worker", target=start_bpf_consumer, args=[queue,])

    producer.start()
    consumer.start()

