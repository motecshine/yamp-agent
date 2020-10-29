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
    lang.LangBPFProducer(load_config(), queue).run()

def start_bpf_consumer(queue: queue.Queue):
    logging.info("start consumer")
    while True:
        collection = queue.get()
        print(collection)        

if __name__ == '__main__':
    queue = queue.Queue()
    producer = threading.Thread(name="bpf_producer_worker", target=start_bpf_producer, args=[queue,])
    consumer = threading.Thread(name="bpf_consumer_worker", target=start_bpf_consumer, args=[queue,])

    producer.start()
    consumer.start()
   

