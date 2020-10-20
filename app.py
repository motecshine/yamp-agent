import argparse
from bcc import BPF
from configparser import ConfigParser
from bpf import lang
import queue
"""
    parsing config file
"""
def load_config(path="./conf/bcc.yaml"):
    config = ConfigParser()
    config.read('conf/bcc.ini')
    return config

if __name__ == '__main__':
    q = queue.Queue()
    lbp = lang.LangBPFProducer(load_config(), q)
    lbp.gen_prog()
    lbp.run()
    

