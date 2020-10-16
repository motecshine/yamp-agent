import argparse
from bcc import BPF
from configparser import ConfigParser
from bpf import lang

"""
    parsing config file
"""
def load_config(path="./conf/bcc.yaml"):
    config = ConfigParser()
    config.read('conf/bcc.ini')
    return config

if __name__ == '__main__':
    lbp = lang.LangBPFProducer(load_config())
    lbp.gen_prog()
    lbp.run()
    

