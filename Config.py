# -*- coding:UTF-8 -*-

import json
import io

class Config:
    def __init__(self,):
        self.stk_path = ""

def loadjson(config, json_path_):
    f = open(json_path_)
    setting = json.load(f)
    config.stk_path = setting['stk_path']
    print(config.stk_path)
    f.close()
    return config
    
def main():
    config  = Config()
    loadjson(config,'/home/ubuntu/ryu/ryu/app/dsSatellite/Config/config.json')
    print(config.stk_path)

