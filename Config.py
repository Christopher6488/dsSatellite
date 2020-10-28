# -*- coding:UTF-8 -*-

import json
import io

class Config:
    def __init__(self, config_path_):
        self.stk_path = ""
        self.json = self.loadjson(config_path_)

    def loadjson(self, json_path_):
        f = open(json_path_)
        setting = json.load(f)
        self.stk_path = setting['stk_path']
        return setting
        
def main():
    config_path_ = '/home/ubuntu/ryu/ryu/app/dsSatellite/config.json'
    config  = Config(config_path_)
    print(config.json['sat']['group1']['host']['ip_addr'])

# if __name__ == '__main__':
#     main()