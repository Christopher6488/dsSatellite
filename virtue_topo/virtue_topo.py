# -*- coding:UTF-8 -*-
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) #当前程序上上一级目录，这里为mycompany
sys.path.append(BASE_DIR)

from datetime import datetime

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

from Config import Config


class virtue_topo(nx.MultiGraph):

    def __init__(self, config_):
        super(virtue_topo, self).__init__()
        self.config = config_
        self.stk_path = config_.stk_path
        self.netnode = []
    
    def create_time_expand_network(self):
        for root, dirs, files in os.walk(self.stk_path):  
            for file in files:
                node_name = file.replace(".csv", "")
                for node in node_name.split('-'):
                    if 'group' in node :
                        self.add_node(node, type='group')
                    if 'sr' in node :
                        self.add_node(node, type='sr')
                    if 'dc' in node:
                        self.add_node(node, type='dc')
                    if node not in self.netnode:
                        self.netnode.append(node)
                self.add_link(node_name.split('-')[0], node_name.split('-')[1], self.config.stk_path+'/'+file)
        #print(list(self.nodes(data=True)))

    def add_link(self, node0, node1, file_):
        f = np.loadtxt(file_, delimiter=',', skiprows=1)
        for data in f:
            time_ = datetime(year=2020,month=5,day=8,hour=int(data[0]),minute=int(data[1]))
            self.add_edge(node0, node1, time = time_, weight = data[2])
        
    def slice_topo(self, hour_, minute_):
        time = datetime(year=2020,month=5,day=8,hour=int(hour_),minute=int(minute_))
        GG = nx.Graph(time=time)
        for node in self.netnode:
            if 'group' in node:
                 GG.add_node(node, type='group')
            if 'dc' in node:
                GG.add_node(node, type='dc')
            if 'sr' in node:
                GG.add_node(node, type='sr')
        self.slice_topo_link(GG, time)

        return GG

    def slice_topo_link(self, GG_,time_):
        for n, nbrs in self.adjacency():
            for nbr, edict in nbrs.items():
                weight = [d['weight'] for d in edict.values() if d['time'] == time_]
                if weight==[]:
                    pass
                else:
                    GG_.add_edge(n, nbr, weight = weight[0])
        

def create_virtue_topo(config):
    satnet = virtue_topo(config)
    satnet.create_time_expand_network()
    return satnet

def show_topo(GG_):
    plt.cla()
    plt.subplot(111)
    pos = nx.circular_layout(GG_)
    nx.draw(GG_,pos=pos,edgelist=None,
                width=1,
                edge_color='k',
                style='solid',
                alpha=0.8,
                arrows=True,
                with_labels=True,
                node_color=['r' if d['type']=='sr' else 'b' for (u,d) in GG_.nodes(data=True)],
                )
    plt.pause(0.5)

def main():
    config_path =  '/home/ubuntu/ryu/ryu/app/dsSatellite/Config/config.json'
    config = Config.Config(config_path)
    time_expand_network = create_virtue_topo(config)
    topo = time_expand_network.slice_topo(19,8)
    all_pairs_shortest_paths = nx.shortest_path(topo,weight = 'weight')
    print(all_pairs_shortest_paths)
    for x in all_pairs_shortest_paths:
        print(x)
    #print(all_pairs_shortest_paths)
    show_topo(topo)

if __name__ == '__main__':
    main()
