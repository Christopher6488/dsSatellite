#!/bin/bash
 
ovs-vsctl set bridge s1 datapath_type=netdev 
ovs-vsctl set bridge s2 datapath_type=netdev
ovs-vsctl set bridge s3 datapath_type=netdev 
ovs-vsctl set bridge s4 datapath_type=netdev 
ovs-vsctl set bridge s5 datapath_type=netdev 
ovs-vsctl set bridge s6 datapath_type=netdev 
ovs-vsctl set bridge s7 datapath_type=netdev 

ovs-vsctl set bridge s1 protocols=OpenFlow14
ovs-vsctl set bridge s2 protocols=OpenFlow14
ovs-vsctl set bridge s3 protocols=OpenFlow14
ovs-vsctl set bridge s4 protocols=OpenFlow14
ovs-vsctl set bridge s5 protocols=OpenFlow14
ovs-vsctl set bridge s6 protocols=OpenFlow14
ovs-vsctl set bridge s7 protocols=OpenFlow14