#!/bin/bash

FILE_PATH=./Config/config.json
JQ_EXEC='which jq'

while getopts m:b:s:t: option
do 
    case $option in
        m)
            mode=$OPTARG;;
        s)
            node=$OPTARG
            if [[ "dc" =~ ${node} ]];
            then
                server_ip=$(cat $FILE_PATH | jq ".dc.${node}.host.ip_addr" | sed 's/\"//g')
            else
                server_ip=$(cat $FILE_PATH | jq ".sat.${node}.host.ip_addr" | sed 's/\"//g')
            fi;;
        b)
            bandwith=$OPTARG;;
        t)
            duration=$OPTARG;;
        \?)
            echo "Usage: args [-m] [-b] [-s] [-t]"
            echo "-m means mode (server or client)"
            echo "-b means bandwith (bits/s only used in client mode)"
            echo "-s means the server to ping (group1-3, sr1-3, dc1; only used in client mode)"
            echo "-t iperf duration (only used in client mode)"
            exit 1;;
    esac
done

if [ "${mode}" == "server" ];
then
    echo "Set server mode"
    echo ${bandwith}
    iperf -u -s -p 8899
else
    if [ ! ${bandwith} ] || [ ! ${duration} ] || [ ! ${node} ];then
        echo "Usage: args [-m] [-b] [-s] [-t]"
        echo "-m means mode (server or client)"
        echo "-b means bandwith (bits/s, only used in client mode)"
        echo "-s means the server to ping (group1-3, sr1-3, dc1; only used in client mode)"
        echo "-t iperf duration (only used in client mode)"
    else
        echo -e "Set client mode! \nServer is ${node}\nServer ip is ${server_ip}\nBandwith: ${bandwith}\nDuration: ${duration}s\n"
        iperf -u -c ${server_ip} -b ${bandwith} -t $duration -i 1 -p 8899
    fi
fi

