#!/bin/bash

path=。/Config/config.json
JQ_EXEC=' which jq'

while getopts b:m:s:t: option
do 
    case "$option" in
        b)
            bandwith = $OPTARG;;
        m)
            mode=$OPTARG;;
        s)
            node= $OPTARG
            if [[ "dc" =~ "$class" ]];
            then
                server_ip = $(cat $FILE_PATH) | ${JQ_EXEC} .dc.dc1.host.ip_addr | sed 's/\"//g'
            else
                server_ip = $(cat $FILE_PATH) | ${JQ_EXEC} .sat.${node}.host.ip_addr | sed 's/\"//g'
            fi
        t)
            duration = $OPTARG;;
        \?)
            echo "Usage: args [-m] [-b] [-s] [-t]"
            echo "-m means mode (server or client)"
            echo "-b means bandwith (only used in client mode)"
            echo "-s means the server to ping (group1-3, sr1-3, dc1; only used in client mode)"
            echo "-t iperf duration (only used in client mode)"
            exit 1;;
    esac
done

if ["${mode}" -eq "server"]
then
    echo "Set server mode"
    exec iperf -u -s -p 66666
else if ["${mode}" -eq "client"]
then
    echo "Set client mode"
    exec iperf -u -c ${server_ip} -b ${bandwith } -t $duration -i 1 -p 666666
fi

