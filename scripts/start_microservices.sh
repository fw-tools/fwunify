#!/bin/bash

####
# This script runs microservices and python api
# 
# Author: Maurício Fiorenza
# Last modification: 04-12-2020
####

#source ../bin/activate

cd services/translators/cisco/
nameko run cisco --broker amqp://guest:guest@localhost &

cd ../iptables/
nameko run iptables --broker amqp://guest:guest@localhost &

cd ../openflow/
nameko run openflow --broker amqp://guest:guest@localhost &

cd ../../connectors/cisco_connector/
nameko run cisco_connector --broker amqp://guest:guest@localhost &

cd ../linux_connector/
nameko run linux_connector --broker amqp://guest:guest@localhost &

#python api.py

echo "To send intents see README.MD"
