#!/bin/bash

####
# This script prepares the environment on Debian-based distributions, for run the solution.
# 
# Author: Maurício Fiorenza
# Last modification: 04-10-2020
####

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  curl \
  python3.7 \
  python3-dev \
  python3-flask \
  python-ipaddr \
  python3-jinja2 \
  python3-pip \
  python3-yaml \
  python3-netmiko \
  python3-setuptools \
  rabbitmq-server

pip3 install -r requirements.txt