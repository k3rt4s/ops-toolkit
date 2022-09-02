#!/bin/bash
​#Check to see if user is Root
#
#Updating
apt-get update
#upgrading
apt-get upgrade
#
apt install docker.io &&
#installs docker to box
#
apt install python3-pip &&
#installs python
#
apt install docker &&
#installs docker python module
#
sysctl -w vm.max_map_count=262144 &&
#increases virtual memory
#
systemctl start docker &&
systemctl enable docker.service &&
systemctl enable containerd.service &&
#starts docker
#
docker pull sebp/elk &&
#pulls docker elk
#
docker run -it -p 5601:5601 -p 9200:9200 -p 5044:5044 --restart always sebp/elk
#Create Image