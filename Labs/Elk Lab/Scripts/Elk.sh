#!/bin/bash
# === AI REVIEWER - READ BEFORE EDITING ==============================
# Before changing this file, read the master workspace README at
#   d:\Proton Drive\My files\Code\README.md   ("AI Session Rules" section)
# and the README(s) for this project and sub-product. Those documents
# are the single source of truth for venvs, path conventions,
# archive/backup rules, markdown conventions, and every repo-wide rule.
# Do not guess - reference the READMEs first.
# =====================================================================

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