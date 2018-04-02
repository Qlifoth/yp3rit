#!/bin/bash

gem install open-uri
gem install nokogiri
gem install shodan
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git
ls vulscan/*.csv
cd vulscan/utilities/updater/
chmod +x updateFiles.sh
./updateFiles.sh
