#!/usr/bin/env bash

echo -e "[*] Installing Impacket library"
git clone https://github.com/SecureAuthCorp/impacket impacket
cd impacket
python3 setup.py install
mv impacket ../impacket36
mv impacket.egg-info ../
cd ../
rm -rf impacket
mv impacket36 impacket

echo -e "\n[*] ldap_search setup complete\n\n"
