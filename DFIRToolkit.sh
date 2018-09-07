#!/bin/bash
# Title: Linux DFIR Toolkit in Bash
# Author: Chris Partridge
# Function: Collect data about a system for forensic use
# Notes: This is clearly a vulnerable script, written late at night, while hyped out on caffeine.
#        You're better off not running this at home. Or at work. Or really anywhere, ever.


# ------ Preflight Checks ------
if [[ $EUID -ne 0 ]]; then
	echo "You are not root."
	exit 1
fi

# ------ Acquire Input ------
# -- Time
# reqs: current time, timezone, uptime
timeZone=`timedatectl`
timeUp=`uptime`

# -- OS Version
# reqs: maj/min/build, typical name, kernel
osSpec=`uname -a`

# -- System Hardware
# reqs: CPU type, RAM amt, HDD amt, list HDDs, list FS
hwCPU=`cat /proc/cpuinfo | grep "model name" | uniq`
hwRAM=`cat /proc/meminfo | grep "MemTotal"`
hwDisk=`lsblk`
hwVol=`df`

# -- Hostname
# reqs: hostname, domain
hostName=`hostname`
hostDomain=`dnsdomainname`

# -- Users
# reqs: local, domain, system, service, login history
# note: include SID, account creation date, and last login
users=`cat /etc/passwd`

# -- Boot
# reqs: services, programs, registry location, command, user run as
bootServices=`ls /etc/init.d/`

# -- Tasks
# reqs: scheduled tasks
taskCron=""
for user in $(cut -f1 -d: /etc/passwd); do taskCron+=`crontab -u $user -l 2>/dev/null`; done

# -- Network
# reqs: ARP table, MACs, routing table, IP addrs, DHCP, DNS, gateways, listening, connections, DNS cache
# note: all listening services should include addr bound, port, protocol, and process/service name
#       all connections should include remote IP, local & remote ports, protocol, timestamp, and process/service name
netMost=`ip a` # honestly this is most of it
netListen=`ss -l`
netConnections=`netstat -netu | grep -i "Established"`

# -- Network Objects
# reqs: shares, printers, WiFi profiles
#objShareArray # unsure
objPrinter=`lpstat -p -d`

# -- Software
# reqs: list of all installed software
sw=`apt list --installed`

# -- Processes
# reqs: name, ID, parent ID, location on FS, owner's username
proc=`ps ax`

# -- Drivers
# reqs: name, boot criticality, location on FS, version, date created, provider name
drivers=`cat /proc/modules`

# -- Filesystem
# reqs: list of files in Downloads & Documents for each user
# resource intensive, putting off until am

# -- Custom
# undecided. grab logfiles perhaps?
# Item 1 - dump syslog, which will have a large assortment of information - including ClamAV logs, remarkably
syslog=`cat /var/log/syslog`
# Item 2 - dump kernel log for any early-boot or near-ring-0 activity
kernlog=`cat /vat/log/kern.log`
# Item 2 - dump authentication log to check for suspicious logins
kernlog=`cat /vat/log/auth.log`

# ------ Render Output ------
# -- Time
echo  -- Time
echo Current time and timezone data:
echo $timeZone
echo Uptime: $timeUp
echo 

# -- OS Version
echo  -- OS Details
echo $osSpec
echo

# -- System Hardware
echo  -- System Hardware
echo CPU $hwCPU
echo $hwRAM
echo Disk info:
lsblk # wasn't formatting correctly
echo Volume info:
df # same as above
echo

# -- Hostname
echo  -- Hostname
echo Hostname: $hostName
echo Domain: $hostDomain
echo

# -- Users
echo  -- Users
cat /etc/passwd # format issues again
echo

# -- Boot
echo  -- Boot
ls /etc/init.d/
echo

# -- Tasks
echo  -- Tasks
echo Cron tasks:
echo $taskCron
echo 

# -- Network
echo  -- Network
echo Network info:
ip a # render issues...
echo Open ports:
ss -l
echo Established connections:
netstat -netu | grep -i "Established"
echo

# -- Network Objects
echo  -- Network Objects
echo Printers installed:
lpstat -p -d
echo 

# -- Software
echo  -- Software
apt list --installed
echo

# -- Processes
echo  -- Processes
ps ax
echo

# -- Drivers
echo  -- Drivers
cat /proc/modules
echo 

# -- Additional Logs
echo  -- Additional Logs
echo syslog:
cat /var/log/syslog
echo kernlog:
cat /var/log/kern.log
echo auth log:
cat /var/log/auth.log
