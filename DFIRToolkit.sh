#!/bin/bash
# Title: Linux DFIR Toolkit in Bash
# Author: Chris Partridge
# Function: Collect data about a system for forensic use
# Notes: This is clearly a vulnerable script, written late at night, while hyped out on caffeine.
#        You're better off not running this at home. Or at work. Or really anywhere, ever.


# ------ Preflight Checks ------


# ------ Acquire Input ------
# -- Time
# reqs: current time, timezone, uptime

# -- OS Version
# reqs: maj/min/build, typical name, kernel

# -- System Hardware
# reqs: CPU type, RAM amt, HDD amt, list HDDs, list FS

# -- Hostname
# reqs: hostname, domain

# -- Users
# reqs: local, domain, system, service, login history
# note: include SID, account creation date, and last login

# -- Boot
# reqs: services, programs, registry location, command, user run as

# -- Tasks
# reqs: scheduled tasks

# -- Network
# reqs: ARP table, MACs, routing table, IP addrs, DHCP, DNS, gateways, listening, connections, DNS cache
# note: all listening services should include addr bound, port, protocol, and process/service name
#       all connections should include remote IP, local & remote ports, protocol, timestamp, and process/service name

# -- Network Objects
# reqs: shares, printers, WiFi profiles

# -- Software
# reqs: list of all installed software

# -- Processes
# reqs: name, ID, parent ID, location on FS, owner's username

# -- Drivers
# reqs: name, boot criticality, location on FS, version, date created, provider name

# -- Filesystem
# reqs: list of files in Downloads & Documents for each user

# -- Custom
# undecided. grab logfiles perhaps?


# ------ Render Output ------
