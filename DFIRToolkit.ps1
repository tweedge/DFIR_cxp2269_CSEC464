# Title: Windows DFIR Toolkit in PowerShell
# Author: Chris Partridge
# Function: Collect data about a Windows system for forensic use
# Notes: This is clearly a vulnerable script, written late at night, while hyped out on caffeine.
#        You're better off not running this at home. Or at work. Or really anywhere, ever.


# ------ Preflight Checks ------
#Requires -RunAsAdministrator


# ------ Acquire Input ------
$win32OS = Get-WmiObject Win32_OperatingSystem
$win32Proc = Get-WmiObject Win32_Processor
$win32Disk = Get-WmiObject Win32_DiskDrive
$win32Vol = Get-WmiObject Win32_Volume
$win32Self = Get-WmiObject Win32_ComputerSystem
$win32LUsers = Get-WmiObject Win32_UserAccount
$win32Serv = Get-WmiObject Win32_Service
$win32Start = Get-WmiObject Win32_StartupCommand
$win32Net = Get-WmiObject Win32_NetworkAdapterConfiguration
$win32SW = Get-WmiObject Win32_Product
$win32BIOS = Get-WmiObject Win32_BIOS

# -- Time
# reqs: current time, timezone, uptime
$timeCurrent = Get-Date
$timeZone = Get-Timezone
$timeLastBoot = $win32OS.ConvertToDateTime($win32OS.LastBootUpTime)

# -- OS Version
# reqs: maj/min/build, typical name, kernel
$osSpec = $win32OS.Version
$osName = $win32OS.Name

# -- System Hardware
# reqs: CPU type, RAM amt, HDD amt, list HDDs, list FS
$hwCPU = $win32Proc.Caption
$hwRAM = $win32Self.TotalPhysicalMemory
$hwDiskArray = $win32Disk | Select-Object Name, Size # is array
$hwVolArray = $win32Vol | Select-Object Label, Caption, Capacity # is array

# -- Domain Controller
# reqs: DC IP, DC hostname, DNS servers for domain
#! needs AD module, will try later

# -- Hostname
# reqs: hostname, domain
$hostName = $win32Self.Name
$hostDomain = $win32Self.Domain

# -- Users
# reqs: local, domain, system, service, login history
# note: include SID, account creation date, and last login
$userLocalArray = $win32LUsers | Select-Object SID, Name
#! needs AD module, will try later

# -- Boot
# reqs: services, programs, registry location, command, user run as
$bootServiceArray = $win32Serv | Where-Object { $_.StartMode -eq "Auto"} | Select-Object Name, ProcessID
$bootProgramArray = $win32Start # needs improvement

# -- Tasks
# reqs: scheduled tasks
$taskArray = Get-ScheduledTask

# -- Network
# reqs: ARP table, MACs, routing table, IP addrs, DHCP, DNS, gateways, listening, connections, DNS cache
# note: all listening services should include addr bound, port, protocol, and process/service name
#       all connections should include remote IP, local & remote ports, protocol, timestamp, and process/service name
$netARPArray = Get-NetNeighbor
$netMACArray = Get-NetAdapter | Select-Object MacAddress
$netRouteArray = Get-NetRoute
$netIPArray = Get-NetIPAddress | Select-Object IPAddress
$netDHCPArray = $win32Net | Select-Object DHCPServer
$netDNSArray = Get-DNSClientServerAddress | Select-Object ServerAddresses
$netGateArray = $win32Net | Select-Object DefaultIPGateway
$netListenTCPArray = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalAddress, LocalPort, OwningProcess
$netListenUDPArray = Get-NetUDPEndpoint
$netConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# -- Network Objects
# reqs: shares, printers, WiFi profiles
$objShareArray = Get-SMBShare
$objPrinterArray = Get-Printer
#$objWifiArray = # will try later

# -- Software
# reqs: list of all installed software
$swArray = $win32SW | Select-Object Name, Vendor, Version, Caption

# -- Processes
# reqs: name, ID, parent ID, location on FS, owner's username
$procArray = Get-Process | Select-Object ID, SI, ProcessName # incomplete

# -- Drivers
# reqs: name, boot criticality, location on FS, version, date created, provider name
$driverArray = Get-WindowsDriver -Online | Select-Object Driver, OriginalFileName, BootCritical, ProviderName, Date, Version

# -- Filesystem
# reqs: list of files in Downloads & Documents for each user
#! need sleep, will try in AM

# -- Custom
# Item 1 - OS extra details - architecture, serial number, included in OS output for filing purposes
$osArch = $win32OS.OSArchitecture
$osSerial = $win32BIOS.SerialNumber
# Item 2 - Dump security log because... why aren't we already
$secArray = Get-EventLog -LogName Security
# Item 3 - TBA

# ------ Render Output ------
Write-Output ""
# -- Time
Write-Output " -- Time Data"
Write-Output "Current time: $timeCurrent"
Write-Output "Timezone: $timeZone"
Write-Output "System last booted: $timeLastBoot"
Write-Output ""

# -- OS Version
Write-Output " -- OS Version"
Write-Output "Build information: $osSpec"
Write-Output "Common name: $osName"
Write-Output "Architecture: $osArch"
Write-Output "Serial: $osSerial"
Write-Output ""

# -- System Hardware
Write-Output " -- System Hardware"
Write-Output "CPU model: $hwCPU"
Write-Output "RAM capacity: $hwRAM bytes"
Write-Output " Disks table:"
$hwDiskArray | Format-Table
Write-Output " Volumes table:"
$hwVolArray | Format-Table
Write-Output ""

# -- Domain Controller
Write-Output " -- Domain Controller"
#see above
Write-Output ""

# -- Hostname
Write-Output " -- Hostname"
Write-Output "Hostname: $hostName" # disturbingly redundant
Write-Output "Domain: $hostDomain"
Write-Output ""

# -- Users
Write-Output " -- Users"
Write-Output " Local users table:"
$userLocalArray | Format-Table
#see above
Write-Output ""

# -- Boot
Write-Output " -- Boot"
Write-Output " Startup services table:"
$bootServiceArray | Format-Table
Write-Output " Startup programs table:"
$bootProgramArray | Format-Table
Write-Output ""

# -- Tasks
Write-Output " -- Tasks"
Write-Output " Scheduled tasks table:"
$taskArray | Format-Table
Write-Output ""

# -- Network
Write-Output " -- Network"
Write-Output " ARP table:"
$netARPArray | Format-Table
Write-Output " MAC addresses table:"
$netMACArray | Format-Table
Write-Output " Route table:"
$netRouteArray | Format-Table
Write-Output " IP addresses table:"
$netIPArray | Format-Table
Write-Output " DHCP servers table:"
$netDHCPArray | Format-Table
Write-Output " DNS servers table:"
$netDNSArray | Format-Table
Write-Output " Gateways table:"
$netGateArray | Format-Table
Write-Output " Listening TCP services:"
$netListenTCPArray | Format-Table
Write-Output " Listening UDP services:"
$netListenUDPArray | Format-Table
Write-Output " Established connections:"
$netConnections | Format-Table
Write-Output ""

# -- Network Objects
Write-Output " -- Network Objects"
Write-Output " Network shares table:"
$objShareArray | Format-Table
Write-Output " Printers table:"
$objPrinterArray | Format-Table
#see above
Write-Output ""

# -- Software
Write-Output " -- Software"
Write-Output " Installed software table:"
$swArray | Format-Table
Write-Output ""

# -- Processes
Write-Output " -- Processes"
Write-Output " Running processes table:"
$procArray | Format-Table
Write-Output ""

# -- Drivers
Write-Output " -- Drivers"
Write-Output " Drivers table:"
$driverArray | Format-Table
Write-Output ""

# -- Security Log
Write-Output " -- Security Log"
Write-Output " Full security log:"
$secArray | Format-Table
Write-Output ""