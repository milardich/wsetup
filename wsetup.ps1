# !!!! update windows !!!!! - user has to do that
# or https://pureinfotech.com/install-windows-10-update-powershell/

############# after windows is fully up to date, execute commands below #########


function Disable-MouseAcceleration {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if ($isAdmin) {
        # Disable mouse acceleration
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value 1
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value 0
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value 0
        Write-Host "Mouse acceleration has been disabled."
    }
    else {
        Write-Host "This function requires administrative privileges. Please run it as an administrator."
    }
}

function Disable-FastStartup {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    # Check if Fast Startup is enabled
    $fastStartupEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled").HiberbootEnabled

    if ($isAdmin) {
        if ($fastStartupEnabled) {
            # Disable Fast Startup
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0
            Write-Host "Fast Startup has been disabled."
        }
        else {
            Write-Host "Fast Startup is already disabled."
        }
    }
    else {
        Write-Host "This script requires administrative privileges. Please run it as an administrator."
    }
}

function Set-UserShellFoldersLocation {
    # Set the new folder path on the D disk
    $downloadsPath = "D:\Downloads"
    $documentsPath = "D:\Documents"
    $musicPath = "D:\Music"
    $picturesPath = "D:\Pictures"
    $videosPath = "D:\Videos"

    # Set the new folder paths for the Downloads, Documents, Music, Pictures, and Videos folders
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Value $downloadsPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Personal" -Value $documentsPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music" -Value $musicPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures" -Value $picturesPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video" -Value $videosPath

    # Set the new folder paths for the Downloads, Documents, Music, Pictures, and Videos folders in the registry
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Value $downloadsPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "Personal" -Value $documentsPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "My Music" -Value $musicPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "My Pictures" -Value $picturesPath
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -Name "My Video" -Value $videosPath

    # Refresh the shell to apply the changes immediately
    $explorerProcess = Get-Process explorer -ErrorAction SilentlyContinue
    if ($explorerProcess) {
        $explorerProcess | ForEach-Object { $_.CloseMainWindow() }
    }
}

function Disable-StickyKeys {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if ($isAdmin) {
        # Disable the Sticky Key warning
        Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 506
        Write-Host "Sticky Key warning has been disabled."

        # Turn off Sticky Keys
        Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 122
        Write-Host "Sticky Keys has been turned off."
    }
    else {
        Write-Host "This function requires administrative privileges. Please run it as an administrator."
    }
}

function Set-KeyboardLayout {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if ($isAdmin) {
        # Add the Croatian keyboard layout
        $layoutID = "0000041A"
        $layoutName = "Croatian"
        $layoutDisplayName = "Croatian"
        $layoutProfile = "00000001"

        $layoutExists = Get-WinUserLanguageList | Where-Object { $_.InputMethodTips -contains $layoutID }
        if (-not $layoutExists) {
            Add-WinUserLanguageList -LanguageTag $layoutID -Autonym $layoutName -EnglishName $layoutDisplayName -InputMethodTips $layoutID -InputMethodTips $layoutProfile
            Write-Host "Croatian keyboard layout has been added."
        }
        else {
            Write-Host "Croatian keyboard layout is already added."
        }

        # Set US English keyboard as primary/default
        $primaryLayout = Get-WinUserLanguageList | Where-Object { $_.InputMethodTips -contains "04090409" }
        if (-not $primaryLayout) {
            $currentLayouts = Get-WinUserLanguageList
            $currentLayouts[0].InputMethodTips = "04090409"
            Set-WinUserLanguageList $currentLayouts -Force
            Write-Host "US English keyboard set as primary/default."
        }
        else {
            Write-Host "US English keyboard is already set as primary/default."
        }
    }
    else {
        Write-Host "This function requires administrative privileges. Please run it as an administrator."
    }
}

function Set-CroatianDateTime {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if ($isAdmin) {
        # Set the timezone to Croatian timezone
        $timezoneId = "Central European Standard Time"
        $timezone = Get-TimeZone -Id $timezoneId -ErrorAction SilentlyContinue
        if (-not $timezone) {
            Set-TimeZone -Id $timezoneId
            Write-Host "Timezone has been set to Croatian timezone."
        }
        else {
            Write-Host "Timezone is already set to Croatian timezone."
        }

        # Set the date and time format for Croatia
        $shortDateFormat = "d.M.yyyy."
        $longDateFormat = "dddd, d. MMMM yyyy."
        $timeFormat = "H:mm:ss"

        Set-Culture -CultureInfo "hr-HR" -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Value $shortDateFormat
        Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongDate" -Value $longDateFormat
        Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sTimeFormat" -Value $timeFormat
        Write-Host "Date and time format has been set for Croatia."

        # Set the day name after the date in the taskbar
        Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "iDate" -Value 1
        Write-Host "Day name after the date has been set in the taskbar."
    }
    else {
        Write-Host "This function requires administrative privileges. Please run it as an administrator."
    }
}

function Set-TaskbarItems {
    # Check if the current user has administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if ($isAdmin) {
        # Define the target icons to keep on the taskbar
        $keepIcons = @(
            "Mozilla Firefox.lnk",
            "File Explorer.lnk"
        )

        # Get the taskbar items
        $taskbarPath = [Environment]::GetFolderPath("ApplicationData") + "\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        $taskbarItems = Get-ChildItem -Path $taskbarPath -File

        # Unpin items from the taskbar except the ones to keep
        foreach ($item in $taskbarItems) {
            if ($keepIcons -notcontains $item.Name) {
                $item.FullName | ForEach-Object {
                    $shell = New-Object -ComObject "Shell.Application"
                    $folder = $shell.NameSpace((Split-Path $_ -Parent))
                    $item = $folder.ParseName((Split-Path $_ -Leaf))
                    $verb = $item.Verbs() | Where-Object { $_.Name -eq "Unpin from Taskbar" }
                    if ($verb) {
                        $verb.DoIt()
                        Write-Host "Unpinned $($item.Name) from the taskbar."
                    }
                }
            }
        }
    }
    else {
        Write-Host "This function requires administrative privileges. Please run it as an administrator."
    }
}

function Update-windows {
    Install-Module PSWindowsUpdate
    Get-WindowsUpdate -AcceptAll -Install -AutoReboot
}


#TODO: create d partition if not already created

#TODO: pull encrypted important folders and files from remote server / hard drive (Books, Projects, Fax, etc)

#TODO: download and install programs (firefox, chrome, vscode....) (see downloads folder for program list)

#TODO: uninstall windows bloatware

#TODO: install office (.exe file from hard drive)

#TODO: turn off unnecessary windows settings

#TODO: activate windows (Microsoft Activation Script)
