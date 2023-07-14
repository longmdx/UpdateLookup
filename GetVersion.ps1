[reflection.assembly]::LoadWithPartialName("System.Version")
$osInfo = Get-WmiObject -class Win32_OperatingSystem
$osName = $osInfo.Caption

if ($osName.Contains('Windows 11') -or $osName.Contains('Windows 10') -or $osName.Contains('Windows Server 2016') -or $osName.Contains('Windows Server 2019') -or $osName.Contains('Windows Server 2022')) {
    
    $versionString = cmd.exe /c ver
    $versionString = $versionString.replace('Microsoft Windows [Version ','')
    $versionString = $versionString.replace(']','')
    
    if ($osName.Contains('Windows 11')) {
        
        $osName = "Windows 11"
    }
    elseif ($osName.Contains('Windows 10')) {
        $osName = "Windows 10"
    }
    elseif ($osName.Contains('Windows Server 2016')) {
        $osName = "Windows Server 2016"
    }
    elseif ($osName.Contains('Windows Server 2019')) {
        $osName = "Windows Server 2019"
    }
    elseif ($osName.Contains('Windows Server 2022')) {
        $osName = "Windows Server 2022"
    }

    $versionString = $versionString.split('.')
    $version = $versionString[1] + '.' + $versionString[2] + '.' + $versionString[3]
    $mirrorNumber =  $versionString[4]
}    
else {
    
    if ($osName.Contains('Windows Server 2012')) {
        
        $osName = "Windows Server 2012"
    }
    if ($osName.Contains('Windows Server 2008')) {
        
        $osName = "Windows Server 2008"
    }
    if ($osName.Contains('Windows Server 2003')) {
        
        $osName = "Windows Server 2003"
    }

    $BuildLabEx = reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | findstr BuildLabEx
    $BuildLabEx = $BuildLabEx.replace('    BuildLabEx    REG_SZ    ','')
    
    $mirrorNumber = $BuildLabEx.split('.')[1]
    $versionString = cmd.exe /c ver
    $versionString = $versionString.replace('Microsoft Windows [Version ','')
    $versionString = $versionString.replace(']','')
    $versionString = $versionString.replace(' ','')
    $versionString = $versionString.split('.')
    $version = $versionString[1] + '.' + $versionString[2] + '.' + $versionString[3]
}


$systemType = (systeminfo | findstr /B /C:"System Type:").replace('System Type:               ','')
$systemType = $systemType.Replace(' PC','')

$VersionOject = new-object -Type PSObject -Property @{
    ProductName = $osName
    Version = $version
    MirrorNumber = $mirrorNumber
    systemType = $systemType
}

$VersionOject | Export-Csv -Path "VersionCheckWindows.csv"



$productWindows = Get-CimInstance -ClassName win32_product
