function InstallPSWindowsUpdatePSModule () {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -Force | Out-Null
    Install-Module PSWindowsUpdate -Force | Out-Null
    Import-Module PSWindowsUpdate -Force | Out-Null
    if(!(Get-Module -Name "PSWindowsUpdate")){
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Warning" -LogMessage "The module PSWindowsUpdate failed to install..."
        EXIT
    }
}

function InstallSqlServerPSModule () {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module SqlServer -Scope CurrentUser -Force -AllowClobber | Out-Null
    Import-Module SqlServer -Force | Out-Null
    if(!(Get-Module -Name "SqlServer")){
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Warning" -LogMessage "The module SqlServer failed to install..."
        EXIT
    }
}

function WindowsUpdateSchedTaskCheck () {
    if(Get-ScheduledTask | Where-Object {$_.TaskName -Like "(MSP) Install Missing Windows Updates*"}){
        $Script:EndpointWindowsUpdateSchedTaskExists = "True"
        $Script:EndpointWindowsUpdateSchedTaskName = (Get-ScheduledTask | Where-Object {$_.TaskName -Like "(MSP) Install Missing Windows Updates*"}).TaskName
    }
    else{
        $Script:EndpointWindowsUpdateSchedTaskExists = "False"
        $Script:EndpointWindowsUpdateSchedTaskName = $Null
    }
}

function CheckUpdateStatus () {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $BlacklistedPatches = @((Invoke-WebRequest -URI "https://raw.githubusercontent.com/RonRunnerElowSum/WindowsUpdate/Prod-Branch/BlackListedPatches.cfg" -UseBasicParsing).Content)
    $MissingUpdates = (Get-WindowsUpdate -MicrosoftUpdate -NotCategory Drivers -NotTitle "Feature update to Windows 10" -NotKBArticleID $BlacklistedPatches).KB
    if(!($Null -eq $MissingUpdates)){
        $Script:NumberOfMissingPatches = $MissingUpdates.Count
        $Script:PatchStatus = "Not current"
        if($NumberOfMissingPatches -eq "1"){
            $Script:FormattedMissingUpdates = $MissingUpdates
        }
        else{
            $Script:FormattedMissingUpdates = [string]::Join("`r`n",($MissingUpdates))
        }
    }
    else{
        $Script:NumberOfMissingPatches = "0"
        $Script:PatchStatus = "Current"
        $Script:FormattedMissingUpdates = $Null
    }
}

function GetEndpointInfo {
    $Script:EndpointSerial = (Get-CimInstance win32_bios).SerialNumber
    $Script:EndpointComputerName = [System.Net.Dns]::GetHostByName($Env:ComputerName).HostName
    $Script:EndpointOS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    if($Script:EndpointOS | Select-String "Windows 10"){
        $Win10CurrentBuildNumber = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).CurrentBuildNumber
        if($Win10CurrentBuildNumber -eq "14393"){
            $Script:Win10Build = "1607"
        }
        if($Win10CurrentBuildNumber -eq "15063"){
            $Script:Win10Build = "1703"
        }
        if($Win10CurrentBuildNumber -eq "16299"){
            $Script:Win10Build = "1709"
        }
        if($Win10CurrentBuildNumber -eq "17134"){
            $Script:Win10Build = "1803"
        }
        if($Win10CurrentBuildNumber -eq "18363"){
            $Script:Win10Build = "1909"
        }
        if($Win10CurrentBuildNumber -eq "19041"){
            $Script:Win10Build = "2004"
        }
        if($Win10CurrentBuildNumber -eq "19042"){
            $Script:Win10Build = "20H2"
        }
        if($Win10CurrentBuildNumber -eq "19043"){
            $Script:Win10Build = "21H1"
        }
        if($Win10CurrentBuildNumber -eq "19044"){
            $Script:Win10Build = "21H2"
        }
    }
    else{
        $Script:Win10Build = $Null
    }
    if($EndpointOS | Select-String "Server"){
        $Script:EndpointType = "Server"
    }
    else{
        $Script:EndpointType = "Workstation"
    }
    if(($Null -eq $Script:EndpointSerial) -or ($Script:EndpointSerial -eq "To be filled by O.E.M.")){
        $Script:EndpointSerial = $Script:EndpointComputerName
    }
    if(Test-Path "C:\*\EndpointSiteName.txt" -ErrorAction SilentlyContinue){
        $Script:EndpointSiteName = Get-Content -Path "C:\*\EndpointSiteName.txt"
    }
    elseif(Test-Path "C:\Program Files\SAAZOD\ApplicationLog\zSCCLog\zDCMGetSitecode.log" -ErrorAction SilentlyContinue){
        $Script:EndpointSiteName = (Get-Content -Path "C:\Program Files\SAAZOD\ApplicationLog\zSCCLog\zDCMGetSitecode.log" | Select-String "sitename=" | Select-Object -Last 1) -Replace "^.*?="
    }
    elseif(Test-Path "C:\Program Files (x86)\SAAZOD\ApplicationLog\zSCCLog\zDCMGetSitecode.log" -ErrorAction SilentlyContinue){
        $Script:EndpointSiteName = (Get-Content -Path "C:\Program Files (x86)\SAAZOD\ApplicationLog\zSCCLog\zDCMGetSitecode.log" | Select-String "sitename=" | Select-Object -Last 1) -Replace "^.*?="
    }
}

function PostPatchHealthInfo {

    try{
        if(!(Test-Path -Path "C:\MSP\secret.txt")){
            Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "C:\MSP\secret.txt does not exist...exiting..."
            EXIT
        }
        $SensitiveString = Get-Content -Path "C:\MSP\secret.txt" | ConvertTo-SecureString
        $Marshal = [System.Runtime.InteropServices.Marshal]
        $Bstr = $Marshal::SecureStringToBSTR($SensitiveString)
        $DecryptedString = $Marshal::PtrToStringAuto($Bstr)
        $Marshal::ZeroFreeBSTR($Bstr)
        $SQLServer = $DecryptedString -split ";" | Select-Object -Index 0
        $SQLDatabase = $DecryptedString -split ";" | Select-Object -Index 1
        $SQLUsername = $DecryptedString -split ";" | Select-Object -Index 2
        $SQLPassword = $DecryptedString -split ";" | Select-Object -Index 3
    }
    catch{
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "Failed to decrypt SQL connection info..."
        EXIT
    }

    $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
    Write-MSPLog -LogSource "MSP Monitoring" -LogType "Information" -LogMessage "Posting patch health information:`r`n`r`nSerial number: $Script:EndpointSerial`r`nComputer name: $Script:EndpointComputerName`r`nOS: $Script:EndpointOS $Script:Win10Build`r`nType: $Script:EndpointType`r`nSitename: $Script:EndpointSiteName`r`nPatch status: $Script:PatchStatus`r`nTotal patches missing: $Script:NumberOfMissingPatches`r`n$Script:FormattedMissingUpdates`r`nWindows Update scheudled task exists: $Script:EndpointWindowsUpdateSchedTaskExists`r`nWindows Update Scheduled Task Name: $Script:EndpointWindowsUpdateSchedTaskName"

$SQLCommand = @"
if exists(SELECT * from Table_CustomerPatchHealthData where EndpointSerial='$Script:EndpointSerial')
BEGIN            
UPDATE Table_CustomerPatchHealthData SET EndpointComputerName='$Script:EndpointComputerName',EndpointOS='$Script:EndpointOS',EndpointType='$Script:EndpointType',EndpointSiteName='$Script:EndpointSiteName',EndpointPatchStatus='$Script:PatchStatus',EndpointNumberOfMissingKBs='$Script:NumberOfMissingPatches',EndpointMissingKBs='$Script:FormattedMissingUpdates',EndpointWindows10Build='$Script:Win10Build',EndpointWindowsUpdateSchedTaskExists='$Script:EndpointWindowsUpdateSchedTaskExists',EndpointWindowsUpdateSchedTaskName='$Script:EndpointWindowsUpdateSchedTaskName',LastPostDate='$DateTime' WHERE (EndpointSerial = '$Script:EndpointSerial')
END                  
else            
BEGIN
INSERT INTO [$SQLDatabase].[dbo].[Table_CustomerPatchHealthData](EndpointSerial,EndpointComputerName,EndpointOS,EndpointType,EndpointSiteName,EndpointPatchStatus,EndpointNumberOfMissingKBs,EndpointMissingKBs,EndpointWindows10Build,EndpointWindowsUpdateSchedTaskExists,EndpointWindowsUpdateSchedTaskName,LastPostDate)
VALUES ('$Script:EndpointSerial','$Script:EndpointComputerName','$Script:EndpointOS','$Script:EndpointType','$Script:EndpointSiteName','$Script:PatchStatus','$Script:NumberOfMissingPatches','$Script:FormattedMissingUpdates','$Script:Win10Build','$Script:EndpointWindowsUpdateSchedTaskExists','$Script:EndpointWindowsUpdateSchedTaskName','$DateTime')
END
"@      

    $Params = @{
        'ServerInstance'=$SQLServer;
        'Database'=$SQLDatabase;
        'Username'=$SQLUsername;
        'Password'=$SQLPassword
    }
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-SqlCmd @Params -Query $SQLCommand -EncryptConnection
}

function GetSystemUptimeData () {
    $WMIInfo = Get-WMIObject -Class Win32_OperatingSystem
    $LastBootTime = $WMIInfo.ConvertToDateTime($WMIInfo.LastBootUpTime)
    $SysUptime = (Get-Date) - $LastBootTime
    $Script:EndpointUptime = $SysUptime.Days
}

function ForceRebootSchedTaskCheck () {
    $EndpointOS = (Get-WmiObject -class Win32_OperatingSystem).Caption
    if((Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq "Microsoft-Hyper-V"} | Where-Object {$_.State -eq "Enabled"}) -and ($EndpointOS | Select-String "Server")){
        if(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -Like "*(HyperV) Weekly Forced Reboot*"}){
            $Script:EndpointForceRebootSchedTaskExists = "True"
            $Script:EndpointForceRebootSchedTaskName = (Get-ScheduledTask | Where-Object {$_.TaskName -Like "*(HyperV) Weekly Forced Reboot*"}).TaskName
        }
        else{
            $Script:EndpointForceRebootSchedTaskExists = "False"
            $Script:EndpointForceRebootSchedTaskName = $Null
        }
    }
    else{
        if(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.TaskName -Like "*Weekly Forced Reboot*"}){
            $Script:EndpointForceRebootSchedTaskExists = "True"
            $Script:EndpointForceRebootSchedTaskName = (Get-ScheduledTask | Where-Object {$_.TaskName -Like "*Weekly Forced Reboot*"}).TaskName
        }
        else{
            $Script:EndpointForceRebootSchedTaskExists = "False"
            $Script:EndpointForceRebootSchedTaskName = $Null
        }
    }
}

function PendingRebootCheckerSchedTaskCheck () {
    if(Get-ScheduledTask -TaskName "(MSP) Pending Reboot Checker" -ErrorAction SilentlyContinue){
        $Script:EndpointPRCSchedTaskExists = "True"
    }
    else{
        $Script:EndpointPRCSchedTaskExists = "False"
    }
}

function GetEndpointPendingRebootState () {
    $PendingRebootStatus = Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    if($PendingRebootStatus -eq "True"){
        $Script:EndpointPendingRebootState = "True"
    }
    else{
        $Script:EndpointPendingRebootState = "False"
    }
}

function PostSystemUptimeInfo {

    try{
        if(!(Test-Path -Path "C:\MSP\secret.txt")){
            Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "C:\MSP\secret.txt does not exist...exiting..."
            EXIT
        }
        $SensitiveString = Get-Content -Path "C:\MSP\secret.txt" | ConvertTo-SecureString
        $Marshal = [System.Runtime.InteropServices.Marshal]
        $Bstr = $Marshal::SecureStringToBSTR($SensitiveString)
        $DecryptedString = $Marshal::PtrToStringAuto($Bstr)
        $Marshal::ZeroFreeBSTR($Bstr)
        $SQLServer = $DecryptedString -split ";" | Select-Object -Index 0
        $SQLDatabase = $DecryptedString -split ";" | Select-Object -Index 1
        $SQLUsername = $DecryptedString -split ";" | Select-Object -Index 2
        $SQLPassword = $DecryptedString -split ";" | Select-Object -Index 3
    }
    catch{
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "Failed to decrypt SQL connection info..."
        EXIT
    }

    $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
    Write-MSPLog -LogSource "MSP Monitoring" -LogType "Information" -LogMessage "Posting system uptime information:`r`n`r`nSerial number: $Script:EndpointSerial`r`nComputer name: $Script:EndpointComputerName`r`nOS: $Script:EndpointOS $Script:Win10Build`r`nType: $Script:EndpointType`r`nSitename: $Script:EndpointSiteName`r`nEndpoint Uptime: $Script:EndpointUptime`r`nPending Reboot State: $Script:EndpointPendingRebootState`r`nForce Reboot Schedulec Task Exists: $Script:EndpointForceRebootSchedTaskExists`r`nForce Reboot Scheduled Task Name: $Script:EndpointForceRebootSchedTaskName`r`nPRC Scheduled Task Exists: $Script:EndpointPRCSchedTaskExists"

$SQLCommand = @"
if exists(SELECT * from Table_CustomerSystemUptimeData where EndpointSerial='$Script:EndpointSerial')
BEGIN            
UPDATE Table_CustomerSystemUptimeData SET EndpointComputerName='$Script:EndpointComputerName',EndpointOS='$Script:EndpointOS',EndpointType='$Script:EndpointType',EndpointSiteName='$Script:EndpointSiteName',EndpointSystemUptime='$Script:EndpointUptime',EndpointPendingRebootState='$Script:EndpointPendingRebootState',EndpointForceRebootSchedTaskExists='$Script:ndpointForceRebootSchedTaskExists',EndpointForceRebootSchedTaskName='$Script:EndpointForceRebootSchedTaskName',EndpointPRCSchedTaskExists='$Script:EndpointPRCSchedTaskExists',LastPostDate='$DateTime' WHERE (EndpointSerial = '$Script:EndpointSerial')
END                  
else            
BEGIN
INSERT INTO [$SQLDatabase].[dbo].[Table_CustomerSystemUptimeData](EndpointSerial,EndpointComputerName,EndpointOS,EndpointType,EndpointSiteName,EndpointSystemUptime,EndpointPendingRebootState,EndpointForceRebootSchedTaskExists,EndpointForceRebootSchedTaskName,EndpointPRCSchedTaskExists,LastPostDate)
VALUES ('$Script:EndpointSerial','$Script:EndpointComputerName','$Script:EndpointOS','$Script:EndpointType','$Script:EndpointSiteName','$Script:EndpointUptime','$Script:EndpointPendingRebootState','$Script:EndpointForceRebootSchedTaskExists','$Script:EndpointForceRebootSchedTaskName','$Script:EndpointPRCSchedTaskExists','$DateTime')
END
"@      

    $Params = @{
        'ServerInstance'=$SQLServer;
        'Database'=$SQLDatabase;
        'Username'=$SQLUsername;
        'Password'=$SQLPassword
    }
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-SqlCmd @Params -Query $SQLCommand -EncryptConnection
}

function GetDiskInfo () {

    $Script:EndpointVolumes = @()
    $DiskDrives = Get-WmiObject Win32_DiskDrive | Where-Object {$_.InterfaceType -eq "IDE" -or $_.InterfaceType -eq "SCSI"} | Sort Index
    ForEach($Disk in $DiskDrives){
        $Part_Query = 'ASSOCIATORS OF {Win32_DiskDrive.DeviceID="' + $Disk.DeviceID.replace('\','\\') + '"} WHERE AssocClass=Win32_DiskDriveToDiskPartition'
        $Partitions = @(Get-WmiObject -Query $Part_Query | Sort StartingOffset)
        ForEach($Partition in $Partitions){
            $Vol_Query = 'ASSOCIATORS OF {Win32_DiskPartition.DeviceID="' + $Partition.DeviceID + '"} WHERE AssocClass=Win32_LogicalDiskToPartition'
            $Volumes = @(Get-WmiObject -Query $Vol_Query)
            ForEach($Volume in $Volumes){
                $Script:EndpointVolumes += $Volume.Name
            }
        }
    }

    $Script:EndpointFreeSpace = @()
    $Script:EndpointFragmentation = @()

    $Script:EndpointVolumes | ForEach-Object {
     #   $_ = "$_" + ":"
        $FilterString = "'" + $_ + "'"
        $Disk = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = $FilterString"
        $DiskDetails = $Disk.DefragAnalysis()
        $DiskFreeSpacePercentage = $DiskDetails.DefragAnalysis.FreeSpacePercent
        $DiskFreeSpaceGB = [math]::Round($DiskDetails.DefragAnalysis.FreeSpace / 1GB)
        $Script:EndpointFreeSpace +=  "$_" + "--" + $DiskFreeSpacePercentage + "%" + " " + "($DiskFreeSpaceGB" + "GB)"
    }

    $Script:EndpointFreeSpace | ForEach-Object {
        $TrimmedValue = (($_) -Replace "%[^%]*$") -Split "--"
        if([int]$TrimmedValue[1] -lt "15"){
            $Script:EndpointSpaceStatus = "Warning: Low space"
        }
        else{
            $Script:EndpointSpaceStatus = "Healthy"
        }
    }

    $Script:EndpointVolumes | ForEach-Object {
      #  $_ = "$_" + ":"
        $FilterString = "'" + $_ + "'"
        $Disk = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter = $FilterString"
        $DiskDetails = $Disk.DefragAnalysis()
        $DiskFragPercentage = $DiskDetails.DefragAnalysis.FilePercentFragmentation
        $Script:EndpointFragmentation +=  "$_" + "--" + $DiskFragPercentage + "%"
    }

    $Script:EndpointFragmentation | ForEach-Object {
        $TrimmedValue = ($_) -Replace ("%","") -Split "--"
        if([int]$TrimmedValue[1] -gt "45"){
            $Script:EndpointFragStatus = "Warning: High Fragmentation"
        }
        else{
            $Script:EndpointFragStatus = "Healthy"
        }
    }
}

function PostDiskInfo {

    try{
        if(!(Test-Path -Path "C:\MSP\secret.txt")){
            Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "C:\MSP\secret.txt does not exist...exiting..."
            EXIT
        }
        $SensitiveString = Get-Content -Path "C:\MSP\secret.txt" | ConvertTo-SecureString
        $Marshal = [System.Runtime.InteropServices.Marshal]
        $Bstr = $Marshal::SecureStringToBSTR($SensitiveString)
        $DecryptedString = $Marshal::PtrToStringAuto($Bstr)
        $Marshal::ZeroFreeBSTR($Bstr)
        $SQLServer = $DecryptedString -split ";" | Select-Object -Index 0
        $SQLDatabase = $DecryptedString -split ";" | Select-Object -Index 1
        $SQLUsername = $DecryptedString -split ";" | Select-Object -Index 2
        $SQLPassword = $DecryptedString -split ";" | Select-Object -Index 3
    }
    catch{
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Error" -LogMessage "Failed to decrypt SQL connection info..."
        EXIT
    }
    
    $DateTime = Get-Date -Format "MM/dd/yyyy HH:mm"
    Write-MSPLog -LogSource "MSP Monitoring" -LogType "Information" -LogMessage "Posting disk information:`r`n`r`nSerial number: $Script:EndpointSerial`r`nComputer name: $Script:EndpointComputerName`r`nSite name: $Script:EndpointSiteName`r`nVolumes: $Script:EndpointVolumes`r`nDisk Space Status: $Script:EndpointSpaceStatus`r`nFragmentation status: $Script:EndpointFragStatus`r`nFree space: $Script:EndpointFreeSpace`r`nFragmentation: $Script:EndpointFragmentation"

$SQLCommand = @"
if exists(SELECT * from Table_CustomerDiskHealthData where EndpointSerial='$Script:EndpointSerial')
BEGIN            
UPDATE Table_CustomerDiskHealthData SET EndpointComputerName='$Script:EndpointComputerName',EndpointOS='$Script:EndpointOS',EndpointType='$Script:EndpointType',EndpointSiteName='$Script:EndpointSiteName',EndpointVolumes='$Script:EndpointVolumes',EndpointSpaceStatus='$Script:EndpointSpaceStatus',EndpointFragStatus='$Script:EndpointFragStatus',EndpointFreeSpace='$Script:EndpointFreeSpace',EndpointFragmentation='$Script:EndpointFragmentation',LastPostDate='$DateTime' WHERE (EndpointSerial = '$Script:EndpointSerial')
END                  
else            
BEGIN
INSERT INTO [$SQLDatabase].[dbo].[Table_CustomerDiskHealthData](EndpointSerial,EndpointComputerName,EndpointOS,EndpointType,EndpointSiteName,EndpointVolumes,EndpointSpaceStatus,EndpointFragStatus,EndpointFreeSpace,EndpointFragmentation,LastPostDate)
VALUES ('$Script:EndpointSerial','$Script:EndpointComputerName','$Script:EndpointOS','$Script:EndpointType','$Script:EndpointSiteName','$Script:EndpointVolumes','$Script:EndpointSpaceStatus','$Script:EndpointFragStatus','$Script:EndpointFreeSpace','$Script:EndpointFragmentation','$DateTime')
END
"@      

    $Params = @{
        'ServerInstance'=$SQLServer;
        'Database'=$SQLDatabase;
        'Username'=$SQLUsername;
        'Password'=$SQLPassword
    }
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-SqlCmd @Params -Query $SQLCommand -EncryptConnection
}

function Write-MSPLog {
    Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [ValidateSet('MSP Monitoring')]
         [string] $LogSource,
         [Parameter(Mandatory=$true, Position=1)]
         [ValidateSet('Information','Warning','Error')]
         [string] $LogType,
         [Parameter(Mandatory=$true, Position=2)]
         [string] $LogMessage
    )

    New-EventLog -LogName MSP-IT -Source 'MSP' -ErrorAction SilentlyContinue
    if(!(Get-EventLog -LogName MSP-IT -Source 'MSP Monitoring' -ErrorAction SilentlyContinue)){
        New-EventLog -LogName MSP-IT -Source 'MSP Monitoring' -ErrorAction SilentlyContinue
    }
    Write-EventLog -Log MSP-IT -Source "MSP Monitoring" -EventID 0 -EntryType $LogType -Message "$LogMessage"
}

function PunchIt {

    if(!(Get-Module -Name "PSWindowsUpdate")){
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Information" -LogMessage "PSWindowsUpdate module is not installed...installing now..."
        InstallPSWindowsUpdatePSModule
    }
    if(!(Get-Module -Name "SqlServer")){
        Write-MSPLog -LogSource "MSP Monitoring" -LogType "Information" -LogMessage "SqlServer module is not installed...installing now..."
        InstallSqlServerPSModule
    }

    GetEndpointInfo
    WindowsUpdateSchedTaskCheck
    CheckUpdateStatus
    PostPatchHealthInfo
    GetSystemUptimeData
    ForceRebootSchedTaskCheck
    PendingRebootCheckerSchedTaskCheck
    GetEndpointPendingRebootState
    PostSystemUptimeInfo
    GetDiskInfo
    PostDiskInfo
}
