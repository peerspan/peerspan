param(
 [ValidateSet('start','stop','status','token','serve','doctor')][string]$Command='status',
 [string]$Distro='Ubuntu-24.04',
 [string]$LinuxUser=''
)
$ErrorActionPreference='Stop'
$managedWslArgs=@('-d',$Distro)
if($LinuxUser){$managedWslArgs+=@('-u',$LinuxUser)}
$managedLinuxRepo=(& wsl.exe @managedWslArgs --exec wslpath -a ($PSScriptRoot -replace '\\','/')).Trim()
if($LASTEXITCODE -ne 0){throw 'Cannot resolve the fork checkout in WSL'}
if($Command -eq 'start' -or $Command -eq 'stop'){
 & wsl.exe @managedWslArgs --exec systemctl --user $Command peerspan-managed.service
 if($LASTEXITCODE -ne 0){throw 'Managed service command failed; see managed/README.md for installation'}
 if($Command -eq 'start'){Write-Output 'Peerspan Managed: http://localhost:4310'}
}else{
 & wsl.exe @managedWslArgs --exec bash -lc 'exec node "$1/managed/cli.mjs" "$2"' managed $managedLinuxRepo $Command
 if($LASTEXITCODE -ne 0){throw 'Managed command failed'}
}
