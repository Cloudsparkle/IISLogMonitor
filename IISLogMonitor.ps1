#requires -modules ActiveDirectory
<#
.SYNOPSIS
  Get al unique endpoints and currently logged on user accessing and IIS webserver
.DESCRIPTION
  This script parses IIS logs continuously and produces a list of unique IP. That IP is then used to gather hostname and currently logged on user via Remote Registry.
.PARAMETER <Parameter_Name>
    None
.INPUTS
  IIS Logfiles
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Bart Jacobs - @Cloudsparkle
  Creation Date:  23/12/2021
  Purpose/Change: Parse IIS Logs for unique endpoints
.EXAMPLE
  None
#>

#Initialize variables
$TempFile = $env:temp +"\WebLog.csv"
$Logpath = "C:\inetpub\logs\LogFiles\W3SVC1"
$Computergroup = "C_Computers_WrongCTXConfig"
$Usergroup = "C_Users_WrongCTXConfig"
$LastIPList = ""
$LastNumberOfIP = 0

Function Ping([string]$hostname, [int]$timeout = 500, [int]$retries = 3)
{
  $result = $true
  $ping = new-object System.Net.NetworkInformation.Ping #creates a ping object
  $i = 0
  do
  {
    $i++
	   try
     {
       $result = $ping.send($hostname, $timeout).Status.ToString()
     }
     catch
     {
       continue
     }
     if ($result -eq "success") { return $true }

  } until ($i -eq $retries)
  return $false
}

while ($true)
{
  # Get Current IIS log filename
  $date= get-date
  $year = ($date.Year).ToString()
  $shortyear = $year.substring($year.length - 2)
  $month = ($date.Month).ToString()
  if ($month.Length -eq 1)
  {
    $month = "0"+$month
  }
  $day = ($date.Day).ToString()
  if ($day.Length -eq 1)
  {
    $day = "0"+$day
  }

  $filename = $logpath+"\u_ex"+$shortyear+$month+$day+".log"

  # Find the right AD Domain Controller
  $dc = Get-ADDomainController -DomainName $SelectedDomain -Discover -NextClosestSite

  # Clear temp file
  $TempFileExists = Test-Path $TempFile
  If ($TempFileExists -eq $True)
  {
    Remove-Item $TempFile
  }

  # Process current logfile
  (Get-Content $filename | Where-Object {$_ -notlike "#[S,V,D]*"}) -replace "#Fields: ","" | Out-File -append $TempFile

  # Import the temporary CSV file to memory
  $webLog = Import-Csv $TempFile -Delimiter " "

  # Extracting all unique IP's
  Write-Host -ForegroundColor Yellow "Gathering IP addresses..."
  $IPList = $weblog | Select-Object -Property 'c-ip' -Unique | Sort-Object -Property 'c-ip' -Descending
  if ($IPList.count -eq $LastNumberOfIP)
  {
    Write-Host "No new IP addresses detected."
    Continue
  }

  # Use IP addresses to get hostname en username
  Write-Host -ForegroundColor Yellow "Processing IP addresses..."
  Foreach ($IP in $IPList)
  {
    # Skip localhost
    if ($IP.'c-ip' -eq "127.0.0.1")
    {
      continue
    }

    # Empty variables
    $RegLM = ""
    $RegKeyLM = ""
    $Computername = ""
    $user = ""

    Write-Host "Processing IP:"$IP.'c-ip'
    if ($LastIPList.'c-ip' -contains($ip.'c-ip'))
    {
      Write-Host "IP:"$IP.'c-ip'"already processed in previous run. Skipping..." -ForegroundColor DarkYellow
      Continue
    }
    $IPonline = Ping $IP.'c-ip' 100
    if ($IPonline -eq $True)
    {
      Try
      {
        $RegLM = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $IP.'c-ip')
      }
      Catch
      {
        write-host "Error connecting to:"($IP.'c-ip') -ForegroundColor Red
      }
    }

    if ($RegLM -ne "")
    {
      $RegKeyLM = $RegLM.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName")
      $Computername = $RegKeyLM.GetValue("ComputerName")

      $RegKeyLM2 = $RegLM.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI")
      $User = $RegKeyLM2.GetValue("LastLoggedOnUser")

      if ($user -ne $null)
      {
        $aduser = $user.Split("\")
        $aduser = $aduser[1]

        Try
        {
          Add-ADGroupMember -Identity $usergroup -Members (get-aduser $aduser) -Server $dc.HostName[0]
          write-host "User"$aduser "added to AD group" -ForegroundColor Green
        }
        Catch
        {
          write-host "Error adding user object to AD group" -ForegroundColor Red
        }
      }

      Try
      {
        Add-ADGroupMember -Identity $Computergroup -Members (get-adcomputer $Computername) -Server $dc.HostName[0]
        Write-Host "Computer"$Computername "added to AD group" -ForegroundColor Green
      }
      Catch
      {
        write-host "Error adding computer object to AD group" -ForegroundColor Red
      }


    }

  }

  $LastIPList = $IPList
  $LastNumberOfIP = $LastIPList.count

  # Memory clean up
  [System.GC]::Collect()
}
