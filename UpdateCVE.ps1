param(

    [switch]$Update
)

Write-Host "
                          ..:::::::::..                              
                      .:-===--::::::::--==-:.                         
                   .:==-:.               .:-==-.                      
                 .-=-.                       .-==:                    
               .-=-.                            :==.                  
              :==.           .::--:::             -=-                 
             -=-            -=========.            :=-                
            -=-             ==========-             :=-               
           :=-        .::--:  .......  ---:..        -=:              
           ==.      :=========-------=========.       ==              
          .==        :======================-:        -=:             
          :=-           :====-======--===-.           :=:             
          :=-         :======-:-===:-======-.         :=:             
          .==         .:-================-:..         -=.             
           ==.            .============-              ==              
           .==             -===========-             -=:              
            :=-             .-=======-              -=-               
             :=-              .====-.              -=-                
              .==:              -=:              .==:                 
                :==:             .             .-=-                   
                  :==:.                     .:==-.                    
                    .-==-:.             .:-==-:-=-.                   
                       .:--==---------===-:.    .-=-.                 
                             .........            .-=-.               
                                                    .-=-.             
                                                      .-- longmdx.github           
" -ForegroundColor Magenta

#table version
[reflection.assembly]::LoadWithPartialName("System.Version")
if($Update) {
    # kiểm tra các bản vá từ năm 2017
    $initYear = 2017
    $lastYear = (Get-Date).Year
    $lastMonth = (Get-Date).Month
    $listMonth = @("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    $listID = [System.Collections.ArrayList]@()
    $affectedSoftware = [System.Collections.ArrayList]@()
    $msrcCvrfCVESummary = [System.Collections.ArrayList]@()
    $cveSummary = $null

    while ($initYear -le $lastYear) {
    
        foreach($id in $listMonth) {

            $lastStringMonth = (Get-Culture).DateTimeFormat.GetMonthName($lastMonth).Substring(0,3)
            $stringID = "$initYear-" + $id
            $msrcCvrfDocument = Get-MsrcCvrfDocument -ID $stringID
            $msrcCvrfdata = $msrcCvrfDocument | Get-MsrcCvrfAffectedSoftware
            $msrcCvrfCVESummary = Get-MsrcCvrfCVESummary -ProductTree $msrcCvrfDocument.ProductTree -Vulnerability $msrcCvrfDocument.Vulnerability | Select CVE, Description
            
            $affectedSoftware += New-Object -Type PSObject -Property @{
                
                FullProductName = $msrcCvrfdata.FullProductName
                CVE = $msrcCvrfdata.CVE
                Severity = $msrcCvrfdata.Severity
                CvssScoreSet = $msrcCvrfdata.CvssScoreSet
                FixedBuild = $msrcCvrfdata.FixedBuild
                Description = $msrcCvrfCVESummary.Description 
            }

            Write-Host "Searching at $id-$initYear `r" -NoNewline -ForegroundColor Yellow
            if ($lastStringMonth -eq $id) {
                break
            }
        }
        $initYear += 1
    }
    $affectedSoftware | Export-Csv -Path "listCVEs.csv"
}

$affectedSoftware = Import-Csv -Path "listCVEs.csv"
$versionCheck = Import-Csv -Path "VersionCheck.csv"

[System.Collections.ArrayList]$listCVEsFinal = @()
[System.Collections.ArrayList]$CVEs = @()
[System.Collections.ArrayList]$detectObject = @()

foreach ($affected in $affectedSoftware) {
    
    $FullProductName = $affected.FullProductName
    $CVE = $affected.CVE
    $Severity = $affected.Severity
    $CvssScoreSet = $affected.CvssScoreSet
    $Impact = $affected.Impact
    $FixedBuild = $affected.FixedBuild
    $Description = $affected.Description

    if ($Severity.Contains('Moderate') -or $Severity.Contains('Critical') -or $Severity.Contains('Important')) {
        if($Impact.Contains('Remote Code Execution') -or $Impact.Contains('Elevation of Privilege')) {
            if ($FullProductName.Contains($versionCheck.ProductName) -and !$FullProductName.Contains('on')) {
            
                foreach ($verfixed in $FixedBuild) {
                
                    $FixedVersion = $verfixed.split('.')[0] + '.' + $verfixed.split('.')[1] + '.' + $verfixed.split('.')[2]
                    $FixedMirror = $verfixed.split('.')[3]
                
                    if ($FullProductName.Contains($versionCheck.systemType) -or !$FullProductName.Contains(' for ')) {
                    
                        if ($FixedMirror -gt $versionCheck.MirrorNumber -and $versionCheck.version -eq $FixedVersion) {
                    
                            $detectObject += new-object -Type PSObject -Property @{
                                ProductName = $FullProductName
                                Impact = $Impact
                                Severity = $Severity
                                CVE = $CVE
                                CvssScoreSet = $CvssScoreSet
                                FixedBuild = $FixedBuild
                                Description = $Description
                            }
                        }
                    }
                }

            }
        }
    }
}

$detectObject | Format-Table