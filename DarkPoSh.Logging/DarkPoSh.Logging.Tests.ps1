BeforeDiscovery {
    #if(($null -eq $global:ModuleInfo) -and ($null -ne $ModuleInfo)){
    #    $global:ModuleInfo = $ModuleInfo
    #}
    #$global:ModuleInfo = $ModuleInfo
    #Push-Location -Path $ModuleInfo.Directory
}
BeforeAll {
    . $PSCommandPath.Replace('.Tests.ps1','.ps1')
    function Get-TestContext{
        param(
            [String]$SourcePath = $PSCommandPath
        )
        $TestFileSuffixes = @(
            ".Tests"
            ".Unit"
            ".Acceptance"
        )
        $Timestamp = Get-Date
        $PathInfo  = Get-Item $SourcePath
        #region Sub-Functions
            function Get-TestContextBaseName{
                param(
                    [String]$SourcePath
                )
                $BaseName = $SourceName
                $TestFileSuffixes | ForEach-Object {
                    $Suffix = (".{0}" -f $($_.Trim(".")))
                    if($BaseName -like "*$Suffix"){
                        $BaseName = $BaseName.Replace($Suffix, "")
                    }
                }
                return $BaseName
            }
        #endregion
        $TestContext = ([PSCustomObject]@{
            Runtime   = [PSCustomObject]@{
                Timestamp       = $Timestamp
                TimestampString = $($Timestamp.ToString('yyyyMMddHHmmss'))
            }
            Directory = $null
            BaseName  = $(Get-TestContextBaseName -SourcePath $PathInfo.BaseName)
            Files = [PSCustomObject]@{
                RootModule = [PSCustomObject]@{
                    Name = $("{0}.psm1" -f $ModuleName)
                    Path = $(Join-Path $SourceDirectory ("{0}.psm1" -f $ModuleName))
                }
                ModuleManifest = [PSCustomObject]@{
                    Name = $("{0}.psd1" -f $ModuleName)
                    Path = $(Join-Path $SourceDirectory ("{0}.psd1" -f $ModuleName))
                }
            }
        })
        
        
        $TimestampString         = $Timestamp.ToString('yyyyMMddHHmmss')
        
        if($PathInfo.Attributes -contains "Directory"){
            $TestContext.Directory = $PathInfo.FullName
            $SourceName      = (Split-Path $PSCommandPath -Leaf)
        } else {
            $TestContext.Directory = $PathInfo.Directory
            $SourceName      = $PathInfo.BaseName
        }
        
        $TestContext.BaseName = 
        
    }
    
    #if(($null -eq $global:ModuleInfo) -and ($null -ne $ModuleInfo)){
    #    $global:ModuleInfo = $ModuleInfo
    #}
    #Push-Location -Path $ModuleInfo.Directory
    
    #$global:ModuleInfo.Exports.Functions.StartSession.Name | ForEach-Object {
    #    $FunctionName = $global:ModuleInfo.Exports.Functions.StartSession.Name
    #    $FunctionInfo = $global:ModuleInfo.Exports.Functions[$FunctionName]
    #    $FunctionInfo.ValidParameterSets
    #}
    if($ModuleInfo.PSObject.Properties.Name -notcontains "Exports"){
        $ModuleInfo | Add-Member -MemberType NoteProperty -Name "Exports" -Value $null
    } 
    $ModuleInfo.Exports = [PSCustomObject]@{
        Functions = [PSCustomObject]@{
            StartSession = [PSCustomObject]@{
                Name = "Start-DarkSession"
                ValidParameterSets = @(
                    @{ LogLast = $true }
                    @{ LogAll = $true }
                    @{ IncludeTranscript = $true }
                    @{ LogAll = $true; LogLast = $true }
                    @{ LogAll = $true; IncludeTranscript = $true }
                    @{ LogLast = $true; IncludeTranscript = $true }
                    @{ LogAll = $true; LogLast = $true; IncludeTranscript = $true }
                )
            }
            StopSession  = [PSCustomObject]@{
                Name = "Stop-DarkSession"
                ValidParameterSets = @()
            }
            WriteLog     = [PSCustomObject]@{
                Name = "Write-DarkLog"
                ValidParameterSets = @()
            }
        }
    }
    # Get list of exported functions:
    #$global:ModuleInfo.Exports.Functions.PSObject.Properties.Value.Name

    #$global:ModuleInfo.Exports.Functions.StartSession.Name
    #$global:ModuleInfo.Exports.Functions.StartSession.ValidParameterSets


    #region Cleanly Import Module 
    #    Get-Module $ModuleInfo.Name | Remove-Module -Force
    #    Import-Module $ModuleInfo.Directory -Force
    #endregion
}
AfterAll {
    #Remove-Variable -Scope Global -Name "ModuleInfo"
    #Pop-Location
}

Describe "Validate Module [$($global:ModuleInfo.Name)]" {
    Context "Validate module files exist."{
        It ("Root module file exists [$($global:ModuleInfo.Files.RootModule.Name)]") {
            $ModuleInfo.Files.RootModule.Path | Should -Exist
        }
        It "Manifest file exists [$($ModuleInfo.Files.ModuleManifest.Name)]" {
            $ModuleInfo.Files.ModuleManifest.Path | Should -Exist
        }
        It "Module manifest points to correct RootModule element [$($ModuleInfo.Files.RootModule.Name)]" {
            $ModuleInfo.Files.ModuleManifest.Path | Should -FileContentMatch $ModuleInfo.Files.RootModule.Name
        }
        #It "Valid manifest file exists [$($global:ModuleInfo.Files.ModuleManifest.Name)]" {
        #    $ModuleInfo.Files.ModuleManifest.Path | Should -Exist
        #    $ModuleInfo.Files.ModuleManifest.Path | Should -FileContentMatch $ModuleInfo.Files.RootModule.Name
        #}
    }
    Context "Check module content for errors."{
        It "Module source files contain no errors." {
            $ModuleFileErrorCount = 0
            @(
                $ModuleInfo.Files.RootModule.Path
                $ModuleInfo.Files.ModuleManifest.Path
            ) | ForEach-Object {
                $ModuleFile = $_
                Get-Content -Path $ModuleFile -ErrorAction Stop
                $ModuleFileErrors = $null
                $null = [System.Management.Automation.PSParser]::Tokenize($ModuleFile, [ref]$ModuleFileErrors)
                $ModuleFileErrorCount += $ModuleFileErrors.Count
            }
            $ModuleFileErrorCount | Should -Be 0
        }
    }
}
<#
Describe "Validate Session Start / Stop" {
    $ValidParameterSets = @(
        @{ LogLast = $true }
        @{ LogAll = $true }
        @{ IncludeTranscript = $true }
        @{ LogAll = $true; LogLast = $true }
        @{ LogAll = $true; IncludeTranscript = $true }
        @{ LogLast = $true; IncludeTranscript = $true }
        @{ LogAll = $true; LogLast = $true; IncludeTranscript = $true }
    )
    #foreach ($ParamList in $global:ModuleInfo.Exports.Functions.StartSession.ValidParameterSets) {
    foreach ($ParamList in $ValidParameterSets) {
        Context ("Validate Start / Stop session parameter set: {0}" -f $($ParamList | ConvertTo-Json -Compress)){
            
            $Result = Start-DarkSession @ParamList

            It "should return $true" {
                $Result | Should -Be $true
            }

            $OutputFileList = $null
            if($Result){
                $OutputFileList = Stop-DarkSession
            }

            It "Stop-DarkSession should return non-null string with log files generated" {
                [String]::IsNullOrWhiteSpace($OutputFileList) | Should -Be $false 
            }   

            $OutputFileList = $OutputFileList.Split(",")

            It "Stop-DarkSession should return non-null string with log files generated" {
                # Number of files included should correspond to the number of log switches are included
                $OutputFileList.Count | Should -Be $ParamList.Keys.Count
            }

        }
    }
    
}
#>
<#

Describe "Start-DarkSession / Stop-DarkSession" {
    #Context "when a valid parameter set is provided to Start-DarkSession" {
$ValidParemeterSets_StartSession_LogFileOptions | ForEach-Object {
    #Describe ("Start/Stop-DarkSession - Parmeters: [{0}]" -f $($_.Keys -Join ",")) {
        $ParamList = $_
        #Write-Output "$($ParamList | ConvertTo-Json)"
            Context ("Parmeters: [{0}]" -f $($ParamList.Keys -Join ",")) {
                $Result = Start-DarkSession @ParamList
                It "should return $true" {
                    $Result | Should -Be $true
                }
            
                #$OutputFileList = $null
                if($Result){
                    $OutputFileList = Stop-DarkSession
                }
                # Output string shouldn't be null or empty
                
                It "Stop-DarkSession should return non-null string with log files generated" {
                    #$OutputFileList = $null
                    #if($Result){
                    #    $OutputFileList = Stop-DarkSession
                    #}
                    [String]::IsNullOrWhiteSpace($OutputFileList) | Should -Be $false 
                }   

                $OutputFileList = $OutputFileList.Split(",")

                It "Stop-DarkSession output should contain the same number of log file paths requested in Start-DarkSession" {
                    # Number of files included should correspond to the number of log switches are included
                    $OutputFileList.Count | Should -Be $ParamList.Keys.Count
                }   
                $AllFilesExist = $true
                $OutputFileList | ForEach-Object {
                    if(-Not (Test-Path -Path $_)){
                        $AllFilesExist = $false
                    }
                }
                It "should have created all returned output files on the file system" {
                    $AllFilesExist | Should -Be $true
                }

                #}
                #$AllResultsSuccessful | Should -Be $true
            }
    }   
}
    #}
#>
<#
    Context "when running Stop-Session and any valid combination of [LogAll], [LogLast] and [IncludeTranscript] were used in the Start-Session command" {
        It "should return a csv string of the file paths to the requested log files created" {
            #$AllResultsIncludeFileLists = $true
            $global:ValidParemeterSets_StartSession_LogFileOptions | ForEach-Object {
                $ParamList = $_
                $OutputFileList = $null
                if(Start-DarkSession @ParamList){
                    $OutputFileList = Stop-DarkSession
                } #else {
                    #$AllResultsIncludeFileLists = $false
                #}

                # Output string shouldn't be null or empty
                [String]::IsNullOrWhiteSpace($OutputFileList) | Should -Be $false -Because ("ParamList specifies {0} log file{1}." -f $ParamList.Keys.Count, $(if($ParamList.Keys.Count -eq 1){ "" } else { "s" }))
                               
                # Number of files included should correspond to the number of log switches are included
                $OutputFileList = $OutputFileList.Split(",")
                $OutputFileList.Count | Should -Be $ParamList.Keys.Count -Because ("ParamList includes;{0}{1}  {0}while OutputFileList includes:{0}{2}" -f ([Environment]::NewLine), ($ParamList | ConvertTo-Json), ($OutputFileList | ConvertTo-Json))
            }
            #$AllResultsIncludeFileLists | Should -Be $true
        }
    }
    #>
    <#
    Context "when a specifying [LogAll], [LogLast] and [IncludeTranscript] switches in the Start-DarkSession command" {
        It "should return a csv string with 3 log files created" {
            $OutputFileList = $null
            if(Start-DarkSession -LogAll -LogLast -IncludeTranscript){
                $OutputFileList = Stop-DarkSession
            }
            $OutputFileList.Split(',').Count | Should -Be 3
        }
        It "should have created all returned output files on the file system" {
            $OutputFileList = $null
            if(Start-DarkSession -LogAll -LogLast -IncludeTranscript){
                $OutputFileList = Stop-DarkSession
            }
            $AllFilesExist = $true
            $OutputFileList=$OutputFileList.Split(',')
            $OutputFileList | %{
                if(-Not (Test-Path -Path $_)){
                    $AllFilesExist = $false
                }
            }
            $AllFilesExist | Should -Be $true
        }
    }
    #>
#}
<#
Describe "New-DarkLogMessage" {

}
#>
<#
Describe "Removing Module" {
    Context "When running the Remove-Module command" {
        It "should not throw any errors" {
            $Exception=$null
            try{
                Remove-Module $myInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
            } catch {
                $Exception=$_
            }
            $Exception | Should -Be $null
        }
    }
}
#>
