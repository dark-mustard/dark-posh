
BeforeAll {
    Push-Location -Path $ModuleInfo.Directory

    #region Cleanly Import Module 
    #    Get-Module $ModuleName | Remove-Module -Force
    #    Import-Module $ModuleRootPath -Force
    #endregion

    #Clear-Host
}
AfterAll {
    Pop-Location
}



Describe "Validate Module [$($ModuleInfo.Name)]" {
    Context "Validate module files exist."{
        It "Root module file exists [$($ModuleInfo.Files.RootModule.Name)]" {
            $ModuleInfo.Files.RootModule.Path | Should -Exist
        }
        It "Valid manifest file exists [$($ModuleInfo.Files.ModuleManifest.Name)]" {
            $ModuleInfo.Files.ModuleManifest.Path | Should -Exist
            #$ModuleInfo.Files.ModuleManifest.Path | Should -FileContentMatch $ModuleInfo.Files.RootModule.Name
        }
    }
    Context "Check module content for errors."{
        It "Module manifest points to correct RootModule element [$($ModuleInfo.Files.RootModule.Name)]" {
            $ModuleInfo.Files.ModuleManifest.Path | Should -FileContentMatch $ModuleInfo.Files.RootModule.Name
        }
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
$ValidParemeterSets_StartSession_LogFileOptions=@(
    @{ LogLast = $true }
    @{ LogAll = $true }
    @{ IncludeTranscript = $true }
    @{ LogAll = $true; LogLast = $true }
    @{ LogAll = $true; IncludeTranscript = $true }
    @{ LogLast = $true; IncludeTranscript = $true }
    @{ LogAll = $true; LogLast = $true; IncludeTranscript = $true }
)
$ValidParemeterSets_StartSession=@()
$ValidParemeterSets_StartSession_LogFileOptions | ForEach-Object {
    $ValidParemeterSets_StartSession+=,$_
    #$script:ValidParemeterSets_StartSession.Add($_, $scriptValidParemeterSets_StartSession_LogFileOptions[$_])
}
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
