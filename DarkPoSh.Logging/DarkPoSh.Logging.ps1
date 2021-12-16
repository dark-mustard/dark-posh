
$global:ValidParemeterSets_StartSession_LogFileOptions=@(
    @{ LogLast = $true }
    @{ LogAll = $true }
    @{ IncludeTranscript = $true }
    @{ LogAll = $true; LogLast = $true }
    @{ LogAll = $true; IncludeTranscript = $true }
    @{ LogLast = $true; IncludeTranscript = $true }
    @{ LogAll = $true; LogLast = $true; IncludeTranscript = $true }
)
$global:ValidParemeterSets_StartSession=@()
$global:ValidParemeterSets_StartSession_LogFileOptions | %{
    $global:ValidParemeterSets_StartSession+=,$_
    #$script:ValidParemeterSets_StartSession.Add($_, $scriptValidParemeterSets_StartSession_LogFileOptions[$_])
}
$ModulePath = "{0}\{1}" -f $PSScriptRoot, $myInvocation.MyCommand.Name.Replace(".Tests.ps1", ".psm1")
$ModuleName = "{0}" -f $myInvocation.MyCommand.Name.Replace(".Tests.ps1", "")

Import-Module $ModulePath
Describe "Start-DarkSession / Stop-DarkSession" {
    Context "when a valid parameter set is provided to Start-DarkSession" {
        It "should return $true" {
            $AllResultsSuccessful = $true
            $global:ValidParemeterSets_StartSession | %{
                $ParamList = $_
                #Write-Output "$($ParamList | ConvertTo-Json)"
                $Result = Start-DarkSession @ParamList
                if($Result -eq $true){
                    try{
                        Stop-DarkSession | Out-Null
                    } catch {
                        # DO NOTHING
                    }
                } else {
                    $AllResultsSuccessful = $false
                }
                $Result | Should -Be $true
            }
            $AllResultsSuccessful | Should -Be $true
        }
    }

    Context "when running Stop-Session and any valid combination of [LogAll], [LogLast] and [IncludeTranscript] were used in the Start-Session command" {
        It "should return a csv string of the file paths to the requested log files created" {
            #$AllResultsIncludeFileLists = $true
            $global:ValidParemeterSets_StartSession_LogFileOptions | %{
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
}
<#
Describe "New-DarkLogMessage" {

}
#>
Describe "Removing Module" {
    Context "When running the Remove-Module command" {
        It "should not throw any errors" {
            Remove-Module $myInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
        }
    }
}
