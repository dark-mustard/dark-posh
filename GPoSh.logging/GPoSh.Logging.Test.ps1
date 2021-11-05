Import-Module GPoSh.Logging

#region Test Functions
    function Test-StartStopGPSession{
        function CompleteTest{
            New-DarkLogMessage -Message "Testing VERBOSE message."       -MessageLevel Verbose
            New-DarkLogMessage -Message "Testing DEBUG message."         -MessageLevel Debug
            New-DarkLogMessage -Message "Testing INFORMATIONAL message." -MessageLevel Information
            New-DarkLogMessage -Message "Testing WARNING message."       -MessageLevel Warning
            New-DarkLogMessage -Message "Testing ERROR message."         -MessageLevel Error
            Stop-DarkSession
        }
        function Success{
            CompleteTest
            Write-Host "SUCCESS" -BackgroundColor DarkGreen -ForegroundColor White
        }
        function Failure{
            CompleteTest
            Write-Host "FAILURE" -BackgroundColor Red -ForegroundColor White
        }
        $TMPDir = ("{0}\logtmp{1}" -f $PSScriptRoot, (Get-Date).ToString("yyyyMMdd")) 
        $FilePrefix = "CUSTOM_PREFIX_"
        if(Start-DarkSession) { Success } else { Failure }
        if(Start-DarkSession -LogOutputDirectory $TMPDir) { Success } else { Failure }
        if(Start-DarkSession -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug) { Success } else { Failure }
        if(Start-DarkSession -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogLast) { Success } else { Failure }
        if(Start-DarkSession -LogAll) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableVerbose) { Success } else { Failure }
        #---
        if(Start-DarkSession -EnableDebug -LogOutputDirectory $TMPDir) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableDebug) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogAll -EnableDebug) { Success } else { Failure }
        if(Start-DarkSession -LogAll -EnableVerbose) { Success } else { Failure }
        #---
        if(Start-DarkSession -EnableDebug -LogOutputDirectory $TMPDir -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose -LogOutputDirectory $TMPDir) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableDebug -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogAll -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableDebug) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableDebug -EnableVerbose) { Success } else { Failure }
        #---
        if(Start-DarkSession -EnableDebug -EnableVerbose -LogOutputDirectory $TMPDir -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose -IncludeTranscript -LogOutputDirectory $TMPDir) { Success } else { Failure }
        if(Start-DarkSession -EnableDebug -EnableVerbose -IncludeTranscript -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableDebug -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-DarkSession -LogLast -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-DarkSession -LogAll -LogLast -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        #---
        if(Start-DarkSession -EnableDebug -EnableVerbose -IncludeTranscript -LogOutputDirectory $TMPDir -LogFileNamePrefix $FilePrefix) { Success } else { Failure }
        #---
    }
    function Test-LogFileCreation{
        #Write-Host "***********************************"
        #Write-Host "*** FUNCTION INVOCATION DETAILS ***"
        #Write-Host "***********************************"
        #$MyInvocation
        #Write-Host "***********************************"
        #$ScriptDir     = $MyInvocation.PSScriptRoot
        #$ScriptName    = (Split-Path $MyInvocation.PSCommandPath -Leaf)
        #$LogNamePrefix = $($ScriptName.Substring(0, $ScriptName.IndexOf((".{0}" -f @($ScriptName.Split(".") | Select -Last 1)[0]))))
        #$LogLast       = ("{0}\{1}_LAST.log" -f $ScriptDir, $LogNamePrefix)
        #$LogAll        = ("{0}\{1}.log" -f $ScriptDir, $LogNamePrefix)
        #New-DarkSessionLog -LogAll $LogAll -LogLast $LogLast -EnableDebug -EnableVerbose -IncludeTranscript
        Start-DarkSession -LogAll -LogLast -EnableDebug -EnableVerbose -IncludeTranscript
        Stop-DarkSession
    }
#endregion



try{
    Start-DarkSession -LogAll -LogLast -EnableDebug -EnableVerbose -IncludeTranscript
    New-DarkLogMessage -MessagePrefix "  |-" -Message "Testing VERBOSE message." -MessageLevel Verbose
    New-DarkLogMessage -Message "Testing DEBUG message." -MessageLevel Debug
    New-DarkLogMessage -Message "Testing INFORMATION message." -MessageLevel Information
    New-DarkLogMessage -Message "Testing WARNING message." -MessageLevel Warning
    New-DarkLogMessage -Message "Testing ERROR message." -MessageLevel Error
    #Test-StartStopGPSession
    #Test-LogFileCreation
    #New-DarkLogMessage -MessagePrefix "*" -Message "TESTING"
} catch {
    New-DarkLogMessage -Message $_
} finally {
    Stop-DarkSession
}
Remove-Module GPoSh.Logging