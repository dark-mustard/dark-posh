Import-Module GPoSh.Logging

#region Test Functions
    function Test-StartStopGPSession{
        function CompleteTest{
            New-GPLogMessage -Message "Testing VERBOSE message."       -LogMessageLevel Verbose
            New-GPLogMessage -Message "Testing DEBUG message."         -LogMessageLevel Debug
            New-GPLogMessage -Message "Testing INFORMATIONAL message." -LogMessageLevel Information
            New-GPLogMessage -Message "Testing WARNING message."       -LogMessageLevel Warning
            New-GPLogMessage -Message "Testing ERROR message."         -LogMessageLevel Error
            Stop-GPLog
        }
        function Success{
            CompleteTest
            Write-Host "SUCCESS" -BackgroundColor DarkGreen -ForegroundColor White
        }
        function Failure{
            CompleteTest
            Write-Host "FAILURE" -BackgroundColor Red -ForegroundColor White
        }
        $TMPDir = ("{0}\logtmp{1}" -f $env:tmp, (Get-Date).ToString("yyyyMMdd")) 
        $LogAll = ("{0}\DailyScriptLog.log" -f $TMPDir, (Get-Date).ToString("yyyyMMdd"))
        if(Start-GPLog) { Success } else { Failure }
        if(Start-GPLog -EnableDebug) { Success } else { Failure }
        if(Start-GPLog -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.1.1")) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.2.1") -EnableDebug) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.2.2") -EnableDebug -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.2.3") -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.2.4") -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.3.1") -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "1.3.2") -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -EnableDebug) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.1.1")) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.2.1") -EnableDebug) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.2.2") -EnableDebug -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.2.3") -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.2.4") -EnableVerbose -IncludeTranscript) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.3.1") -EnableDebug -EnableVerbose) { Success } else { Failure }
        if(Start-GPLog -LogAll $LogAll -LogLast ("{0}\ScriptRun_{1}.log" -f $TMPDir, "2.3.2") -EnableDebug -EnableVerbose -IncludeTranscript) { Success } else { Failure }
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
        #Start-GPLog -LogAll $LogAll -LogLast $LogLast -EnableDebug -EnableVerbose -IncludeTranscript
        Start-GPLog -LogAll -LogLast -EnableDebug -EnableVerbose -IncludeTranscript
        Stop-GPLog
    }
#endregion
Write-Host "*********************************"
Write-Host "*** SCRIPT INVOCATION DETAILS ***"
Write-Host "*********************************"
<#
$InvocationInfo=[PSCustomObject]@{
    MyCommand = ($MyInvocation.MyCommand | Select * -ExcludeProperty 'ScriptBlock', 'ScriptContents')
}
$MyInvocation | Get-Member -MemberType Property | Where { $_.Name -notin @( 'MyCommand' ) } | %{
    $InvocationInfo | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
}
$InvocationInfo | ConvertTo-Json
#>
$MyInvocation
Write-Host "*********************************"


#Test-StartStopGPSession
Test-LogFileCreation

Remove-Module GPoSh.Logging
