#region Initialize module instance-specific variables

    # Generate id value unique to module import context
    #New-Variable -Scope Script -Visibility Private -Name "VariableVisibility" -Value "Private"
        New-Variable -Scope Script -Visibility Private -Name "VariableVisibility" -Value "Public"
    New-Variable -Scope Script -Visibility $script:VariableVisibility -Name "ModuleIdentifier" -Value $((New-Guid).Guid.Replace("-", ""))
    New-Variable -Scope Script -Visibility $script:VariableVisibility -Name "GPLogSessions" -Value @{}

    # Remove when module is unloaded
    $ExecutionContext.SessionState.Module.OnRemove = {
        Write-Host "****************** MODULE UNLOADING ******************" -ForegroundColor White -BackgroundColor Red
        Remove-Variable -Scope Script -Name "GPLogSessions"
        Remove-Variable -Scope Script -Name "ModuleIdentifier"
        Remove-Variable -Scope Script -Name "VariableVisibility"
    }

#endregion
#region GPoSh.Logging
    #region Logging / Output formatting
        enum GPLogMessageLevel{
            Verbose = 0
            Debug = 1
            Information = 2
            Warning = 3
            Error = 4
        }
        function New-GPLogMessage {
            param(
                [Object] $Message,
                [String] $MessagePrefixAddition = $null,
                [Nullable[GPLogMessageLevel]] $LogMessageLevel = $null,
                [Nullable[ConsoleColor]] $MessageColor = $null
            )
            #region Set-up Output-Formatting Dictionaries and Defaults 
                #region Independent (Customizable) Values
                        [GPLogMessageLevel] $DEFAULT_LogMessageLevel   = [GPLogMessageLevel]::Information
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Delim       = [ConsoleColor]::Gray
                    [Nullable[ConsoleColor]] $DEFAULT_Color             = $null
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Debug       = [ConsoleColor]::Cyan
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Verbose     = [ConsoleColor]::DarkCyan
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Information = $DEFAULT_Color
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Warning     = [ConsoleColor]::Yellow
                    [Nullable[ConsoleColor]] $DEFAULT_Color_Error       = [ConsoleColor]::Red
                #endregion
                #region Dependent (Non-Customizable) Values
                    #region Dictionaries
                        $DICT_LogMessageLevelStrings=@{
                            ([GPLogMessageLevel]::Verbose)     = "VERBOSE"
                            ([GPLogMessageLevel]::Debug)       = "DEBUG"
                            ([GPLogMessageLevel]::Information) = "INFO"
                            ([GPLogMessageLevel]::Warning)     = "WARNING"
                            ([GPLogMessageLevel]::Error)       = "ERROR"
                        }
                        $DICT_MessageAdditionalPrefixColors=@{
                            ([GPLogMessageLevel]::Verbose)     = $DEFAULT_Color_Verbose
                            ([GPLogMessageLevel]::Debug)       = $DEFAULT_Color_Debug
                            ([GPLogMessageLevel]::Information) = $DEFAULT_Color
                            ([GPLogMessageLevel]::Warning)     = $DEFAULT_Color
                            ([GPLogMessageLevel]::Error)       = $DEFAULT_Color
                        }
                        $DICT_LogMessageLevelColors=@{
                            ([GPLogMessageLevel]::Verbose)     = $DEFAULT_Color_Verbose
                            ([GPLogMessageLevel]::Debug)       = $DEFAULT_Color_Debug
                            #([GPLogMessageLevel]::Information) = $(if($null -ne $MessageColor) { $MessageColor } else { $DEFAULT_Color })
                            ([GPLogMessageLevel]::Information) = $DEFAULT_Color_Information
                            ([GPLogMessageLevel]::Warning)     = $DEFAULT_Color_Warning
                            ([GPLogMessageLevel]::Error)       = $DEFAULT_Color_Error
                        }
                    #endregion
                    if($null -eq $LogMessageLevel){
                        switch($Message.GetType().ToString()){
                            ("System.Management.Automation.ErrorRecord"){ 
                                # Set $MessageLevel to [Error] if null 
                                <###############################################################################
                                    # The following must be true for this to happen:
                                    #   1) $MessageLevel param was not explicitly identified when the function was called
                                    #   2) $Message param IS of type [System.Management.Automation.ErrorRecord]
                                    ###############################################################################>
                                if($null -eq $LogMessageLevel) {
                                    $LogMessageLevel = [GPLogMessageLevel]::Error
                                }
                            }
                            default{ # Set $LogMessageLevel equal to default value.
                                $LogMessageLevel = $DEFAULT_LogMessageLevel
                            }
                        }
                    }
                    [Nullable[ConsoleColor]] $LogMessageLevelColor      = $DICT_LogMessageLevelColors[$LogMessageLevel]
                #endregion
                #region Function-Specific Initialized Values
                    [Boolean]                $DisplayMessage            = $false
                    [String[]]               $MessageLineArray          = $null
                #endregion
                #region Create the $MessageLineArray and conditionally set the $MessageLevel
                    # Create the $MessageLineArray
                    switch($Message.GetType().ToString()){
                        ("System.Management.Automation.ErrorRecord"){ # Format exception elements into string array and conditionally set $MessageLevel
                            # Set $MessageLineArray equal to custom array of strings
                            <###############################################################################
                                # Formats an "Exception" object into the same format it would be displayed 
                                # in a console if unhandled.
                                ###############################################################################>
                            $MessageLineArray = @(
                                ("The following exception was encountered:")
                                $Indent=" ! "
                                ("{0}{1} : {2}" -f $Indent, $Message.InvocationInfo.InvocationName, $Message.Exception.Message)
                                @($Message.InvocationInfo.PositionMessage.Split([Environment]::NewLine).Where({ -Not [String]::IsNullOrWhiteSpace($_) })) | ForEach-Object{
                                    ("{0}{1}" -f $Indent, $_)
                                }
                                ("{0}    + CategoryInfo          : {1}" -f $Indent, $Message.CategoryInfo.ToString())
                                ("{0}    + FullyQualifiedErrorId : {1}" -f $Indent, $Message.FullyQualifiedErrorId.ToString())
                            )
                        }
                        ("System.Object[]", "System.String[]", "System.Int32[]"){ # For all arrays, just set $MessageLineArray equal to the input object
                            # Set $MessageLineArray equal to the input object
                            $MessageLineArray = $Message
                        }
                        default{ # By default, set $MessageLineArray equal to a new array containing the input object
                            # Set $MessageLineArray equal to a new array containing the input object
                            $MessageLineArray = @(
                                $Message
                            )
                        }
                    }

                    # Set MessageLevel to [$DEFAULT_LogMessageLevel] if null 
                    <###############################################################################
                        # The following must be true for this to happen:
                        #   1) $MessageLevel param was not explicitly identified when the function was called
                        #   2) $Message param IS NOT of type [System.Management.Automation.ErrorRecord]
                        ###############################################################################>
                    if($null -eq $LogMessageLevel) {
                        $LogMessageLevel = $DEFAULT_LogMessageLevel
                    }
                #endregion
                #region Decide whether or not to display the message
                    <###############################################################################
                        # All messages will be displayed without evaluation except for following message levels:
                        #   1) [GPLogMessageLevel]::Debug
                        #   2) [GPLogMessageLevel]::Verbose
                        # Below are the requirements necessary to display a message based on it's corresponding message level:
                        #   ----------------------------------------------------------------------------
                        #   | Message Level                  | Requirements to Display                 |
                        #   ----------------------------------------------------------------------------
                        #   | [GPLogMessageLevel]::Debug       | $DebugPreference must equal "Continue"   |
                        #   | [GPLogMessageLevel]::Verbose     | $VerbosePreference must equal "Continue" |
                        #   | [GPLogMessageLevel]::Information | (n/a)                                    |
                        #   | [GPLogMessageLevel]::Warning     | (n/a)                                    |
                        #   | [GPLogMessageLevel]::Error       | (n/a)                                    |
                        #   -----------------------------------------------------------------------------
                        ###############################################################################>
                    switch($LogMessageLevel){
                        ([GPLogMessageLevel]::Debug){
                            if($DebugPreference -eq "Continue"){
                                $DisplayMessage = $true
                            }
                        }
                        ([GPLogMessageLevel]::Verbose){
                            if($VerbosePreference -eq "Continue"){
                                $DisplayMessage = $true
                            }
                        }
                        Default{
                            $DisplayMessage = $true
                        }
                    }
                #endregion
            #endregion

            if($true -eq $DisplayMessage){
                # Display the message array
                $LogOutputMessageLines=@()
                for($a=0; $a -lt $MessageLineArray.Count; $a++){
                    # Set $MessageString value
                    [String]$MessageString=$MessageLineArray[$a]

                    # Only show a trailing "-" for the first line if one exists in the $MessagePrefixAddition.
                    if($MessagePrefixAddition.EndsWith("-") -and ($a -gt 0)){
                        $MessagePrefixAddition = ("{0} " -f $MessagePrefixAddition.TrimEnd("-"))
                    }

                    # Format and collect message elements in $MessageElements (order-specific hashtable)
                    $MessageElements=[Ordered]@{}
                    $MessageColor = if($null -ne $MessageColor) { $MessageColor } else { $LogMessageLevelColor }
                    $MessagePrefix = "$((Get-Date).ToString('yyyy-MM-dd hh:mm:ss')) | "
                        $MessageElements.Add($MessagePrefix, $DEFAULT_Color_Delim) 
                    $LogMessageLevelString = "$(('[{0}]' -f $DICT_LogMessageLevelStrings[$LogMessageLevel]).PadRight(9, ' '))"
                        $MessageElements.Add($LogMessageLevelString, $LogMessageLevelColor) 
                    $MessageElements.Add(" | ", $DEFAULT_Color_Delim) 
                    if($MessagePrefixAddition) {
                        $MessageElements.Add($MessagePrefixAddition, $DICT_MessageAdditionalPrefixColors[$LogMessageLevel])
                    }
                    $MessageElements.Add($MessageString, $MessageColor)
                    $MessageElements.Keys | ForEach-Object {
                        # Display message part with appropriate color
                        $Msg=$_
                        $MsgColor=$MessageElements[$Msg]
                        $CurrentItemIndex=@($MessageElements.Keys).IndexOf($Msg)
                        $TotalItemCount=@($MessageElements.Keys).Count
                        $NoNewLine=if($CurrentItemIndex -eq ($TotalItemCount - 1)){
                                $false
                            } else {
                                $true
                            }
                        if($null -eq $MsgColor) {
                            Write-Host $Msg -NoNewline:$NoNewLine
                        } else {
                            Write-Host $Msg -NoNewline:$NoNewLine -ForegroundColor $MsgColor
                        }
                    }
                    # Add to $LogOutputMessageText
                    $LogOutputMessageLines += $MessageElements.Keys -join ""
                }

                # Output to log files (if in use)
                $LogOutputMessageText = $LogOutputMessageLines -join [Environment]::NewLine
                if($null -ne $script:GPLogSessionID){
                    $script:GPLogSessions[$script:GPLogSessionID].LogList.Values | Where-Object { $_.LogName -notin @("GPLog_DEBUG") } | ForEach-Object { 
                        #$LogOutputMessageText | Out-File $_.FilePath -Append:$($_.AppendBehavior) -Force
                        $LogOutputMessageText | Out-File $_.FilePath -Append:$true -Force
                    }
                }
            }
        }
    #endregion
    #region Session Management      
        function Add-GPLogToSession{
            [CmdletBinding()]
            param(
                #[Parameter(Mandatory=$true)]
                #[ValidateNotNull()]
                #    [String] $SessionIdentifier,
                [Parameter(Mandatory=$true)]
                [ValidateNotNull()]
                    [String] $LogName,
                [Parameter(Mandatory=$false)]
                    [String] $FilePath,
                [Parameter(Mandatory=$false)]
                    [Switch] $AppendOnly
            )
            $Success = $false
            
            # Skip items with no file path and 
            if(-Not [String]::IsNullOrWhiteSpace($FilePath)) {
                try{
                    # Skip the transcript file from being created manually
                    if($FilePath -notlike "*_DEBUG.log"){
                        #region Initialize file on disk
                            $FileExists = Test-Path $FilePath
                            $Overwrite  = (-Not $AppendOnly)
                            $CreateFile = (-Not $FileExists)
                            if($FileExists){
                                # Overwrite or append any existing files with the same name
                                if($Overwrite){
                                    Remove-Item -Path $FilePath -Force | Out-Null
                                    $CreateFile = $true
                                }
                            } else {
                                # Create root folder if it doesn't already exist
                                $LogDir = (Split-Path $FilePath)
                                if(-Not (Test-Path $LogDir)){
                                    New-Item -ItemType Directory -Path $LogDir | Out-Null
                                }
                                $CreateFile = $true
                            }
                            if($CreateFile){
                                # Create the file on disk.
                                New-Item -ItemType File -Path $FilePath -Force | Out-Null
                            } else {
                                # Append a seperator to the file.
                                $SeperatorLines=@(
                                        ""
                                        "-------------------------------------"
                                        ""
                                    )
                                $SeperatorLines | %{
                                    $_ | Out-File $FilePath -Force -Append #| Out-Null
                                }
                            }
                            
                        #endregion
                    }
                    #region Add object to session list
                        # Add to session list
                        $LogObject=[PSCustomObject]@{
                            LogName           = $LogName
                            FilePath          = $FilePath
                            FileDirectory     = $LogDir
                            AppendBehavior    = $AppendOnly
                            OverwriteBehavior = (-Not $AppendOnly)
                        }
                        $script:GPLogSessions[$script:GPLogSessionID].LogList.Add($LogName, $LogObject)
                    #endregion
                    $Success = $true
                } catch {
                    $Success = $false
                    throw $_
                }
            }
            #return $Success
        }
        function Start-GPLog {
            <#
                .SYNOPSIS
                    Quick way to initialize a few common settings and keep a full log of any scheduled / unattended scripts.
                .DESCRIPTION
                    Quick way to initialize a few common settings and keep a full log of any scheduled / unattended scripts.
                    Including:
                        1) $DebugPreference
                        2) $VerbosePreference
                        3) Ouput location for rotating and / or appending transcript that includes redirected output.
                    (Meant to be used along with Stop-GPScript for environment settings reset & cleanup.)
                    Author       : Greg Phillips
                    Version      : 1.0.0
                    Version-Date : 2021.06.15
                .OUTPUTS
                    System.Boolean. Function returns $true if no errors occur, $false otherwise.
                .LINK 
                
                .EXAMPLE
                    PS C:\> Start-GPLog
                    This does nothing.  Don't do this.
                .EXAMPLE
                    PS C:\> Start-GPLog -EnableDebug
                    Shell display will include Debug messages.
                .EXAMPLE
                    PS C:\> Start-GPLog -LogLast "C:\ScriptLogs\LastScriptRun.log" -EnableDebug:$false -EnableVerbose
                    Outputs to rotating log file that will always maintain the log from the last script run. 
                    Shell display / log output will include Verbose messages, but not Debug messages, regardless of existing shell settings.
                .EXAMPLE
                    PS C:\> Start-GPLog -LogAll ("{0}\logtmp{1}\DailyScriptLog.log" -f $env:tmp, (Get-Date).ToString("yyyyMMdd")) `
                                        -LogLast ("{0}\logtmp{1}\ScriptRun_{2}.log" -f $env:tmp, (Get-Date).ToString("HHmmss"))
                    Creates a daily rotating log file, as well as single log file each run in a TMP folder.
                    Output file paths based on the example above would look something like this:
                        [LogAll]  C:\Users\temp\AppData\Local\Temp\logtmp20211026\DailyScriptLog.log
                        [LogLast] C:\Users\temp\AppData\Local\Temp\logtmp20211026\ScriptRun_220428.log
                    Shell display / log output will follow existing Debug / Verbose prefences.
            #>
            #[alias("Start-GPTranscript")]
            [CmdletBinding(DefaultParameterSetName='NoInput')]
            [OutputType([Boolean])]
            param(
                [Parameter(Mandatory=$false, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_All")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_Last")]
                [Parameter(Mandatory=$false, ParameterSetName="NoTranscript")]
                    [System.String] $LogOutputDirectory = $null,
                [Parameter(Mandatory=$false, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_All")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_Last")]
                [Parameter(Mandatory=$false, ParameterSetName="NoTranscript")]
                    [System.String] $LogFileNamePrefix = $null,
                [Parameter(Mandatory=$true, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$true, ParameterSetName="Transcript_All")]
                    [Switch] $LogAll,
                [Parameter(Mandatory=$true, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$true, ParameterSetName="Transcript_Last")]
                    [Switch] $LogLast,
                [Parameter(Mandatory=$false, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_All")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_Last")]
                [Parameter(Mandatory=$false, ParameterSetName="NoTranscript")]
                    [Switch] $EnableDebug,
                [Parameter(Mandatory=$false, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_All")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_Last")]
                [Parameter(Mandatory=$false, ParameterSetName="NoTranscript")]
                    [Switch] $EnableVerbose,
                [Parameter(Mandatory=$false, ParameterSetName="Transcript")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_All")]
                [Parameter(Mandatory=$false, ParameterSetName="Transcript_Last")]
                [Parameter(Mandatory=$false, ParameterSetName="NoTranscript")]
                    [Switch] $IncludeTranscript
            )
            if([String]::IsNullOrWhiteSpace($local:LogOutputDirectory) -or [String]::IsNullOrWhiteSpace($local:LogFileNamePrefix)){
                # Retrieve the root call from call stack to generate the default log directory
                $local:CallStack=@(Get-PSCallStack)
                $local:RootInvocation=$CallStack[($CallStack.Count - 1)]
                [String]$local:ScriptFullPath=$RootInvocation.InvocationInfo.MyCommand.Path
                Write-Host "ScriptPath: $local:ScriptFullPath"
                if([String]::IsNullOrWhiteSpace($local:LogFileNamePrefix)){
                    #$LogFileNamePrefix  = $RootInvocation.InvocationInfo.MyCommand.Name
                    $local:LogFileNamePrefix  = $(Split-Path $local:ScriptFullPath -Leaf)
                }
                if([String]::IsNullOrWhiteSpace($LogOutputDirectory)){
                    #$local:LogOutputDirectory = $(Split-Path $local:RootInvocation.ScriptName)
                    $local:LogOutputDirectory = $(Split-Path $local:ScriptFullPath)
                }
            }
            
            [Boolean]$Success       = $false
            #[String] $LogPath_DEBUG = $PSCommandPath.Replace(".psm1", "_DEBUG.log").Replace(".ps1", "_DEBUG.log")
            #[String] $LogPath_ALL   = $LogAll
            #[String] $LogPath_LAST  = $LogLast
            $ScriptFilePathPrefix=(Join-Path $LogOutputDirectory $LogFileNamePrefix)
            $ScriptFilePathPrefix=$ScriptFilePathPrefix.Substring(0, $ScriptFilePathPrefix.LastIndexOf("."))
            #$($ScriptFilePathPrefix.Substring(0, $ScriptName.IndexOf((".{0}" -f @($ScriptFilePathPrefix.Split(".") | Select -Last 1)[0]))))
            [String] $LogPath_DEBUG = "{0}_DEBUG.log" -f $ScriptFilePathPrefix
            [String] $LogPath_ALL   = "{0}.log" -f $ScriptFilePathPrefix
            [String] $LogPath_LAST  = "{0}_LAST.log" -f $ScriptFilePathPrefix

            #region Generate unique session identifier and add to session list
                if(-Not $script:GPLogSessionID){
                    New-Variable -Scope "Script" -Visibility $script:VariableVisibility -Name "GPLogSessionID" -Value $null
                }
                if(-Not $script:SessionIndex){
                    New-Variable -Scope "Script" -Visibility $script:VariableVisibility -Name "SessionIndex" -Value 1
                } else {
                    $script:SessionIndex += 1
                }
                #$script:SessionIndex = 1
                $script:GPLogSessions | 
                    Where-Object { $_.SessionID -like "$($script:ModuleIdentifier)*" } | 
                        Sort-Object SessionID -Desc |
                            Select-Object @{ Name="SessionIndex"; Expression={ [Int32]::Parse($_.SessionID.Split(":")[1]) + 1 }} -First 1 | 
                                ForEach-Object {
                                    $script:SessionIndex = $_.SessionIndex
                                }
                $script:GPLogSessionID = "{0}:{1}" -f $script:ModuleIdentifier, $($script:SessionIndex.ToString().PadLeft(3, "0"))
                Write-Host ("Log Session Identifier: {0}" -f $script:GPLogSessionID)
                Remove-Variable -Scope "Script" -Name "SessionIndex" | Out-Null 
                $SessionData=[PSCustomObject]@{
                    SessionID = $script:GPLogSessionID
                }
                $SessionData | Add-Member -MemberType NoteProperty -Name "LogList" -Value @{}
                $SessionData | Add-Member -MemberType NoteProperty -Name "DebugPrefs" -Value (
                    [PSCustomObject] @{
                        Init    = $global:DebugPreference
                        Session = if($EnableDebug)   { 'Continue' } else { $global:DebugPreference }
                    }
                )
                $SessionData | Add-Member -MemberType NoteProperty -Name "VerbosePrefs" -Value (
                    [PSCustomObject] @{
                        Init    = $global:VerbosePreference
                        Session = if($EnableVerbose) { 'Continue' } else { $global:VerbosePreference }
                    }
                )
                $script:GPLogSessions.Add( $script:GPLogSessionID, $SessionData )
            #endregion

            # Assume successful from this point on unless error is thrown
            $Success = $true

            try{
                # Set debug / verbose output settings according to EnableDebug / EnableVerbose flags
                $global:DebugPreference   = $SessionData.DebugPrefs.Session
                $global:VerbosePreference = $SessionData.VerbosePrefs.Session

                # Start transcript if any filepaths were specified
                if($IncludeTranscript){
                    try{
                        Add-GPLogToSession -LogName "GPLog_DEBUG" -FilePath $LogPath_DEBUG
                        try{
                            Stop-Transcript -WarningAction "SilentlyContinue"  -ErrorAction "SilentlyContinue" | Out-Null
                        }catch{
                            #New-GPLogMessage -Message $_ -LogMessageLevel Warning
                        }
                        Start-Transcript -Path $LogPath_DEBUG -Append:$false -Force:$true | Out-Null
                    } catch {
                        New-GPLogMessage -Message $_ -LogMessageLevel Error
                        $Success = $false
                    }
                }
                if($PSCmdlet.ParameterSetName -like "Transcript*"){
                    Add-GPLogToSession -LogName "GPLog_All"  -FilePath $LogPath_ALL  -AppendOnly
                    Add-GPLogToSession -LogName "GPLog_Last" -FilePath $LogPath_LAST
                } 
            } catch {
                New-GPLogMessage -Message $_ -LogMessageLevel Error
                $Success = $false
            }
            
            New-GPLogMessage -MessagePrefixAddition "" -Message " ************************"
            New-GPLogMessage -MessagePrefixAddition "" -Message " * # Process started. # "

            return $Success
        }
        function Stop-GPLog {
            #[alias("Stop-GPTranscript")]
            [CmdletBinding()]
            [OutputType([String[]])]
            param()

            $SessionData = $script:GPLogSessions[$script:GPLogSessionID]
            [String[]] $ReturnFileList = ($SessionData.LogList | Select-Object FilePath).FilePath

            # Set debug / verbose output settings back to original values
            $global:DebugPreference   = $SessionData.DebugPrefs.Init
            $global:VerbosePreference = $SessionData.VerbosePrefs.Init

            New-GPLogMessage -MessagePrefixAddition "" -Message " * # Process complete. # "
            New-GPLogMessage -MessagePrefixAddition "" -Message " ************************"
            

            if(@($script:GPLogSessions[$script:GPLogSessionID].LogList.Values | Where-Object { $_.LogName -eq "GPLog_DEBUG" }).Count -gt 0){
                # Close transcript (if in use)
                Stop-Transcript | Out-Null
            }

            
            $LogFileList = @($script:GPLogSessions[$script:GPLogSessionID].LogList.Values.FilePath)
            $ReturnFileList=$LogFileList -join ","
            
        
            # Remove session from session list and cleanup resources
            $script:GPLogSessions.Remove($script:GPLogSessionID)
            Remove-Variable -Scope "Script" -Name "GPLogSessionID" | Out-Null

            ## Remove unnecessary variables
            #Remove-Variable -Scope "Script" -Name "GPLog_All"  -ErrorAction "SilentlyContinue"      | Out-Null
            #Remove-Variable -Scope "Script" -Name "GPLog_Last" -ErrorAction "SilentlyContinue"      | Out-Null
            #Remove-Variable -Scope "Script" -Name "TranscriptStarted" -ErrorAction "SilentlyContinue"      | Out-Null
            #Remove-Variable -Scope "Script" -Name "DebugPreference_Init" -ErrorAction "SilentlyContinue"   | Out-Null
            #Remove-Variable -Scope "Script" -Name "VerbosePreference_Init" -ErrorAction "SilentlyContinue" | Out-Null
                    
            # End all other existing imported remote sessions
            Get-PSSession | Remove-PSSession

            # Initialize garbage collection
            [GC]::Collect()

            return $ReturnFileList
        }
    #endregion
#endregion

