#region Initialize module instance-specific variables

    # Generate id value unique to module import context
    #New-Variable -Scope Script -Visibility Private -Name "VariableVisibility" -Value "Private"
        New-Variable -Scope Script -Visibility Private -Name "VariableVisibility" -Value "Public"
    New-Variable -Scope Script -Visibility $script:VariableVisibility -Name "ModuleIdentifier" -Value $((New-Guid).Guid.Replace("-", ""))
    New-Variable -Scope Script -Visibility $script:VariableVisibility -Name "GPLogSessions" -Value @{}
    function LogSessionData{
        param(
            $SessionData = $(Get-DarkSessionInfo)
        )
        Write-Host "* --> Session info: $([Environment]::NewLine)"
        $($SessionData | ConvertTo-Json -Depth 4).Split([Environment]::NewLine) | %{
            if(-Not [String]::IsNullOrWhiteSpace($_)){
                Write-Host ("*       | {0}" -f $_)
            }
        }
    }
    # Remove when module is unloaded
    $ExecutionContext.SessionState.Module.OnRemove = {
        Write-Host "********************" -ForegroundColor White -BackgroundColor Red
        Write-Host "* MODULE UNLOADING" -ForegroundColor White -BackgroundColor Red
        #LogSessionData
        Write-Host "********************" -ForegroundColor White -BackgroundColor Red
        #Remove-Variable -Scope Script -Name "GPLogSessionID"
        Remove-Variable -Scope Script -Name "GPLogSessions"
        Remove-Variable -Scope Script -Name "ModuleIdentifier"
        Remove-Variable -Scope Script -Name "VariableVisibility"
    }
    
#endregion
#region GPoSh.Logging
    #region Logging / Output formatting
        enum DarkLogMessageLevel{
            Verbose = 0
            Debug = 1
            Information = 2
            Warning = 3
            Error = 4
        }
        enum DarkLogMessageType{
            Generic = 0
            Success = 1
            Failure = 2
        }
        function New-DarkLogMessage {
            [Alias("New-GPLogMessage")]
            [CmdletBinding()]
            param(
                [Object] $Message,
                [String] $MessagePrefix = $null,
                [Nullable[DarkLogMessageLevel]] $MessageLevel = $null,
                [Nullable[ConsoleColor]] $MessageColor = $null,
                [Nullable[DarkLogMessageType]] $MessageType = $null,
                [Switch] $ConsoleOnly
            )

            # Pull "Last Run" values (if they exist) in the event of a null settings param
            $SD=$script:GPLogSessions[$script:GPLogSessionID]
            $LC=$SD.LoggingContext
            $WriteBackParams=@{
                MessagePrefix = $LC.LastMessageParams.MessagePrefix
                MessageLevel = $LC.LastMessageParams.MessageLevel
                MessageColor = $LC.LastMessageParams.MessageColor
                MessageType = $LC.LastMessageParams.MessageType
                ConsoleOnly = $LC.LastMessageParams.ConsoleOnly
            }
            if(-Not $LC.FirstMessageReceived){
                $WriteBackParams["MessagePrefix"] = $SD.LoggingPrefs.DefaultLogMessagePrefixHeader
            }
            #if($LC.FirstMessageReceived){
                $WriteBackParams.Keys | %{
                    $Name=$_
                    $LastValue=$WriteBackParams[$_]
                    $CurrentValue=Get-Variable -Scope Local -Name $Name -ErrorAction SilentlyContinue
                    $UpdateParameter=$false
                    switch($CurrentValue.GetType().FullName){
                        ("System.String"){
                            if([String]::IsNullOrEmpty($CurrentValue)){
                                $UpdateParameter=$true
                            }
                        }
                        default{
                            if($null -eq $CurrentValue){
                                $UpdateParameter=$true
                            }
                        }
                    }
                    if($UpdateParameter){
                        Set-Variable -Scope Local -Name $Name -Value $LastValue -ErrorAction SilentlyContinue
                        $WriteBackParams.Remove($Name)
                    }
                }
            #}
            
            #region Set-up Output-Formatting Dictionaries and Defaults 
                #region Independent (Customizable) Values
                       [DarkLogMessageLevel] $DEFAULT_LogMessageLevel   = [DarkLogMessageLevel]::Information
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
                            ([DarkLogMessageLevel]::Verbose)     = "VERBOSE"
                            ([DarkLogMessageLevel]::Debug)       = "DEBUG"
                            ([DarkLogMessageLevel]::Information) = "INFO"
                            ([DarkLogMessageLevel]::Warning)     = "WARNING"
                            ([DarkLogMessageLevel]::Error)       = "ERROR"
                        }
                        $DICT_MessageAdditionalPrefixColors=@{
                            ([DarkLogMessageLevel]::Verbose)     = $DEFAULT_Color_Verbose
                            ([DarkLogMessageLevel]::Debug)       = $DEFAULT_Color_Debug
                            ([DarkLogMessageLevel]::Information) = $DEFAULT_Color
                            ([DarkLogMessageLevel]::Warning)     = $DEFAULT_Color
                            ([DarkLogMessageLevel]::Error)       = $DEFAULT_Color
                        }
                        $DICT_LogMessageLevelColors=@{
                            ([DarkLogMessageLevel]::Verbose)     = $DEFAULT_Color_Verbose
                            ([DarkLogMessageLevel]::Debug)       = $DEFAULT_Color_Debug
                            #([DarkLogMessageLevel]::Information) = $(if($null -ne $MessageColor) { $MessageColor } else { $DEFAULT_Color })
                            ([DarkLogMessageLevel]::Information) = $DEFAULT_Color_Information
                            ([DarkLogMessageLevel]::Warning)     = $DEFAULT_Color_Warning
                            ([DarkLogMessageLevel]::Error)       = $DEFAULT_Color_Error
                        }
                    #endregion
                    if($null -eq $MessageLevel){
                        switch($Message.GetType().ToString()){
                            ("System.Management.Automation.ErrorRecord"){ 
                                # Set $MessageLevel to [Error] if null 
                                <###############################################################################
                                    # The following must be true for this to happen:
                                    #   1) $MessageLevel param was not explicitly identified when the function was called
                                    #   2) $Message param IS of type [System.Management.Automation.ErrorRecord]
                                    ###############################################################################>
                                if($null -eq $MessageLevel) {
                                    $MessageLevel = [DarkLogMessageLevel]::Error
                                }
                            }
                            default{ # Set $MessageLevel equal to default value.
                                $MessageLevel = $DEFAULT_LogMessageLevel
                            }
                        }
                    }
                    [Nullable[ConsoleColor]] $LogMessageLevelColor      = $DICT_LogMessageLevelColors[$MessageLevel]
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
                    if($null -eq $MessageLevel) {
                        $MessageLevel = $DEFAULT_LogMessageLevel
                    }
                #endregion
                #region Decide whether or not to display the message
                    <###############################################################################
                        # All messages will be displayed without evaluation except for following message levels:
                        #   1) [DarkLogMessageLevel]::Debug
                        #   2) [DarkLogMessageLevel]::Verbose
                        # Below are the requirements necessary to display a message based on it's corresponding message level:
                        #   ----------------------------------------------------------------------------
                        #   | Message Level                  | Requirements to Display                 |
                        #   ----------------------------------------------------------------------------
                        #   | [DarkLogMessageLevel]::Debug       | $DebugPreference must equal "Continue"   |
                        #   | [DarkLogMessageLevel]::Verbose     | $VerbosePreference must equal "Continue" |
                        #   | [DarkLogMessageLevel]::Information | (n/a)                                    |
                        #   | [DarkLogMessageLevel]::Warning     | (n/a)                                    |
                        #   | [DarkLogMessageLevel]::Error       | (n/a)                                    |
                        #   -----------------------------------------------------------------------------
                        ###############################################################################>
                    switch($LogMessageLevel){
                        ([DarkLogMessageLevel]::Debug){
                            if($DebugPreference -eq "Continue"){
                                $DisplayMessage = $true
                            }
                        }
                        ([DarkLogMessageLevel]::Verbose){
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

                    # Only show a trailing "-" for the first line if one exists in the $MessagePrefix.
                    if($MessagePrefix.EndsWith("-") -and ($a -gt 0)){
                        $MessagePrefix = ("{0} " -f $MessagePrefix.TrimEnd("-"))
                    }

                    # Format and collect message elements in $MessageElements (order-specific hashtable)
                    $MessageElements=[Ordered]@{}
                    $MessageColor = if($null -ne $MessageColor) { $MessageColor } else { $LogMessageLevelColor }
                    $MessagePrefixTimestamp = "$((Get-Date).ToString('yyyy-MM-dd hh:mm:ss')) | "
                        $MessageElements.Add($MessagePrefixTimestamp, $DEFAULT_Color_Delim) 
                    $LogMessageLevelString = "$(('[{0}]' -f $DICT_LogMessageLevelStrings[$MessageLevel]).PadRight(9, ' '))"
                        $MessageElements.Add($LogMessageLevelString, $LogMessageLevelColor) 
                    $MessageElements.Add(" | ", $DEFAULT_Color_Delim) 
                    if($MessagePrefix) {
                        $MessageElements.Add($MessagePrefix, $DICT_MessageAdditionalPrefixColors[$MessageLevel])
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
                    if(-Not $ConsoleOnly){
                        # Add to $LogOutputMessageText
                        $LogOutputMessageLines += $MessageElements.Keys -join ""
                    }
                }

                if(-Not $ConsoleOnly){
                    # Output to log files (if in use)
                    $LogOutputMessageText = $LogOutputMessageLines -join [Environment]::NewLine
                    if($null -ne $script:GPLogSessionID){
                        $script:GPLogSessions[$script:GPLogSessionID].LogList.Values | Where-Object { $_.LogName -notin @("GPLog_DEBUG") } | ForEach-Object { 
                            #$LogOutputMessageText | Out-File $_.FilePath -Append:$($_.AppendBehavior) -Force
                            $LogOutputMessageText | Out-File $_.FilePath -Append:$true -Force
                        }
                    }
                }

                # Save "Last Run" settings back to session context
                #if($LC.FirstMessageReceived){
                    $LC.RecordLastMessageParams($WriteBackParams)
                #}
            }
        }
    #endregion
    #region Process alerts / notifications
        function Send-DarkAlert{
            #[alias()]
            [CmdletBinding()]
            #[OutputType()]
            param(
                [String] $SubjectAlertType = "Script Execution Status",
                [String] $SessionName,
                [String] $MailTo,
                [String] $MailToTest,
                [Switch] $ExcludeIPInfo,
                [Switch] $ExcludeHostname,
                [Switch] $TestMode
            )
            $local:DarkAlertBody=""
            #region Sub-functions
                <# [System.Object[]] = <ul>
                 # [HashTable]       = HTML Table
                 #>
                function New-MessageBodyElement{
                    param(
                        [Object]$Element
                    )
                    $ObjectType=$Element.GetType().FullName
                    $LineList=@()
                    switch($ObjectType){
                        ("System.Object[]"){
                            $LineList=$Element
                        }
                        default{
                            $LineList+=$Element.ToString()
                        }
                    }
                    if(-Not [String]::IsNullOrWhiteSpace($local:DarkAlertBody)){
                        $LineList | %{
                            $local:DarkAlertBody+=("{0}<br/>{1}" -f $local:DarkAlertBody.TrimEnd("<br/>").TrimEnd("<br />"), $Element)
                        }
                    }
                }
                function Add-MessageFooterElement{
                    param(
                        $Message
                    )
                    $MessageFooterElements+=$Message
                }
                function Add-MessageFooterElementProperty{
                    param(
                        $Name,
                        $Value
                    )
                    $Message = "  <tr>" + 
                               "    <td>{0}</td>" + 
                               "    <td>{1}</td>" + 
                               "  </tr>" -f $Name, $Value
                    Add-MessageFooterElement -Message $Message
                }
            #endregion
            
            $msgTo = if($TestMode) { $MailTo_Test } else { $MailTo }
            $msgSubject = ("[{0}] ({1} User Groups) Membership Changed" -f $SubjectAlertType, $AppSyncSettings.AppName)
            New-MessageBodyElement
            $msgBody  = "This alert is sent to inform you that one or more AD Users have been added or removed from the following AD groups:  " +
                $AppSyncSettings.ADSyncTargets.Keys | %{
                    $msgBody += " * [{$_}] <br />"
                }
            $msgBody += "The attached log file lists the corrective actions that have already been taken and is for your review only. <br /><br />" + 
                        "NO ACTION IS NECESSARY AT THIS TIME <br /><br />"
            #region Generate footer array
                $MessageFooterElements=@()
                if(
                    (-Not $ExcludeHostname) -and 
                    (-Not $ExcludeIPInfo)
                  ){
                    Add-MessageFooterElement -Message "[Report generated from a machine with the following properties]"
                    Add-MessageFooterElement -Message "<table>"
                    if(-Not $ExcludeHostname){
                        Add-MessageFooterElementProperty -Name "Hostname" -Value ($env:computername)
                    }
                    if(-Not $ExcludeIPInfo){
                        $senderPrivateIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" }).IPv4Address.IPAddress
                        $MessageFooterElements+=("Private IP" -f $senderPrivateIP)
           
                        $senderPublicIP = $(try{
                                Invoke-RestMethod https://ifconfig.me
                            } catch {
                                Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
                            })
                        $MessageFooterElements.Add("", $senderPrivateIP)
                    }
                    Add-MessageFooterElement -Message "</table>"
                }
                New-MessageBodyElement -Message $MessageFooterElements
            #endregion
          
            if($TestMode) {
                $msgSubject+=" **TEST MODE**"
            }
            Send-MailMessage -From $MailFrom -To $msgTo -Subject $msgSubject -Body $msgBody -Attachments $Log_Last -SmtpServer $SmtpServer -BodyAsHtml
        }
    #endregion
    #region Session Management
        function HandleException{
            #[Alias()]
            [CmdletBinding()]
            [OutputType([HashTable])]
            param(
                [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
                [ValidateNotNull()]
                    $ErrorObject,
                [Parameter(Mandatory=$false)]
                    [Switch]$ConsoleOnly
            )
            ($script:GPLogSessions[$script:GPLogSessionID]).RuntimeInfo.Errors+=$ErrorObject
            New-DarkLogMessage -Message $ErrorObject -MessageLevel Error -ConsoleOnly:$ConsoleOnly
        }
        #region Session information retrieval
            function Get-DarkSessionInfo{
                #[Alias()]
                [CmdletBinding()]
                [OutputType([HashTable])]
                 param(
                    [Parameter(Mandatory=$false)]
                        [String]$SessionIdentifier=$null
                )
                $SessionInfo=$null
                try{
                    if([String]::IsNullOrWhiteSpace($SessionIdentifier)){
                        $SessionIdentifier=$script:GPLogSessionID
                    }
                    if(-Not [String]::IsNullOrWhiteSpace($SessionIdentifier)){
                        if($null -ne $script:GPLogSessions) {
                            if($script:GPLogSessions.ContainsKey($SessionIdentifier)){
                                $SessionInfo=$script:GPLogSessions[$SessionIdentifier]
                            } else {
                                throw ("Could not find information object for session. [{0}]" -f $SessionIdentifier)
                            }
                        } else {
                            throw ("No log session information could be found. [{0}]" -f $SessionIdentifier)
                        }
                    } else {
                        throw ("No session identifier specified.")
                    }
                } catch {
                    $SessionInfo=$null
                    HandleException -ErrorObject $_ #-ConsoleOnly
                }
                return $SessionInfo
            }
            function Get-DarkSessionLog{
                #[Alias()]
                [CmdletBinding()]
                [OutputType([PSCustomObject])]
                param(
                    [Parameter(Mandatory=$false)]
                        [String]$SessionIdentifier=$null,
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                        [String]$LogName
                )
                $LogObject=$null
                try{
                    $LogList = (Get-DarkSessionInfo -SessionIdentifier $SessionIdentifier).LogList
                    if($null -ne $LogList){
                        if($LogList.ContainsKey($LogName)) {
                            $LogObject=$LogList[$LogName]
                        } else {
                            throw ("Could not find information object for session. {'SessionID':'{0}', 'LogName':'{1}'}" -f $SessionIdentifier, $LogName)
                        }
                    } else {
                        throw ("No session logs could be retrieved. {'SessionID':'{0}', 'LogName':'{1}'}" -f $SessionIdentifier, $LogName)
                    }
                } catch {
                    $LogObject=$null
                    throw $_
                }
                return $LogObject
            }
        #endregion
        function New-DarkSessionLog{
            [Alias("New-GPSessionLog", "Add-GPLogToSession")]
            [CmdletBinding()]
            #[OutputType([Boolean])]
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
                        #$script:GPLogSessions[$script:GPLogSessionID].LogList.Add($LogName, $LogObject)
                        (Get-DarkSessionInfo).LogList.Add($LogName, $LogObject)
                    #endregion
                    $Success = $true
                } catch {
                    $Success = $false
                    throw $_
                }
            }
            #return $Success
        }
            function New-DarkSessionID{
                # Generate unique session identifier and add to session list
                if(-Not $script:SessionIndex){
                    New-Variable -Scope "Script" -Visibility $script:VariableVisibility -Name "SessionIndex" -Value 1
                } else {
                    $script:SessionIndex += 1
                }
                $script:GPLogSessions | 
                    Where-Object { $_.SessionID -like "$($script:ModuleIdentifier)*" } | 
                        Sort-Object SessionID -Desc |
                            Select-Object @{ Name="SessionIndex"; Expression={ [Int32]::Parse($_.SessionID.Split(":")[1]) + 1 }} -First 1 | 
                                ForEach-Object {
                                    $script:SessionIndex = $_.SessionIndex
                                }
                $NewLogSessionID = "{0}:{1}" -f $script:ModuleIdentifier, $($script:SessionIndex.ToString().PadLeft(3, "0"))
                Remove-Variable -Scope "Script" -Name "SessionIndex" | Out-Null 
                return $NewLogSessionID
            }
            function Set-DarkSessionID{
                if(-Not $script:GPLogSessionID){
                    New-Variable -Scope "Script" -Visibility $script:VariableVisibility -Name "GPLogSessionID" -Value $null
                }
                $script:GPLogSessionID = New-DarkSessionID
                Write-Host ("Log Session Identifier: {0}" -f $script:GPLogSessionID)
                return $script:GPLogSessionID
            }
            function New-DarkSession{
                param(
                    [Parameter(Mandatory=$false, ParameterSetName="Default")]
                        [System.String] $LogOutputDirectory = $null,
                    [Parameter(Mandatory=$false, ParameterSetName="Default")]
                        [System.String] $LogFileNamePrefix = $null,
                    [Parameter(Mandatory=$false, ParameterSetName="Default")]
                        [Switch] $EnableDebug,
                    [Parameter(Mandatory=$false, ParameterSetName="Default")]
                        [Switch] $EnableVerbose
                )
                Set-DarkSessionID
                $local:CallStack=@(Get-PSCallStack)
                $SessionData=[PSCustomObject]@{
                    SessionID = $script:GPLogSessionID
                    Origin = ([PSCustomObject]@{
                        CallStack=$local:CallStack
                        RootInvocation=$CallStack[($CallStack.Count - 1)]
                    })
                    LogList = @{}
                    RuntimeInfo = ([PSCustomObject]@{
                        Started=$((Get-Date).ToString("yyyyMMdd-HHmmss"))
                        Errors = @()
                        Completed=$null
                    })
                    LoggingPrefs = ([PSCustomObject]@{
                        Debug = ([PSCustomObject]@{
                            Init    = $($global:DebugPreference)
                            Session = $(if($EnableDebug) { 'Continue' } else { $global:DebugPreference })
                        })
                        Verbose = ([PSCustomObject]@{
                            Init    = $($global:VerbosePreference)
                            Session = $(if($EnableVerbose) { 'Continue' } else { $global:VerbosePreference })
                        })
                        #----------------------------------------------
                        DefaultLogMessagePrefixDepth              = 0
                        #----------------------------------------------
                        DefaultLogMessagePrefixHeader             = "*"
                        DefaultLogMessagePrefixHeaderSpace        = "  "
                        #----------------------------------------------
                        DefaultLogMessagePrefixSubLevelHeader     = "-"
                        DefaultLogMessagePrefixSubLevelDelim      = "|"
                        DefaultLogMessagePrefixSubLevelTerminator = "\"
                        DefaultLogMessagePrefixSubLevelSpace      = "  "
                        #----------------------------------------------
                    })
                    LoggingContext = ([PSCustomObject]@{
                        SessionID = $script:GPLogSessionID
                        FirstMessageReceived = $false
                        LogMessagePrefixDepth=$SessionData.LoggingPrefs.DefaultLogMessagePrefixDepth
                        LogMessagePrefix=$SessionData.LoggingPrefs.DefaultLogMessagePrefixHeader
                        #LastLogMessagePrefixDepth=$SessionData.LoggingPrefs.DefaultLogMessagePrefixDepth
                        #LastLogMessagePrefix=$null
                        LastMessageParams=(
                            [PSCustomObject] @{
                                MessagePrefix = [String] $null
                                MessageLevel  = [Nullable[DarkLogMessageLevel]] $null
                                MessageType   = [Nullable[DarkLogMessageType]] $null
                                MessageColor  = [Nullable[ConsoleColor]] $null
                                ConsoleOnly   = [Nullable[Boolean]] $null
                            }
                        )
                    })
                }
                $SessionData.LoggingPrefs | Add-Member -MemberType NoteProperty -Name "LogFileNamePrefix" -Value $(
                    if([String]::IsNullOrWhiteSpace($local:LogFileNamePrefix)){
                        (Split-Path $($SessionData.Origin.RootInvocation.InvocationInfo.MyCommand.Path) -Leaf)
                    } else {
                        $local:LogFileNamePrefix
                    })
                $SessionData.LoggingPrefs | Add-Member -MemberType NoteProperty -Name "LogOutputDirectory" -Value $(
                    if([String]::IsNullOrWhiteSpace($local:LogOutputDirectory)){
                        (Split-Path $($SessionData.Origin.RootInvocation.InvocationInfo.MyCommand.Path))
                    } else {
                        $local:LogOutputDirectory
                    })
                $SessionData.LoggingContext | Add-Member -MemberType ScriptMethod -Name "SessionData" -Value {
                        param()
                        return $script:GPLogSessions[$this.SessionID]
                    }
                $SessionData.LoggingContext | Add-Member -MemberType ScriptMethod -Name "RecordLastMessageParams" -Value {
                        param(
                            [HashTable]$ParamList
                        )
                        $SessionData=$this.SessionData()
                        $ParamList.Keys | %{
                            $Name=$_
                            $Value=$ParamList[$_]
                            $SessionData.LoggingContext.LastMessageParams.PSObject.Properties[$Name].Value = $Value
                        }
                        $SessionData.LoggingContext.FirstMessageReceived -eq $true
                    }
                $SessionData.LoggingContext | Add-Member -MemberType ScriptMethod -Name "SetPrefixDepthString" -Value {
                        param(
                            [Switch]$EndOfSection
                        )
                        $SessionData=$this.SessionData()
                        switch($SessionData.LoggingContext.LogMessagePrefixDepth){
                            ( 0 ){
                                $SessionData.LoggingContext.LogMessagePrefix=$SessionData.LoggingPrefs.DefaultLogMessagePrefixHeader
                            }
                            default{
                                $SessionData.LoggingContext.LogMessagePrefix=$SessionData.LoggingPrefs.DefaultLogMessagePrefixHeaderSpace
                                for($a=1; $a -lt $SessionData.LoggingContext.LogMessagePrefixDepth; $a ++){
                                    $SessionData.LoggingContext.LogMessagePrefix+=(
                                        "{0}{1}" -f $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelDelim,
                                                    $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelSpace
                                    )
                                }
                                $SessionData.LoggingContext.LogMessagePrefix+=(
                                        "{0}{1}" -f $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelDelim,
                                                    $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelHeader
                                    )
                            }
                        }
                    }
                $SessionData.LoggingContext | Add-Member -MemberType ScriptMethod -Name "DecreasePrefixDepth" -Value {
                        param()
                        $SessionData=$this.SessionData()
                        if($SessionData.LoggingContext.LogMessagePrefixDepth -gt 0){
                            
                            # Fetch last message parameters
                            $Params=$SessionData.LoggingContext.LastMessageParams
                            $Params.Add("Message", "")
                            
                            # Terminate current section
                            $TrimmedPrefix=$Params["MessagePrefix"].TrimEnd(
                                "{0}{1}" -f $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelDelim,
                                            $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelHeader         
                            )
                            $SessionData.LoggingContext.LogMessagePrefix=("{0}{1}" -f $TrimmedPrefix, $SessionData.LoggingContext.DefaultLogMessagePrefixSubLevelTerminator)
                            $Params["MessagePrefix"]=$SessionData.LoggingContext.LogMessagePrefix
                            
                            # Log termination string message
                            New-DarkLogMessage @Params

                            # Decrease message prefix depth and calculate new message prefix string
                            $SessionData.LoggingContext.LogMessagePrefixDepth -= $SessionData.LoggingContext.LogMessagePrefixDepth
                            $SessionData.LoggingContext.SetPrefixDepthString()
                        }
                    }
                $SessionData.LoggingContext | Add-Member -MemberType ScriptMethod -Name "IncreasePrefixDepth" -Value {
                        param()
                        $SessionData=$this.SessionData()
                        $SessionData.LoggingContext.LogMessagePrefixDepth += 1
                        $SessionData.LoggingContext.SetPrefixDepthString()
                    }
                
                
                $script:GPLogSessions.Add( $script:GPLogSessionID, $SessionData )
                #$SessionData
                #LogSessionData -SessionData $SessionData
                return $SessionData
            }

        function Start-DarkSession {
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
            [alias("New-GPSession", "Start-GPLog")]
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

            #region Initialize variables
                # Set default values for null inputs
                <#
                if([String]::IsNullOrWhiteSpace($local:LogOutputDirectory) -or [String]::IsNullOrWhiteSpace($local:LogFileNamePrefix)){
                    # Retrieve the root call from call stack to generate the default log directory
                    $local:CallStack=@(Get-PSCallStack)
                    $local:RootInvocation=$CallStack[($CallStack.Count - 1)]
                    [String]$local:ScriptFullPath=$RootInvocation.InvocationInfo.MyCommand.Path
                    if([String]::IsNullOrWhiteSpace($local:LogFileNamePrefix)){
                        #$LogFileNamePrefix  = $RootInvocation.InvocationInfo.MyCommand.Name
                        $local:LogFileNamePrefix  = $(Split-Path $local:ScriptFullPath -Leaf)
                    }
                    if([String]::IsNullOrWhiteSpace($LogOutputDirectory)){
                        #$local:LogOutputDirectory = $(Split-Path $local:RootInvocation.ScriptName)
                        $local:LogOutputDirectory = $(Split-Path $local:ScriptFullPath)
                    }
                }
                #>
                
            #endregion

            #region Generate unique session identifier and add to session list
                $SD=New-DarkSession -LogOutputDirectory $local:LogOutputDirectory -LogFileNamePrefix $local:LogFileNamePrefix -EnableDebug:$EnableDebug -EnableVerbose:$EnableVerbose
                # Create new variables and initialize values
                [Boolean]$Success              = $false
                [String] $ScriptFilePathPrefix = (Join-Path $SD.LoggingPrefs.LogOutputDirectory $SD.LoggingPrefs.LogFileNamePrefix)
                    $ScriptFilePathPrefix=$ScriptFilePathPrefix.Substring(0, $ScriptFilePathPrefix.LastIndexOf("."))
                [String] $LogPath_DEBUG        = "{0}_DEBUG.log" -f $ScriptFilePathPrefix
                [String] $LogPath_ALL          = "{0}.log"       -f $ScriptFilePathPrefix
                [String] $LogPath_LAST         = "{0}_LAST.log"  -f $ScriptFilePathPrefix
            #endregion

            # Assume successful from this point on unless error is thrown
            $Success = $true

            try{
                # Set debug / verbose output settings according to EnableDebug / EnableVerbose flags
                $global:DebugPreference   = $SD.LoggingPrefs.Debug.Session
                $global:VerbosePreference = $SD.LoggingPrefs.Verbose.Session

                # Start transcript if any filepaths were specified
                if($IncludeTranscript){
                    try{
                        New-DarkSessionLog -LogName "GPLog_DEBUG" -FilePath $LogPath_DEBUG
                        # Attempt to stop any transcripts already running.
                        try{
                            Stop-Transcript -InformationAction "SilentlyContinue" -WarningAction "SilentlyContinue"  -ErrorAction "SilentlyContinue" | Out-Null
                        } catch {
                            # DO NOTHING
                        }
                        # Start the transcript
                        Start-Transcript -Path $LogPath_DEBUG -Append:$false -Force:$true | Out-Null
                    } catch {
                        HandleException -ErrorObject $_ #-ConsoleOnly
                        $Success = $false
                    }
                }
                if($PSCmdlet.ParameterSetName -like "Transcript*"){
                    New-DarkSessionLog -LogName "GPLog_All"  -FilePath $LogPath_ALL  -AppendOnly
                    New-DarkSessionLog -LogName "GPLog_Last" -FilePath $LogPath_LAST
                } 
            } catch {
                HandleException -ErrorObject $_ #-ConsoleOnly
                $Success = $false
            }
            
            New-DarkLogMessage -MessagePrefix "" -Message " ************************"
            New-DarkLogMessage -MessagePrefix "" -Message " * # Process started. # "

            return $Success
        }
        function Stop-DarkSession {
            [alias("Stop-GPLog")]
            [CmdletBinding()]
            [OutputType([String[]])]
            param()

            $SessionData = $script:GPLogSessions[$script:GPLogSessionID]
            #$SessionData = (Get-DarkSessionInfo)
            [String[]] $ReturnFileList = ($SessionData.LogList | Select-Object FilePath).FilePath

            # Set debug / verbose output settings back to original values
            $global:DebugPreference   = $SessionData.LoggingPrefs.Debug.Init
            $global:VerbosePreference = $SessionData.LoggingPrefs.Verbose.Init

            New-DarkLogMessage -MessagePrefix "" -Message " * # Process complete. # "
            New-DarkLogMessage -MessagePrefix "" -Message " ************************"
            
            #if(@((Get-DarkSessionLog -LogName "GPLog_DEBUG")).Count -gt 0){
            if(@($SessionData.LogList.Values | Where-Object { $_.LogName -eq "GPLog_DEBUG" }).Count -gt 0){
                # Close transcript (if in use)
                Stop-Transcript | Out-Null
            }

            $LogFileList = @($script:GPLogSessions[$script:GPLogSessionID].LogList.Values.FilePath)
            $ReturnFileList=$LogFileList -join ","
            
            # Remove session from session list and cleanup resources
                $global:LAST_SESSION_DATA=$SessionData
            $script:GPLogSessions.Remove($script:GPLogSessionID)
            Remove-Variable -Scope "Script" -Name "GPLogSessionID" | Out-Null
                    
            # End all other existing imported remote sessions
            Get-PSSession | Remove-PSSession

            # Initialize garbage collection
            [GC]::Collect()

            return $ReturnFileList
        }
    #endregion
#endregion

