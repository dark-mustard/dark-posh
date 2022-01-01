# DarkPoSh.Imports
#region Custom Functions
    #region Local Module Management
        #region Context Variable Management
            function Get-DarkModuleContextVariableName{
                $Return = $null

                #$CallStack = @(Get-PSCallStack)
                #$Return = $CallStack[$CallStack.Count - 1].InvocationInfo.MyCommand.Path
        
                #$FileInfo = Get-Item $PSCommandPath
                #$ScriptBaseName = $FileInfo.BaseName

                $ScriptBaseName = Split-Path $PSCommandPath -Leaf
                $ScriptBaseName = $ScriptBaseName.Substring(0, $ScriptBaseName.LastIndexOf(".ps")).Replace(".", "_")
                $ContextVariableName = "{0}_Context" -f $ScriptBaseName

                $Return = $ContextVariableName

                return $Return
            }
            function Get-DarkModuleContext{
                param(
                    [Switch]$Initialize
                )
                $Return = $null
        
                $ContextVariableName = Get-DarkModuleContextVariableName

                $Return = Get-Variable -Scope Script -Name $ContextVariableName -ErrorAction SilentlyContinue
                if(($Initialize) -or ($null -eq $Return)){
                    Set-Variable -Scope Script -Visibility Private -Name $ContextVariableName -Value ([PSCustomObject]@{
                        RunTime = [PSCustomObject]@{
                            ID        = $((New-Guid).Guid)
                            StartTime = $(Get-Date)
                            EndTime   = $null
                            Errors    = @()
                        }
                        ServerRoleDict=@{
                            "AzureADConnect"="ETSYNC01"
                        }
                    })
                    $Return = Get-Variable -Scope Script -Name $ContextVariableName -ErrorAction SilentlyContinue
                }

                if($Return.Count -ne 0){
                    $Return = $Return[0].Value
                } else {
                    $Return = $null
                }
        
                return $Return
            }
            function Remove-ScriptContext{
                $Return = $null
        
                $ContextVariableName = Get-DarkModuleContextVariableName

                Remove-Variable -Scope Script -Name $ContextVariableName -ErrorAction SilentlyContinue
                
                return $Return
            }
        #endregion
        function Initialize-DarkModule{
            #region Create script variables
                $ScriptContext = Get-DarkModuleContext -Initialize
            #endregion
        }
        function Dispose-DarkModule{
            $ScriptContext = Get-DarkModuleContext

        }
        function Handle-Exception{
            param(
                $Exception
            )
            (Get-DarkModuleContext).RunTime.Errors+=,$Exception
            Write-Error -Message $Exception
        }
    #endregion
    #region Module Management
        enum PSModulePackageManagers {
            Nuget
        }
        function Import-DarkModule {
            <#
            .SYNOPSIS
        
            .DESCRIPTION
        
            .OUTPUTS
        
            .LINK 
        
            .EXAMPLE
                PS C:\>
        
            .EXAMPLE
                PS C:\>
        
            .EXAMPLE
                PS C:\>
        
            .EXAMPLE
                PS C:\>
        
            #>
            param(
                [String] $ModuleName,
                [String] $PackageManager=$null,
                [String] $PackageManagerVersion=$null,
                [Switch] $UpdateModule
            )
            # Import PS module if not already present
            if((Get-DarkModule -Name $ModuleName).Count -eq 0) {
                # Install PS module if not already present
                #if((Get-DarkModule -Name $ModuleName -ListAvailable).Count -eq 0) {
                if((Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue).Count -eq 0) {
                    #----
                    # Ensure TLS protocol is set to 1.2
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    #----
                    # Verify PowerShellGet installation
                    #try{
                    #    Update-DarkModule PowerShellGet -Force | Out-Null
                    ##} catch {
                    #    Install-DarkModule PowerShellGet -Force | Out-Null
                    #}
                    #----
                    # Verify PackageManager (if specified)
                    if($PackageManager) {
                        switch($PackageManager.ToLower()){
                            ("powershellget"){
                                $PMInstance=Find-DarkModule $PackageManager
                                if(($null -ne $PMInstance)){
                                    if(($null -eq $PackageManagerVersion) -or ($PMInstance.Version -lt $PackageManagerVersion)){
                                        try{
                                            Update-DarkModule $PackageManager -Force | Out-Null
                                        } catch {
                                            if($_.Message -like "*was not installed by using Install-DarkModule, so it cannot be updated.*"){
                                                Install-DarkModule -Name $PackageManager -Force -AllowClobber | Out-Null
                                            }
                                        }
                                    }
                                
                                }
                            }
                            default{
                                # Install dependent package manager if not already present
                                if($PackageManagerVersion) {
                                    if((Get-PackageProvider -ListAvailable | Where { $_.Version -ge $PackageManagerVersion }).Name -notcontains $PackageManager){
                                        Install-PackageProvider -Name $PackageManager -MinimumVersion $PackageManagerVersion -Force | Out-Null
                                    }
                                } else {
                                    if((Get-PackageProvider -ListAvailable).Name -notcontains $PackageManager){ 
                                        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                                        Install-PackageProvider -Name $PackageManager -Force | Out-Null
                                    }
                                }
                            }
                        }
                    }
                    #----
                    # Install the module
                    Install-DarkModule -Name $ModuleName -Force | Out-Null
                } elseif($UpdateModule){ 
                    Update-DarkModule $ModuleName -Force | Out-Null
                }
                Import-DarkModule -Name $ModuleName | Out-Null
            }
        }
    #endregion
    #region Environment Connectivity
        #region On-Prem / AD / etc
            #region AD
                function Test-DarkADCredential {
                    [CmdletBinding()]
                    [OutputType([String])] 
                    param ( 
                        [Parameter( 
                            Mandatory = $false, 
                            ValueFromPipeLine = $true, 
                            ValueFromPipelineByPropertyName = $true
                        )] 
                        [Alias( 
                            'PSCredential'
                        )] 
                        [ValidateNotNull()] 
                        [System.Management.Automation.PSCredential]
                        [System.Management.Automation.Credential()] 
                        $Credentials
                    )
                    $UserIsAuthorized=$false
                    $Continue=$true
                    $Domain = $null
                    $Root = $null
                    $Username = $null
                    $Password = $null

                    # NUGET REPO: Register-PackageSource -provider NuGet -name nugetRepository -location https://www.nuget.org/api/v2
      
                    if($null -eq $Credentials){
                        try {
                            $Credentials = Get-Credential "domain\$env:username" -ErrorAction Stop
                        } catch {
                            Write-Warning "!WARNING! Failed to retrieve credentials: $($_.Exception.Message)"
                            $Continue=$false
                        }
                    }
                    if($Continue){
                        # Checking module
                        try {
                            # Split username and password
                            $Username = $credentials.username
                            $Password = $credentials.GetNetworkCredential().password
  
                            # Get Domain
                            $Root = "LDAP://" + ([ADSI]'').distinguishedName
                            $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
                        } catch {
                            Write-Error "!ERROR! Could not validate credentials: $($_.Exception.Message)"
                            $Continue=$false
                        }
  
                        if($Continue -and ($null -ne $Domain) -and (-Not [String]::IsNullOrEmpty($Domain.Name))) {
                            $UserIsAuthorized=$true
                        }
                    }

                    if($UserIsAuthorized){
                        Write-Debug "User authorized successfully. [$($Username)]"
                    } else {
                        if(-Not [String]::IsNullOrEmpty($Username)){
                            Write-Debug "!ERROR! Unauthorized username or password. [$($Username)]"
                        } else {
                            Write-Debug "!ERROR! No credentials provided."
                        }
                    }
                
                    return $UserIsAuthorized
                }
                function DarkImport-AD {
                    [alias("DarkConnect-AD")]
                    [CmdletBinding(DefaultParameterSetName='NoInput')]
                    param(
                        [Parameter(Mandatory=$false, ValueFromPipeline=$false)] 
                            [String]$DC = $null,
                        [Parameter(ParameterSetName="CredsFromUsername", Mandatory=$true)] 
                            [String]$Username = $null, 
                        [Parameter(ParameterSetName="CredsFromObject", Mandatory=$true)] 
                            [PSCredential]$Credentials = $null
                    )
                
                    $ImportSucceeded=$false

                    #region Sub-Functions
                        function Connect-DC{
                            param(
                                [Parameter(Mandatory=$true)] 
                                    [String] $DC,
                                [Parameter(Mandatory=$false)] 
                                    [PSCredential]$Creds = $null
                            )
                            $Success = $false
                            # Make sure server is online / reachable
                            if(Test-Connection -ComputerName $DC -Count 4 -Quiet){
                                if(-Not $Creds){
                                    #--> No credential information provided
                                    if($script:ETPSESSION_ActiveDirectory){
                                        #--> Set value to cached credentials
                                        $Creds = $script:ETPSESSION_ActiveDirectory
                                    } else {
                                        #--> Try with current user context
                                        ($script:ETPSESSION_ActiveDirectory=New-PSSession -ComputerName $DC -ErrorAction SilentlyContinue) | Out-Null
                                        if((-Not $script:ETPSESSION_ActiveDirectory) -or ($script:ETPSESSION_ActiveDirectory.State -eq "Closed")){
                                            # If session credentials fail - prompt for credentials and save them to script var
                                            $Creds=Get-Credential -UserName "$(($env:USERDOMAIN).ToLower())\" -Message "Please supply credentials for AD Access"
                                        }
                                    }
                                
                                } 
                            
                                #if((-Not $Creds) -and ((-Not $script:ETPSESSION_ActiveDirectory) -or ($script:ETPSESSION_ActiveDirectory.State -eq "Closed"))){
                                #    # If session credentials fail - prompt for credentials and save them to script var
                                #    $Creds=Get-Credential -UserName "$(($env:USERDOMAIN).ToLower())\" -Message "Please supply credentials for AD Access"
                                #}
                            
                                if(((-Not $script:ETPSESSION_ActiveDirectory) -or ($script:ETPSESSION_ActiveDirectory.State -eq "Closed")) -and ($Creds)) {
                                    #--> [Creds] has value - connection not yet established: attempt with [Creds]
                                    ($script:ETPSESSION_ActiveDirectory=New-PSSession -ComputerName $DC -Credential $($Creds) -ErrorAction SilentlyContinue) | Out-Null
                                } 

                                if((-Not $script:ETPSESSION_ActiveDirectory) -or ($script:ETPSESSION_ActiveDirectory.State -eq "Closed")){
                                    #--> Bad credentials.  Throw exception
                                    throw "!ERROR! No valid credentials provided for access."
                                } else {
                                    #--> Session authenticated: Import
                                    Invoke-Command -Session $script:ETPSESSION_ActiveDirectory {
                                        Import-DarkModule ActiveDirectory
                                        Import-DarkModule GroupPolicy
                                    }
                                    ($script:ETPMODULE_ActiveDirectory=Import-PSSession $script:ETPSESSION_ActiveDirectory -DarkModule ActiveDirectory,GroupPolicy -AllowClobber -ErrorAction SilentlyContinue) | Out-Null
                                    if($script:ETPMODULE_ActiveDirectory){
                                        #--> Cache credentials to script variable
                                        $script:ETPVARP_LocalDomainCredentials=$Creds
                                        #--> Set [Success] = $true
                                        $Success=$true
                                    } else {
                                        $script:ETPSESSION_ActiveDirectory = $null
                                        throw "!ERROR! Session could not be imported."
                                    }
                                }
                            } 
                            return $Success
                        }
                    #endregion

                    if(-Not $script:ETPMODULE_ActiveDirectory) {
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        $Creds=$null
                        if($Username){
                            if($script:ETPVARP_LocalDomainCredentials){
                                # IF username does not match any cached creds - THEN...
                                if($script:ETPVARP_LocalDomainCredentials.Username -ne $Username){
                                    # ...delete the cached creds
                                    $script:ETPVARP_LocalDomainCredentials=$null
                                } else {
                                    #...set to cached credentials
                                    $Creds = $script:ETPVARP_LocalDomainCredentials
                                }
                            } 
                            if(-Not $Creds) {
                                #...prompt for password 
                                $Creds=Get-Credential -UserName $Username -Message "Please supply credentials for AD Access"
                            }
                        
                        } elseif($Credentials){
                            if($script:ETPVARP_LocalDomainCredentials){
                                # IF username does not match any cached creds - THEN...
                                if($script:ETPVARP_LocalDomainCredentials.Username -ne $Credentials.UserName){
                                    # ...delete the cached creds
                                    $script:ETPVARP_LocalDomainCredentials=$null
                                } else {
                                    #...set to cached credentials
                                    $Creds = $script:ETPVARP_LocalDomainCredentials
                                }
                            } 
                            if(-Not $Creds) {
                                #...set to [Credentials]
                                $Creds = $Credentials
                            }
                        } elseif($script:ETPVARP_LocalDomainCredentials) {
                            #...set to cached credentials
                            $Creds = $script:ETPVARP_LocalDomainCredentials
                        }
                        if(-Not $DC){
                            $FullDCList = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain().DomainControllers | Select Name).Name
                            $StopEnumeration=$false
                            ForEach($DC in $FullDCList){
                                if((-Not $ImportSucceeded) -and (-Not $StopEnumeration)) {
                                    $ImportSucceeded = Connect-DC -DC $DC -Creds $Creds
                                }
                            }
                        } else {
                            $ImportSucceeded = Connect-DC -DC $DC -Creds $Creds
                        }
                        if(($ImportSucceeded) -and ($Creds)){
                            $script:ETPVARP_LocalDomainCredentials = $Creds
                        }
                    } else {
                        $ImportSucceeded=$true
                    }
                    return $ImportSucceeded
                }
                function DarkRemove-AD {
                    [alias("DarkDisconnect-AD")]
                    param( )
                    Remove-DarkModule $script:ETPMODULE_ActiveDirectory
                        $script:ETPMODULE_ActiveDirectory = $null
                    Remove-PSSession $script:ETPSESSION_ActiveDirectory
                        $script:ETPSESSION_ActiveDirectory = $null
                    $script:ETPVARP_LocalDomainCredentials = $null
                }
                function DarkSync-AD {
                    param(
                    
                    )
                    if(-Not ($Session)){
                        $Session=$script:ETPSESSION_ActiveDirectory
                    }
                    if(-Not ($Session)){
                        if(DarkImport-AD){
                            $Session=$script:ETPSESSION_ActiveDirectory
                        }
                    }
                    if($Session){
                        Invoke-Command -Session $Session -ScriptBlock {
                            repadmin /syncall /AdeP
                        }
                    }
                }
            #endregion
            #region Exchange
            <#
                function Connect-Exchange{
                        param(
                            [String][ValidateNotNull()]$DMInit,
                            [String][ValidateNotNull()]$DMInc,
                            [String][ValidateNotNull()]$ExchangeHost="etex01.Dark-PoSh.local",
                            [switch]$DevMode
                        )
                        $script:ETPSESSION_Exchange=$null
                        if($DevMode) {
                            Write-Host "$($DMInit)<Connect-Exchange>" -ForegroundColor Gray
                        }

                        $AbortConnection=$false
                        # Make sure server is online / reachable
                        if(Test-Connection -ComputerName $ExchangeHost -Count 4 -Quiet){
                            if(-Not $script:ETPVARP_LocalDomainCredentials) {
                                # Try session credentials first
                                ($script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeHost/PowerShell/ -Authentication Kerberos -ErrorAction SilentlyContinue) | Out-Null
                                if(-Not $script:ETPSESSION_Exchange){
                                    # If session credentials fail - prompt for credentials and save them to script var
                                    if($DevMode) {
                                        Write-LogMessage -Message "$($DMInit)$($DMInc)$($DMInc)$($DMInc)<Warning>Local session credentials refused.</Warning>" -Format ([LogMessageFormat]::DevModeWarning)
                                    }
                                    if(-Not (Get-LocalDomainCredentials)) {
                                        $AbortConnection=$true
                                    }
                                }
                            }
                            # Connect using provided credentials if provided and not already connected
                            if((-Not $AbortConnection) -and 
                                (-Not $script:ETPSESSION_Exchange) -and
                                ($script:ETPVARP_LocalDomainCredentials)) {
                                ($script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeHost/PowerShell/ -Authentication Basic -AllowRedirection -Credential $($script:ETPVARP_LocalDomainCredentials) -ErrorAction SilentlyContinue) | Out-Null
                                if(-Not $script:ETPSESSION_Exchange){
                                    if($DevMode) {
                                        Write-LogMessage -Message "$($DMInit)$($DMInc)$($DMInc)$($DMInc)<Warning>Specified credentials refused.</Warning>" -Format ([LogMessageFormat]::DevModeWarning)
                                    }
                                    $AbortConnection=$true
                                }
                            } 
                            if((-Not $AbortConnection) -and ($script:ETPSESSION_Exchange)){
                                (Import-PSSession $script:ETPSESSION_Exchange -DisableNameChecking -ErrorAction SilentlyContinue) | Out-Null
                                if($DevMode) {
                                    Write-LogMessage -Message "$($DMInit)$($DMInc)$($DMInc)$($DMInc)<Success>Session connected successfully!</Success>" -Format ([LogMessageFormat]::DevModeSuccess)
                                }
                            } else  {
                                if($DevMode) {
                                    Write-LogMessage -Message "$($DMInit)$($DMInc)$($DMInc)$($DMInc)<Error>Unable to establish secure session to host.</Error>" -Format ([LogMessageFormat]::DevModeError)
                                }
                            }
                        } else {
                            if($DevMode) {
                                Write-LogMessage -Message "$($DMInit)$($DMInc)$($DMInc)$($DMInc)<Warning>Host offline or unreachable.</Warning>" -Format ([LogMessageFormat]::DevModeWarning)
                            }
                        }

                        #throw [PSNotImplementedException] "!THIS HAS NOT YET BEEN CONFIGURED!"
                        #
                        #    $UserCredential = Get-Credential
                        #    (
                        #        # Try kerberos if the $ExchangeHost is the fully qualified name of the AD object (ex. server.domain.local)
                        #        script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeHost/PowerShell/ -Authentication Kerberos
                        #        Import-PSSession $script:ETPSESSION_Exchange -DisableNameChecking
                        #        #------ EXAMPLE ------#
                        #        $ExchangeHost="etex01.Dark-PoSh.local"
                        #        $script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeHost/PowerShell/ -Authentication Kerberos
                        #        #Connect-PSSession -Session ($script:ETPSESSION_Exchange) -Name ETPSession_Exchange 
                        #        Connect-PSSession -Session ($script:ETPSESSION_Exchange)
                        #        #---------------
                        #        Get-PSSession | Disconnect-PSSession
                        #        Get-PSSession | Remove-PSSession
                        #        #---------------
                        #        Get-PSSession | FL *
                        #        #    State                  : Opened
                        #        #    IdleTimeout            : 900000
                        #        #    OutputBufferingMode    : None
                        #        #    DisconnectedOn         : 
                        #        #    ExpiresOn              : 
                        #        #    ComputerType           : RemoteMachine
                        #        #    ComputerName           : etex01.Dark-PoSh.local
                        #        #    ContainerId            : 
                        #        #    VMName                 : 
                        #        #    VMId                   : 
                        #        #    ConfigurationName      : Microsoft.Exchange
                        #        #    InstanceId             : 6ecad3bb-478e-478b-9409-c8af9de0f35b
                        #        #    Id                     : 5
                        #        #    Name                   : WinRM5
                        #        #    Availability           : Available
                        #        #    ApplicationPrivateData : {SupportedVersions, ImplicitRemoting, PSVersionTable}
                        #        #    Runspace               : System.Management.Automation.RemoteRunspace
                        #    )
                        #    # Try basic if the $ExchangeHost is an external uri not known by AD (ex. mail.domain.com)
                        #    New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeHost/PowerShell/ -Credential ($script:ETPVARP_LocalDomainCredentials) -Authentication Basic -AllowRedirection
                        #    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://$ExchangeHost/PowerShell/ -Credential ($script:ETPVARP_LocalDomainCredentials) $UserCredential -Authentication Basic -AllowRedirection
                        #    Import-PSSession $Session
                        #
                    
                        if($DevMode) {
                            if(-Not $script:ETPSESSION_Exchange) {
                                Write-Host "$($DMInit)$($DMInc)<Error>Unable to establish a secure session to Exchange.</Error>" -ForegroundColor DarkRed
                            }
                            Write-Host "$($DMInit)</Connect-Exchange>" -ForegroundColor Gray
                        }
                    }
                    #>
                function DarkImport-Exchange {
                    [alias("DarkConnect-Exchange")]
                    param(
                        [String]$ServerFQDN = $null,
                        [String]$Username = $null
                    )
                    $ImportSucceeded=$false
                    if(-Not $script:ETPMODULE_Exchange) {
                        Write-Debug "[ServerFQDN] $(if(-Not [String]::IsNullOrEmpty($ServerFQDN)){ $ServerFQDN })"
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        $Creds=$null

                        # IF a username is supplied, THEN prompt for password  (regardless of current user session)
                        if($Username){
                            # IF username does not match any cached creds - THEN...
                            if(($script:ETPVARP_LocalDomainCredentials) -and ($script:ETPVARP_LocalDomainCredentials.Username -ne $Username)){
                                # ...delete the cached creds
                                $script:ETPVARP_LocalDomainCredentials=$null
                            }
                            #...prompt for password 
                            #$Creds=Get-Credential -UserName "$(($env:USERDOMAIN).ToLower())\$Username" -Message "Please supply credentials for AD Access"
                            $Creds=Get-Credential -UserName "$Username" -Message "Please supply credentials for AD Access"
                        } elseif($script:ETPVARP_LocalDomainCredentials) {
                            $Creds=$script:ETPVARP_LocalDomainCredentials
                        }

                        #--> Make sure server is online / reachable
                        if(Test-NetConnection -ComputerName $ServerFQDN -Port 443 -InformationLevel Quiet) {
                            #--> Ensure Authorized Access available
                            # IF the credentials have not been set yet (by providing a username value) - THEN...
                            if(-Not $Creds) {
                                # ...try connecting with session credentials
                                #     -Reference on -Authentication: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.authenticationmechanism?view=powershellsdk-7.0.0#fields
                                #($script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerFQDN/PowerShell/" -Authentication Kerberos -ErrorAction SilentlyContinue) | Out-Null
                                ($script:ETPSESSION_Exchange=New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerFQDN/PowerShell/" -Authentication Kerberos -ErrorAction SilentlyContinue) | Out-Null
                                # IF session credentials fail - THEN...
                                if(-Not $script:ETPSESSION_Exchange){
                                    # ...prompt for credentials and save to script var
                                    $Creds=Get-Credential -UserName "$(($env:USERDOMAIN).ToLower())\" -Message "Please supply credentials for Exchange Access"
                                    # TODO: SAVE TO SCRIPT VARIABLE
                                }
                            }
                            # Connect using provided credentials if provided and not already connected
                            if((-Not $script:ETPSESSION_Exchange) -and ($Creds)) {
                                # IF script variable doesn't already exist with cached creds / OR cached creds have different username - save now
                                if((-Not $script:ETPVARP_LocalDomainCredentials) -or ($script:ETPVARP_LocalDomainCredentials.UserName -ne $Username)) {
                                    # prompt for credentials and save them to script var
                                    $script:ETPVARP_LocalDomainCredentials = $Creds
                                }
                                #...save session to script var for future use
                                $script:ETPSESSION_Exchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ServerFQDN/PowerShell/" -Authentication Kerberos -Credential $($script:ETPVARP_LocalDomainCredentials) 
                                #$script:ETPSESSION_Exchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://$ServerFQDN/PowerShell/" -Authentication Digest -AllowRedirection -Credential $($script:ETPVARP_LocalDomainCredentials)  -
                                #--> *** DO NOT USE *** This works for any resolvable name - not secure at ALL though...
                                #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ExchangeHost/powershell/" -Credential $UserCredential -Authentication Basic -AllowRedirection
                            } 
                            if(($script:ETPSESSION_Exchange)){
                                (Import-PSSession $script:ETPSESSION_Exchange -DisableNameChecking -ErrorAction SilentlyContinue) | Out-Null
                                if($script:ETPMODULE_Exchange){
                                    # ToDo: Set $script:ETPSESSION_Exchange to $null?
                                    $ImportSucceeded=$true
                                }
                            }
                        } 
                    }
                    return $ImportSucceeded
                }
            #endregion
        #endregion
        #region Cloud service MGMT
            #region Duo
                function DarkImport-Duo {
                    [alias("DarkConnect-Duo")]
                    param( 
                        [String]$RequiredVersion="1.0.0.3"
                    )
                    $Success=$false
                    if((Get-DarkModule Duo).Count -eq 0){
                        Import-DarkModule Duo -RequiredVersion $RequiredVersion
                    }
                    if($null -ne $(try{ duoGetInfo -info summary -ErrorAction SilentlyContinue } catch { $null })){
                        $Success=$true
                    }
                    return $Success
                }
                function DarkSync-Duo{
                    <# Examples:
                     #  > DarkSync-Duo -TestMode
                     #  > DarkSync-Duo -Group '<AD Group Name> (from AD sync "<domain.local>")' -TestMode
                     #  > DarkSync-Duo -User "<UserName>" -TestMode
                     ##################>
                    [CmdletBinding(DefaultParameterSetName='NoInput')]
                    param(
                        [Parameter(ParameterSetName="NoInput", Mandatory=$false, ValueFromPipeline=$false)]
                        [Parameter(ParameterSetName="SyncDuoGroup", Mandatory=$true)] 
                        [Parameter(ParameterSetName="SyncDuoUser", Mandatory=$true)] 
                            [Switch]$TestMode,
                        [Parameter(ParameterSetName="SyncDuoGroup", Mandatory=$true)] 
                            [String]$Group,
                        [Parameter(ParameterSetName="SyncDuoUser", Mandatory=$true)] 
                            [String]$User
                    )
                    $Success=$false
                    if(DarkConnect-Duo){
                        function DarkSync-DuoUser{
                            param(
                                [Switch] $TestMode,
                                [String] $User
                            )
                            Write-Debug " |-Syncing Duo User: $User"
                            if(-Not $TestMode){
                                duoSyncUser -username $User
                            }
                        }

                        try{
                            switch($PSCmdlet.ParameterSetName){
                                ("SyncDuoGroup"){
                                    Write-Debug "Syncing Duo Group: $Group"
                                    if(-Not ([String]::IsNullOrEmpty($Group))){
                                        # Sync members of a group
                                        duoGetUser | %{
                                            if($_.groups.name -contains $Group){
                                                DarkSync-DuoUser -User $_.username -TestMode:$TestMode
                                            } 
                                        }
                                    }
                                }
                                ("SyncDuoUser"){
                                    if(-Not ([String]::IsNullOrEmpty($User))){
                                        # Sync a single user
                                        DarkSync-DuoUser -User $User -TestMode:$TestMode
                                    }
                                }
                                default{
                                    # Sync ALL users
                                    Write-Debug "Syncing ALL Duo Users:"
                                    duoGetUser | %{
                                        DarkSync-DuoUser -User $_.username -TestMode:$TestMode
                                    }
                                }
                            }
                            $Success=$true
                        } catch {
                            $Success=$false
                        } finally {
                            Write-Debug " \"
                        }
                    }
                    return $Success
                }
            #endregion
            #region Azure / Microsoft 365
                #region AzureAD
                    function DarkImport-AzureAD {
                        [alias("DarkConnect-AzureAD")]
                        [CmdletBinding(DefaultParameterSetName = '__AllParameterSets')]
                        param(
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Username’)] 
                                [String]$Username = $null,
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Object’)]
                                [PSCredential] $Credential = $null
                        )

                        $ImportSucceeded=$false
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import AzureAD PS module if not already present
                        Import-DarkModule -DarkModuleName AzureAD -PackageManager Nuget -PackageManagerVersion 2.8.5.201
                        # Get current connectivity details (if any)
                        $ConnectivityContext=$(try { Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue } catch { $null })
                        if(-Not $ConnectivityContext) {
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        # Login with specified $Username
                                        Connect-AzureAD -AccountId $Username | Out-Null
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        # Login with specified $Credential
                                        Connect-AzureAD -Credential $Credential | Out-Null
                                    }
                                }
                                default{
                                    # Login and let user enter all information manually
                                    Connect-AzureAD | Out-Null
                                }
                            }
                        } else {
                            # Force login again if specified username is different from current context.
                            $NewUsername=$null
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        $NewUsername=$Username
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        $NewUsername=$Credential.UserName
                                    }
                                }
                                default{
                                    $NewUsername=$ConnectivityContext.Account.Id
                                }
                            }
                            if($NewUsername -ne $ConnectivityContext.Account.Id){
                                Connect-AzureAD -AccountId $NewUsername | Out-Null
                            }
                        }
                        if($(try { Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue } catch { $null })) {
                            $ImportSucceeded=$true
                        } else {
                            $ImportSucceeded=$false
                        }
                        return $ImportSucceeded
                    }
                    function DarkSync-AzureAD {
                        [CmdletBinding()]
                        param(
                            [Parameter(Mandatory=$false,ParameterSetName="Default")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Username")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Credential")]
                            [ValidateNotNull()]
                            [String]$ADSyncHost = $($script:ETPoSh_Imports_Context.ServerRoleDict["AzureADConnect"]),
                            #-----
                            [Parameter(Mandatory=$true,ParameterSetName="Params_Username")]
                            [ValidateNotNull()]
                            [String]$ConnectAs,
                            [Parameter(Mandatory=$true,ParameterSetName="Params_Credential")]
                            [PSCredential]$Creds=$null,
                            #-----
                            [Parameter(Mandatory=$false,ParameterSetName="Default")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Username")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Credential")]
                            [Switch]$FullSync,
                            [Parameter(Mandatory=$false,ParameterSetName="Default")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Username")]
                            [Parameter(Mandatory=$false,ParameterSetName="Params_Credential")]
                            [Switch]$Silent
                        )
                        $PSSession=$null
                        $Success=$false
                        $Continue=$true

                        #region Session Creation Functions
                            function New-Session-Integrated{
                                $PSSession=New-PSSession -ComputerName $ADSyncHost
                                return $PSSession
                            }
                        
                            function New-Session-Credential{
                                param(
                                    $Credential
                                )
                                $PSSession=New-PSSession -ComputerName $ADSyncHost
                                return $PSSession
                            }
                            function New-Session-Username{
                                param(
                                    $Username
                                )
                                #...prompt for password 
                                $Credential=Get-Credential -UserName $Username -Message "Please supply the password for [$Username]"
                                $PSSession=New-Session-Credential -Credential $Credential
                                return $PSSession
                            }
                            function New-Session-InvalidCredentials{
                                $Credential=Get-Credential -Message "The suppied credentials did not work.  Please supply valid credentials."
                                $PSSession=New-Session-Credential -Credential $Credential
                                return $PSSession
                            }
                        #endregion

                        # Make sure server is online / reachable
                        if(Test-Connection -ComputerName $ADSyncHost -Count 4 -Quiet){
                            try {
                                switch($PSCmdlet.ParameterSetName){
                                    ("Default"){
                                        # Try session credentials FIRST
                                        $PSSession=New-Session-Integrated
                                    }
                                    ("Params_Username"){
                                        # Create PSCredential object from $ConnectAs FIRST
                                        $PSSession=New-Session-Username -Username $ConnectAs
                                    }
                                    ("Params_Credential"){
                                        # Use $Creds PSCredential object FIRST
                                        $PSSession=New-Session-Credential -Credential $Creds
                                    }
                                    default{
                                        throw "Invalid parameter set."
                                    }
                                } 
                            
                                # If session connection failed, prompt for other credentials if not running in "Silent" mode
                                if(($null -eq $PSSession) -or ($PSSession.State -ne "Opened")){
                                    if($Creds) {
                                        Write-Host "!ERROR! Provided credentials did not work." -ForegroundColor Red
                                    } 
                                    if(-Not $Silent){
                                        $PSSession=New-Session-InvalidCredentials
                                    }
                                }
                            
                                # Continue if $PSSession is not $null
                                if(($null -ne $PSSession) -or ($PSSession.State -eq "Opened")){
                                    $CommandResult=(Invoke-Command -Session $PSSession -ArgumentList $FullSync -ScriptBlock {
                                        $FullSync=$args[0]
                                        Import-DarkModule ADSync
                                        if($FullSync.IsPresent) { 
                                            Start-ADSyncSyncCycle -PolicyType Initial
                                        } else {
                                            Start-ADSyncSyncCycle -PolicyType Delta
                                        }
                                    }).Result
                                    if($CommandResult -eq "Success"){
                                        $Success=$true
                                    }
                                }
                            } catch {
                                Write-Error $_
                            } finally {
                                $PSSession = $null
                            }
                        }
                        return $Success
                    }
                #endregion
                #region MSOL
                    function DarkImport-MSOL {
                        [alias("DarkConnect-MSOL")]
                        param()
                        #param(
                        #    [String]$Username = $null
                        #)
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import MSOnline PS module if not already present
                        Import-DarkModule -DarkModuleName MSOnline -PackageManager Nuget -PackageManagerVersion 2.8.5.201
                        # Connect to MSOnline if not already connected
                        if((-Not $(try { Get-MsolCompanyInformation -ErrorAction SilentlyContinue } catch { $null }))) { 
                            #if(-Not ([String]::IsNullOrEmpty($Username))){
                            #        -Credential $MSOL_AdminUser_Creds
                            #    Connect-MsolService -AccountID $Username | Out-Null
                            #} else {
                                Connect-MsolService | Out-Null
                            #}
                        }
                    }       
                #endregion
                #region ExchangeOnline
                    function DarkImport-ExchangeOnline {
                        [alias("DarkConnect-ExchangeOnline")]
                        param(
                            [String]$Username = $null
                        )
                        $Success=$null
                            function Validate-Session{
                                if((Get-PSSession | `
                                    Where { ($_.ConfigurationName -eq "Microsoft.Exchange") `
                                     -and   ($_.ComputerName -eq "outlook.office365.com") `
                                     -and   ($_.State -eq "Opened") }).Count -eq 0) { 
                                    return $false
                                } else {
                                    return $true
                                }
                            }
                        try {
                            Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                            # Import PowerShellGet PS module if not already present
                            Import-DarkModule -DarkModuleName PowerShellGet
                            # Import ExchangeOnlineManagement PS module if not already present
                            Import-DarkModule -DarkModuleName ExchangeOnlineManagement 
                            # Connect to ExchangeOnlineManagement if not already connected
                            if(-Not (Validate-Session)) { 
                                if(-Not ([String]::IsNullOrEmpty($Username))){
                                    Connect-ExchangeOnline -UserPrincipalName $Username | Out-Null
                                } else {
                                    Connect-ExchangeOnline | Out-Null
                                }
                            } else {
                                $Success = $true
                            }
                            # Validate session if new
                            if($true -ne $Success){
                                $Success = Validate-Session
                            }
                        } catch {
                            $Success=$false
                        }
                        return $Success
                    }
                    function Get-ObjectBySMTPAddress{
                        param(
                            [String]$SMTPAddress=$null
                        )

                        $ReturnValue=$null

                        #if(DarkConnect-ExchangeOnline){
                            $ReturnValue=@(Get-EXORecipient -Resultsize Unlimited -PropertySets All | %{ 
                                $EXORecipient=$_
                                $EXORecipient.EmailAddresses | 
                                    Where { $_.ToLower() -like "smtp:*"} | %{
                                        [PSCustomObject] @{
                                            ObjectType=$EXORecipient.RecipientType
                                            Name=$EXORecipient.DisplayName
                                            ReplyAddress=$EXORecipient.PrimarySmtpAddress
                                            SMTPAddress=$_.ToLower().TrimStart("smtp:").TrimStart("SMTP:")
                                        }
                                    } 
                            })
                        #}

                        if([String]::IsNullOrWhiteSpace($SMTPAddress)){
                            return @($ReturnValue)
                        } else {
                            return @($ReturnValue | Where { $_.SMTPAddress -like "*$($SMTPAddress.ToLower())*" })
                        }
                    }
                    function DarkRemove-ExchangeOnline{
                        [Alias("DarkDisconnect-ExchangeOnline")]
                        [CmdletBinding()]
                        param()
                        Disconnect-ExchangeOnline
                        Get-DarkModule | Where { $_.Name -eq "ExchangeOnlineManagement" } | Remove-DarkModule
                    }
                #endregion
                #region Teams
                    function DarkImport-MSTeams {
                        [alias("DarkConnect-MSTeams")]
                        [CmdletBinding(DefaultParameterSetName = '__AllParameterSets')]
                        param(
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Username’)] 
                                [String]$Username = $null,
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Object’)]
                                [PSCredential] $Credential = $null
                        )

                        $ImportSucceeded=$false
                        $ModuleName="MicrosoftTeams"
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import PowerShellGet PS module if not already present
                        Import-DarkModule -DarkModuleName PowerShellGet
                        # Import AzureAD PS module if not already present
                        Import-DarkModule -DarkModuleName $ModuleName 
                        # Get current connectivity details (if any)
                    
                        $ConnectivityContext=$(try { Get-CsTenant -ErrorAction SilentlyContinue } catch { $null })
                        if(-Not $ConnectivityContext) {
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        # Login with specified $Username
                                        Connect-MicrosoftTeams  -AccountId $Username | Out-Null
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        # Login with specified $Credential
                                        Connect-MicrosoftTeams -Credential $Credential | Out-Null
                                    }
                                }
                                default{
                                    # Login and let user enter all information manually
                                    Connect-MicrosoftTeams | Out-Null
                                }
                            }
                        } else {
                            # Force login again if specified username is different from current context.
                            $NewUsername=$null
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        $NewUsername=$Username
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        $NewUsername=$Credential.UserName
                                    }
                                }
                                default{
                                    $NewUsername=$ConnectivityContext.Account.Id
                                }
                            }
                            if($NewUsername -ne $ConnectivityContext.Account.Id){
                                Connect-MicrosoftTeams -AccountId $NewUsername | Out-Null
                            }
                        }
                        if($(try { Get-CsTenant -ErrorAction SilentlyContinue } catch { $null })) {
                            $ImportSucceeded=$true
                        } else {
                            $ImportSucceeded=$false
                        }
                        return $ImportSucceeded
                    }
                    function DarkRemove-MSTeams{
                        [Alias("DarkDisconnect-MSTeams")]
                        [CmdletBinding()]
                        param()
                        Disconnect-MicrosoftTeams
                        Get-DarkModule | Where { $_.Name -eq "MicrosoftTeams" } | Remove-DarkModule
                    }
                #endregion
                #region SharePoint
                    function DarkImport-SharePointOnline {
                        [alias("DarkConnect-SharePointOnline")]
                        [CmdletBinding(DefaultParameterSetName = '__AllParameterSets')]
                        param(
                            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Username’)] 
                            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Object’)]
                                [String]$SiteUrl = $null,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Username’)] 
                                [String]$Username = $null,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Object’)]
                                [PSCredential] $Credential = $null
                        )

                        $ImportSucceeded=$false
                        $ModuleName="Microsoft.Online.SharePoint.PowerShell"
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import AzureAD PS module if not already present
                        Import-DarkModule -DarkModuleName $ModuleName #-PackageManager PowerShellGet
                        # Get current connectivity details (if any)
                    
                        $ConnectivityContext=$(try { Get-SpoTenant -ErrorAction SilentlyContinue } catch { $null })
                        if(-Not $ConnectivityContext) {
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        # Login with specified $Username
                                        Connect-SPOService -Url $SiteUrl -Credential $Username | Out-Null
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        # Login with specified $Credential
                                        Connect-SPOService -Url $SiteUrl -Credential $Credential | Out-Null
                                    }
                                }
                                default{
                                    # Login and let user enter all information manually
                                    Connect-SPOService -Url $SiteUrl | Out-Null
                                }
                            }
                        } else {
                            # Force login again if specified username is different from current context.
                            $NewUsername=$null
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_Username"){
                                    if(-Not ([String]::IsNullOrEmpty($Username))){
                                        $NewUsername=$Username
                                    }
                                }
                                ("CREDS_Object"){
                                    if($null -ne $Credential){
                                        $NewUsername=$Credential.UserName
                                    }
                                }
                                default{
                                    $NewUsername=$ConnectivityContext.Account.Id
                                }
                            }
                            if($NewUsername -ne $ConnectivityContext.Account.Id){
                                Connect-SPOService -Url $SiteUrl -Credential $NewUsername | Out-Null
                            }
                        }
                        if($(try { Get-SpoTenant -ErrorAction SilentlyContinue } catch { $null })) {
                            $ImportSucceeded=$true
                        } else {
                            $ImportSucceeded=$false
                        }
                        return $ImportSucceeded
                    }
                    function DarkRemove-SharePointOnline{
                        [Alias("DarkDisconnect-SharePointOnline")]
                        [CmdletBinding()]
                        param()
                        Disconnect-SPOService
                        Get-DarkModule | Where { $_.Name -eq "Microsoft.Online.SharePoint.PowerShell" } | Remove-DarkModule
                    }
                #endregion
                #region Partner Center
                    function DarkImport-PartnerCenter{
                        [alias("DarkConnect-PartnerCenter")]
                        [CmdletBinding(DefaultParameterSetName = '__AllParameterSets')]
                        param(
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_ServicePrincipal’)] 
                                [String]$TenantID = $null,
                            [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ParameterSetName=’CREDS_Object’)]
                                [PSCredential] $Credential = $null
                        )

                            Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import PartnerCenter PS module if not already present
                        Import-DarkModule -DarkModuleName PartnerCenter
                        # Connect to PartnerCenter if not already connected
                        $ConnectivityContext=$(try { Get-PartnerContext -ErrorAction SilentlyContinue } catch { $null })
                        if(-Not $ConnectivityContext) {
                            $LoginAsServiceCredential=$false
                            $ServicePrincipal_Credentials = $null
                            switch($PSCmdlet.ParameterSetName){
                                ("CREDS_ServicePrincipal"){
                                    $LoginAsServiceCredential=$true
                                    if(-Not ([String]::IsNullOrEmpty($TenantID))){
                                        # Login with specified $Username
                                        $Credential = Get-Credential -UserName $TenantID -Message ("Please provide the service principal secret for application id [{0}]." -f $TenantID)
                                    }
                                }
                                ("CREDS_Object"){
                                    $LoginAsServiceCredential=$true
                                    #if($null -ne $Credential){
                                    #    # Login with specified $Credential
                                    #    Connect-PartnerCenter -Credential $Credential | Out-Null
                                    #}
                                }
                                default{
                                    $LoginAsServiceCredential=$false
                                }
                            }
                            if($LoginAsServiceCredential){
                                Connect-PartnerCenter -Credential $Credential -ServicePrincipal | Out-Null
                            } else {
                                # Login and let user enter all information manually
                                Connect-PartnerCenter | Out-Null
                            }
                            #-----------------
                            # This command connects to a Partner Center account. To run partner cmdlets with this account, you must provide an organizational credentials, that are associated with the Cloud Solution Provider program, at the prompt.
                            #PS C:\> Connect-PartnerCenter
                            #-----------------
                            # The first command gets the service principal credentials (application identifier and service principal secret), and then stores them in the $credential variable. 
                            # The second command connects to Partner Center using the service principal credentials stored in $credential for the specified Tenant. The ServicePrincipal switch parameter indicates that the account authenticates as a service principal.
                            #PS C:\> $credential = Get-Credential
                            #PS C:\> Connect-PartnerCenter -Credential $credential -Tenant 'xxxx-xxxx-xxxx-xxxx' -ServicePrincipal
                            #-----------------
                            # Connects to Partner Center using a refresh token that was generated using a native application (https://docs.microsoft.com/azure/active-directory/develop/native-app).
                            #PS C:\> $refreshToken = '<refreshToken>'
                            #PS C:\> Connect-PartnerCenter -ApplicationId 'xxxx-xxxx-xxxx-xxxx' -RefreshToken $refreshToken
                            #-----------------
                            # Connects to Partner Center using a refresh token that was generated using a web application (https://docs.microsoft.com/azure/active-directory/develop/web-app).
                            #PS C:\> $appId = 'xxxx-xxxx-xxxx-xxxx'
                            #PS C:\> $secret =  ConvertTo-SecureString 'app-secret-here' -AsPlainText -Force
                            #PS C:\> $refreshToken = '<refreshToken>'
                            #PC C:\> $tenantId = 'yyyy-yyyy-yyyy-yyyy'
                            #PS C:\>
                            #PS C:\> $credential = New-Object System.Management.Automation.PSCredential($appId, $secret)
                            #PS C:\>
                            #PS C:\> Connect-PartnerCenter -ApplicationId $appId -Credential $credential -RefreshToken $refreshToken
                            #-----------------
                        }
                    }
                #endregion
                #region MS Graph
                    function New-DarkAppRegCert{
                        param(
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$ClientID,
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$TenantID,
                            [String]$StoreLocation = "Cert:\CurrentUser\My",
                            [DateTime]$ExpirationDate = (Get-Date).AddMonths(60)
                        )
                        # Where to export the certificate without the private key
                        #$CerOutputPath     = "$($env:userprofile)\Desktop\PowerShellGraphCert.cer"

                        $CertSubject=Get-DarkAppRegCertSubject -ClientID $ClientID -TenantID $TenantID

                        # Splat for readability
                        $CreateCertificateSplat = @{
                            FriendlyName      = "Azure AD App"
                            DnsName           = $CertSubject
                            CertStoreLocation = $StoreLocation
                            NotAfter          = $ExpirationDate
                            KeyExportPolicy   = "Exportable"
                            KeySpec           = "Signature"
                            #--> ECC Options
                            #Provider          = "Microsoft SSL Protocol Provider"
                            #KeyAlgorithm      = "ECDSA_brainpoolP384r1"
                            #KeyAlgorithm      = "ECDSA_brainpoolP512r1"
                            #CurveExport       = "CurveName"
                            #--> RSA Options
                            KeyAlgorithm      = "RSA"
                            KeyLength         = 4096
                            Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
                            HashAlgorithm     = "SHA256"
                            #HashAlgorithm     = "SHA512"
                        }
                        # Create certificate
                        $Certificate = New-SelfSignedCertificate @CreateCertificateSplat
                    }
                    function Get-DarkAppRegCertSubject{
                        param(
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$ClientID,
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$TenantID
                        )
                        $String=("[{0}].[{1}]" -f $TenantID, $ClientID).ToLower()
                        $StringBuilder = New-Object System.Text.StringBuilder 
                        [System.Security.Cryptography.HashAlgorithm]::Create("SHA256").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | %{ 
                            [Void]$StringBuilder.Append($_.ToString("x2")) 
                        } 
                        return $StringBuilder.ToString() 
                    }
                    function Get-DarkLocalAppRegCert{
                        param(
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$ClientID,
                            [Parameter(Mandatory=$true)]
                            [ValidateNotNull()]
                            [String]$TenantID,
                            [Switch]$Newest = $false
                        )
                        $CertSubject=Get-DarkAppRegCertSubject -ClientID $ClientID -TenantID $TenantID
                        $MatchingCerts = @(Get-ChildItem "Cert:\CurrentUser\My" | Where { 
                             ($_.NotAfter -gt (Get-Date)) -and 
                             ($_.NotBefore -lt (Get-Date)) -and
                             ($_.DnsNameList -contains $CertSubject)
                        } | Sort NotBefore)
                        if($MatchingCerts.Count -gt 0){
                            if($Newest){
                                $ReturnCert = $MatchingCerts | Select * -Last 1
                            } else {
                                $ReturnCert = $MatchingCerts | Select * -First 1
                            }
                        } else {
                            $ReturnCert = $null
                        }
                        return $ReturnCert
                    }
                    function DarkImport-MSGraph{
                        [alias("DarkConnect-MSGraph")]
                        [CmdletBinding()]
                        param(
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’NoCredentials’)] 
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate’)]
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Thumprint’)] 
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Subject’)] 
                            #[Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_ClientSecret’)]
                            [ValidateNotNull()]
                                [String]$ClientID,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’NoCredentials’)]
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate’)]
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Thumprint’)]
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Subject’)]  
                            #[Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_ClientSecret’)]
                            [ValidateNotNull()]
                                [String]$TenantID,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate’)]
                            [ValidateNotNull()] 
                                [Object]$Certificate,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Thumprint’)]
                            [ValidateNotNull()] 
                                [String]$CertificateThumbprint,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Subject’)] 
                            [ValidateNotNull()]
                                [String]$CertificateSubject,
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’NoCredentials’)]
                            [Parameter(Mandatory=$true, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate’)]
                            [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Thumprint’)]
                            [Parameter(Mandatory=$false, ValueFromPipeline=$false, ParameterSetName=’AppOnlyAuth_Certificate_Subject’)] 
                                [Switch]$Teams
                        )
                        # https://docs.microsoft.com/en-us/graph/powershell/app-only?tabs=azure-portal
                        $Success=$null
                    
                        enum GraphModuleGroups{
                            All
                            Teams
                        }

                        $ModuleBase="Microsoft.Graph"

                        $ModuleList_AllGroups=@(
                            ("{0}.Authentication" -f $ModuleBase)
                        )
                        $ModuleGroupLists=[PSCustomObject]@{
                            All=@(
                                ("{0}" -f $ModuleBase)
                            )
                            Teams=@(
                                ("{0}.Teams" -f $ModuleBase)
                                ("{0}.Groups" -f $ModuleBase)
                                ("{0}.Reports" -f $ModuleBase)
                            )
                        }
                        <#
                            Microsoft.Graph                                
                            Microsoft.Graph.Applications                   
                            Microsoft.Graph.Authentication                 
                            Microsoft.Graph.Bookings                       
                            Microsoft.Graph.Calendar                       
                            Microsoft.Graph.ChangeNotifications            
                            Microsoft.Graph.CloudCommunications            
                            Microsoft.Graph.Compliance                     
                            Microsoft.Graph.CrossDeviceExperiences         
                            Microsoft.Graph.DeviceManagement               
                            Microsoft.Graph.DeviceManagement.Actions       
                            Microsoft.Graph.DeviceManagement.Administration
                            Microsoft.Graph.DeviceManagement.Enrolment     
                            Microsoft.Graph.DeviceManagement.Functions     
                            Microsoft.Graph.Devices.CloudPrint             
                            Microsoft.Graph.Devices.CorporateManagement    
                            Microsoft.Graph.DirectoryObjects               
                            Microsoft.Graph.Education                      
                            Microsoft.Graph.Files                          
                            Microsoft.Graph.Financials                     
                            Microsoft.Graph.Groups                         
                            Microsoft.Graph.Identity.DirectoryManagement   
                            Microsoft.Graph.Identity.Governance            
                            Microsoft.Graph.Identity.SignIns               
                            Microsoft.Graph.Mail                           
                            Microsoft.Graph.Notes                          
                            Microsoft.Graph.People                         
                            Microsoft.Graph.PersonalContacts               
                            Microsoft.Graph.Planner                        
                            Microsoft.Graph.Reports                        
                            Microsoft.Graph.SchemaExtensions               
                            Microsoft.Graph.Search                         
                            Microsoft.Graph.Security                       
                            Microsoft.Graph.Sites                          
                            Microsoft.Graph.Teams                          
                            Microsoft.Graph.Users                          
                            Microsoft.Graph.Users.Actions                  
                            Microsoft.Graph.Users.Functions                
                            Microsoft.Graph.WindowsUpdates
                        #>

                        $ModuleNameList=$ModuleGroupLists.All

                        if($Teams){
                            $ModuleNameList=$ModuleGroupLists.Teams
                        }

                        try{
                            # Import Microsoft.Graph PS modules if not already present
                            $ModuleList_AllGroups | %{
                                $moduleName = $_
                                Import-DarkModule -DarkModuleName $ModuleName -UpdateModule
                            }
                            $ModuleNameList | %{
                                $moduleName = $_
                                Import-DarkModule -DarkModuleName $ModuleName -UpdateModule
                            }


                            #@(
                            #    $ModuleList_AllGroups
                            #    $ModuleNameList
                            #) | %{
                            #    $moduleName = $_
                            #    Import-DarkModule -DarkModuleName $ModuleName #-UpdateModule
                            #}

                            #region Generate Authentication Params
                                $GraphParams=@{
                                    ClientID=$ClientID
                                    TenantID=$TenantID
                                }
                                switch($PSCmdlet.ParameterSetName){
                                    ("NoCredentials"){
                                        $Cert=Get-DarkLocalAppRegCert @GraphParams
                                        if($Cert){
                                            # Make sure to use the "Thumbprint" method here to verify that the certificate is actually installed locally.
                                            #$GraphParams.Add("CertificateName", $(Get-DarkAppRegCertSubject @GraphParams))
                                            $GraphParams.Add("CertificateThumbprint", $(Get-DarkLocalAppRegCert @GraphParams).Thumbprint)
                                        } else {
                                            throw "Unable to obtain access using any available methods."
                                        }
                                    }
                                    ("AppOnlyAuth_Certificate"){
                                        $GraphParams.Add("Certificate", $Certificate)
                                    }
                                    ("AppOnlyAuth_Certificate_Thumprint"){
                                        $GraphParams.Add("CertificateThumbprint", $CertificateThumbprint)
                                    }
                                    ("AppOnlyAuth_Certificate_Subject"){
                                        $GraphParams.Add("CertificateName", $CertificateSubject)
                                    }
                                    #("AppOnlyAuth_ClientSecret"){
                                    #    $GraphParams.Add("ClientSecret", $CertificateSubject)
                                    #}
                                    default{
                                        throw "Invalid parameter set."
                                    }
                                }
                            #endregion

                            # Connect
                            Connect-MgGraph @GraphParams

                            $Success = $true
                        } catch { 
                            $Success = $false
                        }
                        return $Success
                    }
                    function DarkRemove-MSGraph{
                        [Alias("DarkDisconnect-MSGraph")]
                        [CmdletBinding()]
                        param()
                        Disconnect-MgGraph
                        Get-DarkModule | Where { $_.Name -like "Microsoft.Graph*" -and $_.Name -notlike "*.Authentication" } | Remove-DarkModule
                        Get-DarkModule | Where { $_.Name -like "Microsoft.Graph.Authentication" } | Remove-DarkModule
                    }
                    <#
                    function DarkImport-MSGraph{
                        [alias("DarkConnect-MSGraph")]
                        param(
                            #[String]$Username = $null
                        )
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import Microsoft.Graph PS module if not already present
                        Import-DarkModule -DarkModuleName "Microsoft.Graph"

                        # Connect to Microsoft.Graph if not already connected
                        if(-Not ($(try { Get-PartnerContext -ErrorAction SilentlyContinue } catch { $null }))) {
                            if(-Not ([String]::IsNullOrEmpty($Username))){
                                Connect-PartnerCenter -AccountId $Username | Out-Null
                                Connect-MgGraph -Scopes "User.Read.All","Group.ReadWrite.All" -
                            } else {
                                Connect-PartnerCenter | Out-Null
                            }
                        }
                    }
                    #>
                #endregion
                <#
                #region MSAL
                    function etpMSAL{
                        Import-DarkModule -DarkModuleName "MSAL.PS" -PackageManager Nuget
                        Install-DarkModule -Name 
                        Get-MsalToken
                    }
                #endregion
                #>
                <#
                #region Az...
                    function DarkImport-Az {
                        [alias("DarkConnect-Az")]
                        param(
                            [String]$Username = $null
                        )
                        $ImportSucceeded=$false
                        Write-Debug "[Username] $(if(-Not [String]::IsNullOrEmpty($Username)){ $Username })"
                        # Import Az PS module if not already present
                        #Install-DarkModule -Name Az -Scope CurrentUser -Repository PSGallery -Force
                        Import-DarkModule -DarkModuleName Az -PackageManager Nuget
                        # Connect to Az if not already connected
                        if(-Not ($(try { Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue } catch { $null }))) {
                            if(-Not ([String]::IsNullOrEmpty($Username))){
                                Connect-AzAccount -AccountId $Username | Out-Null
                            } else {
                                Connect-AzAccount | Out-Null
                            }
                        }
                        if($(try { Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue } catch { $null })) {
                            $ImportSucceeded=$true
                        } else {
                            $ImportSucceeded=$false
                        }
                        return $ImportSucceeded
                    }
                #endregion
                #>
            #endregion
            #region CW Manage
        
            #endregion
            #region CW Automate
        
            #endregion
            #region IT Glue
                function DarkImport-ITGlue {
                    [alias("DarkConnect-ITGlue")]
                    param(
                        [Switch]$Persist
                    )
                    $ModuleName="ITGlueAPI"
                    $Authenticated=$false

                    # Import Module
                    try{
                        if(-Not $Persist) {
                            if((Get-DarkModule -Name $ModuleName)) {
                                Remove-DarkModule $ModuleName | Out-Null
                            }
                        }
                    } catch {
                        # DO NOTHING
                    } finally {
                        Import-DarkModule -DarkModuleName $ModuleName
                    }

                    # Import Cached Credentials
                    function Setup-DarkITGlueUserSettings{
                        param(
                            [String]$APIKey=$null,
                            [String]$APIUrl="https://api.itglue.com"
                        )
                        if(-Not $APIKey) {
                            $APIKey=Read-Host -Prompt "[APIKey]" 
                        }
                        DarkImport-ITGlueModule -Persist | Out-Null
                        Add-ITGlueBaseURI -base_uri $APIUrl
                        Add-ITGlueAPIKey -Api_Key $APIKey
                        Export-ITGlueModuleSettings 
                        $APIKey=$null
                        $APIUrl=$null
                        Remove-DarkModule ITGlueAPI
                    }
                    try {
                        $ITGlueTempFile = "$($env:userprofile)\AppData\Local\Dark-PoSh\API\access\itg.psd1"
                        $ITGlueAPIConfPath = "$($env:USERPROFILE)\ITGlueAPI"
                        $ITGlueAPIConfFile = "config.psd1"
                        $NewLineToken = "%NEWLINE%"
                        if(-Not (Test-Path $ITGlueTempFile)){
                            if(-Not (Test-Path "$($ITGlueAPIConfPath)\$($ITGlueAPIConfFile)")){
                                Setup-DarkITGlueUserSettings
                            }
                            (Get-Content "$($ITGlueAPIConfPath)\$($ITGlueAPIConfFile)").Replace("\r\n", $NewLineToken) | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $ITGlueTempFile -Append:$false -Force:$true -Confirm:$false
                        }
                        # Delete persistent file: $($env:USERPROFILE)\ITGlueAPI\config.psd1
                        if(Test-Path "$ITGlueAPIConfPath\$ITGlueAPIConfFile"){
                            Remove-Item "$ITGlueAPIConfPath\$ITGlueAPIConfFile" -Force
                        }
                        # Create the persistent file: $($env:USERPROFILE)\ITGlueAPI\config.psd1
                        (Get-Content $ITGlueTempFile) | ConvertTo-SecureString | %{ [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)).Replace($NewLineToken, "\r\n") } | Out-File "$($ITGlueAPIConfPath)\$($ITGlueAPIConfFile)" -Append:$true -Force:$true -Confirm:$false
                        #if(-Not (Test-Path "$($ITGlueAPIConfPath)\$($ITGlueAPIConfFile)")){
                            (Get-Content $ITGlueTempFile) | ConvertTo-SecureString | %{ [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)).Replace($NewLineToken, "\r\n") } | Out-File "$($ITGlueAPIConfPath)\$($ITGlueAPIConfFile)" -Append:$false -Force:$true -Confirm:$false
                        #}
                        # Import settings from $($env:USERPROFILE)\ITGlueAPI\config.psd1
                        DarkImport-ITGlueModule
                        $Authenticated=$true
                    } catch {
                        $Authenticated=$false
                        Write-Error "Could not import cached credentials."
                    } finally {
                        # Delete persistent file: $($env:USERPROFILE)\ITGlueAPI\config.psd1
                        if(Test-Path "$ITGlueAPIConfPath\$ITGlueAPIConfFile"){
                            Remove-Item "$ITGlueAPIConfPath\$ITGlueAPIConfFile" -Force
                        }
                    }
                    return $Authenticated
                }
            #endregion
        #endregion
    #endregion
#endregion
#region Module Events
    #<#
    $ExecutionContext.SessionState.Module.OnRemove = {
        Dispose-DarkModule
    }
    #>
#endregion
Initialize-DarkModule