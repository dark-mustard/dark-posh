$UnitTestFileList=@(
    "$PSScriptRoot\DarkPoSh.Logging\DarkPoSh.Logging.Tests.ps1"
)

#region Custom Pester Functions
    function Import-Pester{
        param(
            [String]$MinimumVersion,
            [Switch]$Update
        )
        <# Pester v. 3.4.0 installed by default on Windows Server OS and 
        # cannot be updated using the "Update-Module" command.
        # This command will check if any other versions of Pester are installed.
        #   [If so]  - it will check for and apply updates
        #   [If not] - it will install the newest version in parallel
        # Reference:
        #   https://pester-docs.netlify.app/docs/introduction/installation
        #>
        $Success       = $false
        $ModuleName    = "Pester"
        $IgnoreVersion = "3.4.0"

        #region Sub-Functions
            function Get-ImportedModuleMatches{
                param(
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                        [String]$ModuleName,
                    [Parameter(Mandatory = $false)]
                        [String]$MinimumVersion = $null,
                    [Parameter(Mandatory = $false)]
                        [String]$IgnoreVersion = $null
                )
                $CurrentlyImportedModules = @(Get-Module $ModuleName | Sort-Object Version -Descending)
                if(-Not [String]::IsNullOrWhiteSpace($MinimumVersion)){
                    $CurrentlyImportedModules = @($CurrentlyImportedModules | Where-Object { $_.Version -ge $MinimumVersion })
                }
                if(-Not [String]::IsNullOrWhiteSpace($IgnoreVersion)){
                    $CurrentlyImportedModules = @($CurrentlyImportedModules | Where-Object { $_.Version -ne $IgnoreVersion })
                }
                return $CurrentlyImportedModules
            }
            function Get-ImportedModuleMatch{
                param(
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                        [String]$ModuleName,
                    [Parameter(Mandatory = $false)]
                        [String]$MinimumVersion = $null,
                    [Parameter(Mandatory = $false)]
                        [String]$IgnoreVersion = $null
                )
                $LatestMatchingModule = $null
                $ModuleMatchParams = @{
                    ModuleName     = $ModuleName
                    MinimumVersion = $MinimumVersion
                    IgnoreVersion  = $IgnoreVersion
                }
                $CurrentlyImportedModules = Get-ImportedModuleMatches @ModuleMatchParams
                if($CurrentlyImportedModules.Count -gt 0){
                    $LatestMatchingModule = $CurrentlyImportedModules[0]
                }
                return $LatestMatchingModule
            }
            function Get-InstalledModuleMatches{
                param(
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                        [String]$ModuleName,
                    [Parameter(Mandatory = $false)]
                        [String]$MinimumVersion = $null,
                    [Parameter(Mandatory = $false)]
                        [String]$IgnoreVersion = $null
                )
                $CurrentlyInstalledModules = @(
                    Get-Module -ListAvailable | 
                        Where-Object { $_.Name -eq $ModuleName } | 
                            Sort-Object Version -Descending
                )
                if(-Not [String]::IsNullOrWhiteSpace($MinimumVersion)){
                    $CurrentlyInstalledModules = @($CurrentlyImportedModules | Where-Object { $_.Version -ge $MinimumVersion })
                }
                if(-Not [String]::IsNullOrWhiteSpace($IgnoreVersion)){
                    $CurrentlyInstalledModules = @($CurrentlyInstalledModules | Where-Object { $_.Version -ne $IgnoreVersion })
                }
                return $CurrentlyImportedModules
            }
            function Get-InstalledModuleMatch{
                param(
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                        [String]$ModuleName,
                    [Parameter(Mandatory = $false)]
                        [String]$MinimumVersion = $null,
                    [Parameter(Mandatory = $false)]
                        [String]$IgnoreVersion = $null
                )
                $LatestMatchingModule = $null
                $ModuleMatchParams = @{
                    ModuleName     = $ModuleName
                    MinimumVersion = $MinimumVersion
                    IgnoreVersion  = $IgnoreVersion
                }
                $CurrentlyInstalledModules = Get-InstalledModuleMatches @ModuleMatchParams
                if($CurrentlyInstalledModules.Count -gt 0){
                    $LatestMatchingModule = $CurrentlyInstalledModules[0]
                }
                return $LatestMatchingModule
            }
        #endregion
        $ModuleMatchParams = @{
            ModuleName     = $ModuleName
            MinimumVersion = $MinimumVersion
            IgnoreVersion  = $IgnoreVersion
        }
        # Skip process if module is already present
        $CurrentlyImportedMatch = Get-ImportedModuleMatch @ModuleMatchParams
        if($null -eq $CurrentlyImportedMatch) {

            # Enable TLS 1.2 for current session
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            # Retrieve list of versions installed other than factory-shipped version.
            $LatestInstalledVersion = Get-InstalledModuleMatch @ModuleMatchParams

            # Install / update depending on results.
            if($null -eq $LatestInstalledVersion){
                # No other versions found - install newest release in parallel
                Install-Module -Name $ModuleName -Force -SkipPublisherCheck
            } else {
                if($Update){
                    # Valid version found - update to latest
                    $ManuallyInstalledVersionList[0] | Update-Module #-Confirm
                }
            }

            # Re-fetch latest installed version for import
            $LatestInstalledVersion = Get-InstalledModuleMatch @ModuleMatchParams

            # Remove any other imported versions from current context
            Get-Module -Name $ModuleName | Where-Object { $_.Version -ne $LatestInstalledVersion.Version } | Remove-Module -Force

            # Import specific module
            Import-Module -Name $LatestInstalledVersion.Name -RequiredVersion $LatestInstalledVersion.Version -Force
            Write-Debug ("Valid module version imported successfully. {0} 'ModuleName': '{2}', 'Version': '{3}' {1}" -f "{", "}", $LatestInstalledVersion.Name, $LatestInstalledVersion.Version)
            
            # Declare function status a success
            $Success = $true
        } else {
            # Declare function status a success
            $Success = $true
            Write-Debug ("Valid module version already imported. {0} 'ModuleName': '{2}', 'Version': '{3}' {1}" -f "{", "}", $CurrentlyImportedMatch.Name, $CurrentlyImportedMatch.Version)
        }

        # Return function status
        return $Success
    }
    function New-PesterRuntimeConfig{
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateNotNull()]
                [String]$Path,
            [Parameter(Mandatory = $false)]
            [ValidateSet(0, 1, 2, 3, 4)]
                [Int32]$DetailLevel = 1,
            [Parameter(Mandatory = $false)]
                [Switch]$PassThru,
            [Parameter(Mandatory = $false)]
                [Switch]$SaveResultsToFile,
            [Parameter(Mandatory = $false)]
                [Switch]$Force  
        )
        if(Test-Path $Path){
            #region Initialize parameters
                $Timestamp              = Get-Date
                $TimestampString        = $Timestamp.ToString('yyyyMMddHHmmss')
                $PathInfo               = Get-Item $Path
                #$PathInfo | FL *
                if($PathInfo.Attributes -contains "Directory"){
                    $TestSourceRootPath = $PathInfo.FullName
                    $TestSourceName     = (Split-Path $TestSourceRootPath -Leaf)
                } else {
                    $TestSourceRootPath = $PathInfo.Directory
                    $TestSourceName     = $PathInfo.BaseName
                }
                $TestFileSuffix         = ".Tests"
                $ModuleName             = $TestSourceName.Replace($TestFileSuffix, "")
                #$ContainerTempDir = Join-Path $(Join-Path $env:tmp "Pester") $("{0}_{1}" -f $TestSourceName, (Get-Date).ToString("yyyyMMddHHmmss"))
                    #Write-Host "TestSourceRootPath: [$TestSourceRootPath]"
                    #Write-Host "TestSourceName:     [$TestSourceName]"
                    #Write-Host "ContainerTempDir:   [$ContainerTempDir]"
            #endregion
            #region Create Container
                $ContainerConfig = @{
                    Path        = $Path
                    Data        = @{
                        ModuleInfo = ([PSCustomObject]@{
                            Directory = $TestSourceRootPath
                            Name      = $ModuleName
                            Files = [PSCustomObject]@{
                                RootModule = [PSCustomObject]@{
                                    Name = $("{0}.psm1" -f $ModuleName)
                                    Path = $(Join-Path $TestSourceRootPath ("{0}.psm1" -f $ModuleName))
                                }
                                ModuleManifest = [PSCustomObject]@{
                                    Name = $("{0}.psd1" -f $ModuleName)
                                    Path = $(Join-Path $TestSourceRootPath ("{0}.psd1" -f $ModuleName))
                                }
                            }
                        })
                    }
                    <#
                    ScriptBlock = {
                        
                    }
                    #>
                }
                $PesterContainer = New-PesterContainer @ContainerConfig
            #endregion
            #region Create Configuration
                ####################################
                # Create Configuration
                #    Reference: https://pester-docs.netlify.app/docs/commands/New-PesterConfiguration
                # ----------------------------------
                # [Should.ErrorAction]
                #    Value Range: @( "Stop", "Continue" )
                #    Default:     "Stop"
                # [Output.Verbosity]
                #    Value Range: @(None, Normal, Detailed, Diagnostic)
                #    Default:     Normal
                ####################################
                #$PesterRuntimeSettings.Config = [PesterConfiguration]::Default
                $PesterRuntimeConfig = New-PesterConfiguration -Hashtable @{
                    Run          = @{
                        Path                = $Path
                        Container           = $PesterContainer
                        PassThru            = $(if($PassThru) { $true } else { $false })
                        TestExtension       = "$TestFileSuffix.ps1"
                        <#
                        ExcludePath         = @()
                        ScriptBlock         = @()
                        Exit                = $false
                        Throw               = $false
                        SkipRun             = $false
                        #>
                    }
                    <#
                    Filter       = @{
                        Tag                    = @()
                        ExcludeTag             = @()
                        Line                   = @()
                        FullName               = @()
                    }
                    CodeCoverage = @{
                        Enabled                  = $false
                        OutputFormat             = 'JaCoCo'
                        OutputPath               = 'coverage.xml'
                        OutputEncoding           = 'UTF8'
                        Path                     = @()
                        ExcludeTests             = $true
                        RecursePaths             = $true
                        CoveragePercentTarget    = 75
                        SingleHitBreakpoints     = $true
                    }
                    #>
                    TestResult  = @{
                        Enabled                = $(if($SaveResultsToFile) { $true } else { $false })
                        OutputFormat           = 'NUnitXml'
                        OutputPath             = ('{0}\{1}\TestResults_{2}.xml' -f (Join-Path $PSScriptRoot "_PesterOutput"), $ModuleName, $TimestampString)
                        <#
                        OutputEncoding         = 'UTF8'
                        TestSuiteName          = 'Pester'
                        #>
                    }
                    Should     = @{
                        ErrorAction            = $(if($Force){ "Continue" } else { "Stop" }) 
                    }
                    Debug      = @{
                        ShowFullErrors         = $(if($DetailLevel -ge 2) { $true } else { $false })
                        WriteDebugMessages     = $(if($DetailLevel -ge 3) { $true } else { $false }) 
                        <#
                        ReturnRawResultObject  = $false
                        WriteDebugMessagesFrom = @('Discovery', 'Skip', 'Filter', 'Mock', 'CodeCoverage')
                        ShowNavigationMarkers  = $false
                        #>
                    }
                    Output     = @{
                        Verbosity              = $(
                                switch($DetailLevel){
                                    {$_ -le 0} {
                                        'None'
                                    }
                                    {1} {
                                        'Normal'
                                    }
                                    {$_ -in @(2, 3)} {
                                        'Detailed'
                                    }
                                    {$_ -ge 4} {
                                        'Diagnostic'
                                    }
                                    default{
                                        throw "Could not determine Verbosity based on provided DetailLevel. [$DetailLevel]"
                                    }
                                }
                            )
                    }
                }
            #endregion
            return $PesterRuntimeConfig
        } else {
            return $null
        }
    }
#endregion 

Push-Location -Path $PSScriptRoot
if(Import-Pester){
    $UnitTestFileList | ForEach-Object {
        $PesterConfig = New-PesterRuntimeConfig -Path $_ -SaveResultsToFile -DetailLevel 2 -PassThru
        if($null -ne $PesterConfig){
            Write-Host "*Running pester tests from [" -NoNewLine; Write-Host $_ -ForegroundColor Blue -NoNewLine; Write-host "]";
            
            # Creates Global variable equal to $ModuleInfo to make it available during discovery 
            # (allows variable to be used in "Describe", "Context" and "It" declarations)
            $global:ModuleInfo = $PesterConfig.Run.Container.Value.Data["ModuleInfo"]
            
            # Change directory to Module directory
            Push-Location -Path $ModuleInfo.Directory
            
            # Run tests
            $Results = Invoke-Pester -Configuration $PesterConfig

            # Display details
            if($Results.Passed.Count -gt 0){
                Write-Host "  |-" -NoNewline; Write-Host "Passed Tests:" -ForegroundColor Green;
                $Results.Passed | ForEach-Object {
                    Write-Host "  |  |-" -NoNewline; Write-Host $_ -ForegroundColor Green;
                }
                Write-Host ("  |  \") 
            }
            if(($Results.Result -ne "Passed") -and ($Results.Failed.Count -gt 0)){
                Write-Host "  |-" -NoNewline; Write-Host "Failed Tests:" -ForegroundColor Red;
                $Results.Failed | ForEach-Object {
                    Write-Host "  |  |-" -NoNewline; Write-Host $_ -ForegroundColor Red;
                }
                Write-Host ("  |  \")
            }
            Write-Host "  \"

            # Clean up global variable
            Remove-Variable -Scope Global -Name "ModuleInfo"

            # Change directory back to local script directory
            Pop-Location
        }
    }
}
Pop-Location