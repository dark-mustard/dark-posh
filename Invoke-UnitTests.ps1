$UnitTestFileList=@(
    "$PSScriptRoot\DarkPoSh.Logging\DarkPoSh.Logging.Tests.ps1"
)

#region Custom Pester Functions
    function Import-Pester{
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

        # Skip process if module is already present
        if((Get-Module -Name $ModuleName | Where-Object { $_.Version -ne $IgnoreVersion }).Count -eq 0) {

            # Enable TLS 1.2 for current session
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            # Retrieve list of versions installed other than factory-shipped version.
            $ManuallyInstalledVersionList = @(
                    Get-Module -ListAvailable | 
                        Where-Object { $_.Name -eq $ModuleName -and $_.Version -ne $IgnoreVersion } | 
                            Sort-Object Version -Descending | 
                                Select-Object * -First 1
                )

            # Install / update depending on results.
            if($ManuallyInstalledVersionList.Count -eq 0){
                # No other versions found - install newest release in parallel
                Install-Module -Name $ModuleName -Force -SkipPublisherCheck
            } else {
                # Valid version found - update to latest
                $ManuallyInstalledVersionList[0] | Update-Module -Confirm
            }

            # Re-fetch latest installed version for import
            $ManuallyInstalledVersionList = @(
                    Get-Module -ListAvailable | 
                        Where-Object { $_.Name -eq $ModuleName -and $_.Version -ne $IgnoreVersion } | 
                            Sort-Object Version -Descending | 
                                Select-Object * -First 1
                )

            # Remove any other imported versions from current context
            Get-Module -Name $ModuleName | Where-Object { $_.Version -ne $ManuallyInstalledVersionList[0].Version } | Remove-Module -Force

            # Import specific module
            Import-Module -Name $ManuallyInstalledVersionList[0].Name -RequiredVersion $ManuallyInstalledVersionList[0].Version -Force

            # Declare function status a success
            $Success = $true
        } else {
            # Declare function status a success
            $Success = $true
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
                [Switch]$ObjectOutput
        )
        if(Test-Path $Path){
            #region Initialize parameters
                $PathInfo = Get-Item $Path
                #$PathInfo | FL *
                if($PathInfo.Attributes -contains "Directory"){
                    $TestSourceRootPath = $PathInfo.FullName
                    $TestSourceName   = (Split-Path $TestSourceRootPath -Leaf)
                } else {
                    $TestSourceRootPath = $PathInfo.Directory
                    $TestSourceName     = $PathInfo.BaseName
                }
                $TestFileSuffix = ".Tests"
                $ModuleName       = $TestSourceName.Replace($TestFileSuffix, "")
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
                        PassThru            = $(if($ObjectOutput) { $true } else { $false })
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
                        Enabled                = $(if($ObjectOutput) { $true } else { $false })
                        <#
                        OutputFormat           = 'NUnitXml'
                        OutputPath             = 'testResults.xml'
                        OutputEncoding         = 'UTF8'
                        TestSuiteName          = 'Pester'
                        #>
                    }
                    Should     = @{
                        ErrorAction            = "Continue" 
                    }
                    Debug      = @{
                        ShowFullErrors         = $(if($DetailLevel -ge 2) { $true } else { $false })
                        WriteDebugMessages     = $(if($DetailLevel -ge 3) { $true } else { $false }) 
                        <#
                        WriteDebugMessagesFrom = @('Discovery', 'Skip', 'Filter', 'Mock', 'CodeCoverage')
                        ShowNavigationMarkers  = $false
                        ReturnRawResultObject  = $false
                        #>
                    }
                    Output     = @{
                        Verbosity              = $(if($DetailLevel -ge 4) { 'Diagnostic' } elseif ($DetailLevel -eq 3) { 'Detailed' } elseif($DetailLevel -le 0) { 'None' } else { 'Normal' })
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
        $PesterConfig = New-PesterRuntimeConfig -Path $_ -DetailLevel 2
        if($null -ne $PesterConfig){
            Push-Location -Path (Split-Path $_)
            Invoke-Pester -Configuration $PesterConfig
            Pop-Location
        }
    }
}
Pop-Location