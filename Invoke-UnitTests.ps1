$UnitTestFileList=@(
    "$PSScriptRoot\GPoSh.logging\GPoSh.Logging.Tests.ps1"
)

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
    if((Get-Module -Name $ModuleName | Where { $_.Version -ne $IgnoreVersion }).Count -eq 0) {

        # Enable TLS 1.2 for current session
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Retrieve list of versions installed other than factory-shipped version.
        $ManuallyInstalledVersionList = @(
                Get-Module -ListAvailable | 
                    Where { $_.Name -eq $ModuleName -and $_.Version -ne $IgnoreVersion } | 
                        Sort Version -Descending | 
                            Select * -First 1
            )

        # Install / update depending on results.
        if($ManuallyInstalledVersionList.Count -eq 0){
            # No other versions found - install newest release in parallel
            Install-Module -Name Pester -Force -SkipPublisherCheck
        } else {
            # Valid version found - update to latest
            $ManuallyInstalledVersionList[0] | Update-Module
        }

        # Re-fetch latest installed version for import
        $ManuallyInstalledVersionList = @(
                Get-Module -ListAvailable | 
                    Where { $_.Name -eq $ModuleName -and $_.Version -ne $IgnoreVersion } | 
                        Sort Version -Descending | 
                            Select * -First 1
            )

        # Import specific module
        Import-Module -Name $ManuallyInstalledVersionList[0].Name -RequiredVersion $ManuallyInstalledVersionList[0].Version

        # Declare function status a success
        $Success = $true
    } else {
        # Declare function status a success
        $Success = $true
    }

    # Return function status
    return $Success
}
Push-Location $PSScriptRoot
if(Import-Pester){
    $UnitTestFileList | %{
        Invoke-Pester -Path $_
    }
}