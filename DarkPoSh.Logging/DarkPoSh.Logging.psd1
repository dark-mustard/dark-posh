# Reference:
#  -> https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-modulemanifest?view=powershell-7.1
@{

    #>Identifiers
    #  |-Guid: ID used to uniquely identify this module
        GUID = '56ee9538-16b0-488d-83e1-563f335a9233'
    #  |-ModuleVersion: Version number of this module.
        ModuleVersion = '1.0.2'
    #  |-Description: Description of the functionality provided by this module
        Description = 'Logging - Cmdlets for logging script runtime information.'
    #  |-Author: Author of this module
        Author = 'Greg Phillips (dark-mustard)'
    #  |-CompanyName: Company or vendor of this module
        CompanyName = ''
    #  |-Copyright: Copyright statement for this module
        Copyright = '(c) Greg Phillips. All rights reserved.'
    #  |-RootModule: Script module or binary module file associated with this manifest.
        RootModule = 'DarkPoSh.Logging.psm1'
    #  |-HelpInfoURI: HelpInfo URI of this module
        #HelpInfoURI = ''
    #  \

    #>Dependencies
    #  |-CompatiblePSEditions: Supported PSEditions
        CompatiblePSEditions = @( "Desktop" )
        #CompatiblePSEditions = @( "Core" )
        #CompatiblePSEditions = @( "Desktop", "Core" )
    #  |-PowerShellVersion: Minimum version of the Windows PowerShell engine required by this module
        PowerShellVersion = '5.0'
        #PowerShellVersion = '4.0'
        #PowerShellVersion = '3.0'
    #  |-PowerShellHostName: Name of the Windows PowerShell host required by this module
        #PowerShellHostName = ''
    #  |-PowerShellHostVersion: Minimum version of the Windows PowerShell host required by this module
        #PowerShellHostVersion = ''
    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
        #DotNetFrameworkVersion = '4.5.2'
    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
        #CLRVersion = '4.0'
    # Processor architecture (None, X86, Amd64) required by this module
        #ProcessorArchitecture = ''
    # Modules that must be imported into the global environment prior to importing this module
        #RequiredModules = @()
    # Assemblies that must be loaded prior to importing this module
        #RequiredAssemblies = '.\Microsoft.Azure.Management.Websites.dll', 
        #RequiredAssemblies = '.\Microsoft.Azure.Commands.Common.Strategies.3.dll'
    #  \

    #> Import Settings
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
        # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
        # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
        # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
        #NestedModules = @()
    
    #> Export Settings
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
        #FunctionsToExport = @()
        FunctionsToExport = @( 
            "Start-DarkSession"
            "Stop-DarkSession"
            "Write-DarkLog"
        )
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
        #CmdletsToExport = @(
        #    "Start-DarkSession"
        #    "Stop-DarkSession"
        #    "Write-DarkLog"
        #) 
    # Variables to export from this module
        #VariablesToExport = @()
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
        #AliasesToExport = 'Swap-AzureRmWebAppSlot'
    # DSC resources to export from this module
        # DscResourcesToExport = @()

    #>???
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
        #DefaultCommandPrefix = 'dposh'
    # List of all modules packaged with this module
        # ModuleList = @()
    # List of all files packaged with this module
        # FileList = @()
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
        <#PrivateData = @{
            PSData = @{
                # Tags applied to this module. These help with module discovery in online galleries.
                Tags = 'Azure','ResourceManager','ARM','Websites','Website','AppService'

                # A URL to the license for this module.
                LicenseUri = 'https://aka.ms/azps-license'

                # A URL to the main website for this project.
                ProjectUri = 'https://github.com/Azure/azure-powershell'

                # A URL to an icon representing this module.
                # IconUri = ''

                # ReleaseNotes of this module
                ReleaseNotes = '* Updated to the latest version of the Azure ClientRuntime'

                # Prerelease string of this module
                # Prerelease = ''

                # Flag to indicate whether the module requires explicit user acceptance for install/update
                # RequireLicenseAcceptance = $false

                # External dependent modules of this module
                # ExternalModuleDependencies = @()

            } # End of PSData hashtable
         } # End of PrivateData hashtable
         #>
}

