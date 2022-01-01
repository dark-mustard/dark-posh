# DarkPoSh.BuildTools
#region Custom Functions
    #region Certificates and Signing
        function New-DarkCertificate{
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $CN,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string[]]
                    $SAN,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [String]
                    $TemplateName,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $CAName,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [switch]
                    $Export,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [ValidateScript( {Resolve-Path -Path $_})]
                [string]
                    $ExportPath,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $Country,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $State,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $City,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $Organisation,
                [Parameter(Mandatory = $False, ValueFromPipelineByPropertyName = $True)]
                [string]
                    $Department
            )
            BEGIN {
                function Remove-ReqTempfiles() {
                    param(
                        [String[]]$tempfiles
                    )
                    Write-Verbose "Cleanup temp files..."
                    Remove-Item -Path $tempfiles -Force -ErrorAction SilentlyContinue
                }
                
                function Remove-ReqFromStore {
                    param(
                        [String]$CN
                    )
                    Write-Verbose "Remove pending certificate request form cert store..."
    
                    #delete pending request (if a request exists for the CN)
                    $certstore = new-object system.security.cryptography.x509certificates.x509Store('REQUEST', 'LocalMachine')
                    $certstore.Open('ReadWrite')
                    ForEach-Object ($certreq -in $($certstore.Certificates)) {
                        if ($certreq.Subject -eq "CN=$CN") {
                            $certstore.Remove($certreq)
                        }
                    }
                    $certstore.close()
                }

            }
            PROCESS{
                #disable debug confirmation messages
                if ($PSBoundParameters['Debug']) {$DebugPreference = "Continue"}

                Write-Verbose "Generating request inf file"
                $file  = ("{1}{0}" -f [Environment]::NewLine, '[NewRequest]')
                $file += ("{1}{0}" -f [Environment]::NewLine, ('Subject = "CN=$CN,c={0}, s={1}, l={2}, o={3}, ou={4}"' -f $Country, $State, $City, $Organisation, $Department))
                $file += ("{1}{0}" -f [Environment]::NewLine, 'MachineKeySet = TRUE')
                $file += ("{1}{0}" -f [Environment]::NewLine, 'KeyLength = 2048')
                $file += ("{1}{0}" -f [Environment]::NewLine, 'KeySpec=1')
                $file += ("{1}{0}" -f [Environment]::NewLine, 'Exportable = TRUE')
                $file += ("{1}{0}" -f [Environment]::NewLine, 'RequestType = PKCS10')
                $file += ("{1}{0}" -f [Environment]::NewLine, 'ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"')
                $file += ("{1}{0}" -f [Environment]::NewLine, '[RequestAttributes]')
                $file += ("{1}{0}" -f [Environment]::NewLine, ('CertificateTemplate = "{0}"' -f $TemplateName))

                #check if SAN certificate is requested
                if ($PSBoundParameters.ContainsKey('SAN')) {
                    #each SAN must be a array element
                    #if the array has ony one element then split it on the commas.
                    if (($SAN).count -eq 1) {
                        $SAN = @($SAN -split ',')

                        Write-Host "Requesting SAN certificate with subject $CN and SAN: $($SAN -join ',')" -ForegroundColor Green
                        Write-Debug "Parameter values: CN = $CN, TemplateName = $TemplateName, CAName = $CAName, SAN = $($SAN -join ' ')"
                    }

                    Write-Verbose "A value for the SAN is specified. Requesting a SAN certificate."
                    Write-Debug "Add Extension for SAN to the inf file..."
                    $file += ("{1}{0}" -f [Environment]::NewLine, '[Extensions]')
                    $file += ("{1}{0}" -f [Environment]::NewLine, '; If your client operating system is Windows Server 2008, Windows Server 2008 R2, Windows Vista, or Windows 7')
                    $file += ("{1}{0}" -f [Environment]::NewLine, '; SANs can be included in the Extensions section by using the following text format. Note 2.5.29.17 is the OID for a SAN extension.')
                    #$file += ("{1}{0}" -f [Environment]::NewLine, '')
                    $file += ("{1}{0}" -f [Environment]::NewLine, '2.5.29.17 = "{text}"')
                    #$file += ("{1}{0}" -f [Environment]::NewLine, '')

                    ForEach-Object ($an -in $SAN) {
                        $file += "_continue_ = `"$($an)&`"`n"
                    }
                } else {
                    Write-Host "Requesting certificate with subject $CN" -ForegroundColor Green
                    Write-Debug "Parameter values: CN = $CN, TemplateName = $TemplateName, CAName = $CAName"
                }

                try	{
                    #create temp files
                    $inf = [System.IO.Path]::GetTempFileName()
                    $req = [System.IO.Path]::GetTempFileName()
                    $cer = Join-Path -Path $env:TEMP -ChildPath "$CN.cer"
                    $rsp = Join-Path -Path $env:TEMP -ChildPath "$CN.rsp"

                    Remove-ReqTempfiles -tempfiles $inf, $req, $cer, $rsp
                    #create new request inf file
                    Set-Content -Path $inf -Value $file

                    #show inf file if -verbose is used
                    Get-Content -Path $inf | Write-Verbose

                    Write-Verbose "generate .req file with certreq.exe"
                    Invoke-Expression -Command "certreq -new `"$inf`" `"$req`""
                    if (!($LastExitCode -eq 0)) {
                        throw "certreq -new command failed"
                    }

                    write-verbose "Sending certificate request to CA"
                    Write-Debug "CAName = $CAName"

                    if (!$PSBoundParameters.ContainsKey('CAName')) {
                        $rootDSE = [System.DirectoryServices.DirectoryEntry]'LDAP://RootDSE'
                        $searchBase = [System.DirectoryServices.DirectoryEntry]"LDAP://$($rootDSE.configurationNamingContext)"
                        $CAs = [System.DirectoryServices.DirectorySearcher]::new($searchBase,'objectClass=pKIEnrollmentService').FindAll()

                        if($CAs.Count -eq 1){
                            $CAName = "$($CAs[0].Properties.dnshostname)\$($CAs[0].Properties.cn)"
                        }
                        else {
                            $CAName = ""
                        }
                    }

                    if (!$CAName -eq "") {
                        $CAName = " -config `"$CAName`""
                    }

                    Write-Debug "certreq -submit$CAName `"$req`" `"$cer`""
                    Invoke-Expression -Command "certreq -submit$CAName `"$req`" `"$cer`""

                    if (!($LastExitCode -eq 0)) {
                        throw "certreq -submit command failed"
                    }
                    Write-Debug "request was successful. Result was saved to `"$cer`""

                    write-verbose "retrieve and install the certificate"
                    Invoke-Expression -Command "certreq -accept `"$cer`""

                    if (!($LastExitCode -eq 0)) {
                        throw "certreq -accept command failed"
                    }

                    if (($LastExitCode -eq 0) -and ($? -eq $true)) {
                        Write-Host "Certificate request successfully finished!" -ForegroundColor Green
                    } else {
                        throw "Request failed with unknown error. Try with -verbose -debug parameter"
                    }


                    if ($export) {
                        Write-Debug "export parameter is set. => export certificate"
                        Write-Verbose "exporting certificate and private key"
                        $cert = Get-Childitem "cert:\LocalMachine\My" | where-object {$_.Thumbprint -eq (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Get-Item $cer).FullName, "")).Thumbprint}
                        Write-Debug "Certificate found in computerstore: $cert"

                        #create a pfx export as a byte array
                        $certbytes = $cert.export([System.Security.Cryptography.X509Certificates.X509ContentType]::pfx)

                        #write pfx file
                        if ($PSBoundParameters.ContainsKey('ExportPath')) {
                            $pfxPath = Join-Path -Path (Resolve-Path -Path $ExportPath) -ChildPath "$CN.pfx"
                        } else {
                            $pfxPath = ".\$CN.pfx"
                        }
                        $certbytes | Set-Content -Encoding Byte -Path $pfxPath -ea Stop
                        Write-Host "Certificate successfully exported to `"$pfxPath`"!" -ForegroundColor Green

                        Write-Verbose "deleting exported certificate from computer store"
                        # delete certificate from computer store
                        $certstore = new-object system.security.cryptography.x509certificates.x509Store('My', 'LocalMachine')
                        $certstore.Open('ReadWrite')
                        $certstore.Remove($cert)
                        $certstore.close()

                    }
                    else {
                        Write-Debug "export parameter is not set. => script finished"
                        Write-Host "The certificate with the subject $CN is now installed in the computer store !" -ForegroundColor Green
                    }
                }
                catch {
                    #show error message (non terminating error so that the rest of the pipeline input get processed)
                    Write-Error $_
                }
                finally {
                    #tempfiles and request cleanup
                    Remove-ReqTempfiles -tempfiles $inf, $req, $cer, $rsp
                    Remove-ReqFromStore -CN $CN
                }
            }
            END{
                Remove-ReqTempfiles -tempfiles $inf, $req, $cer, $rsp
            }
        }
        function Get-DarkCertificate {
            [CmdletBinding()]
            param(

            )
            $Return = $null
            $CurrentDate = Get-Date
            $CodeSigningCerts = @((dir Cert:\CurrentUser\My -CodeSigningCert) | Where { ($_.NotBefore -le $CurrentDate) -and ($_.NotAfter -ge $CurrentDate) } | Sort NotAfter -Descending)
            if($CodeSigningCerts.Count -gt 0){
                $Return = $CodeSigningCerts[0]
            }
            return $Return
        }
        function Set-DarkScriptSignature{
            [Alias('dpSet-ScriptSignature', 'Set-DPScriptSignature', 'dpSign-Script')]
            [CmdletBinding()]
            param(
                [Parameter(ParameterSetName="Default")]
                [String]
                [ValidateNotNullOrEmpty()]
                    $CAName,
                [Parameter(ParameterSetName="Default")]
                [String]
                [ValidateNotNullOrEmpty()]
                    $TemplateName
            )
            $CodeSigningCert=Get-DarkCertificate
            if(-Not $CodeSigningCert) {
                $cn=$CAName.Split("\")[0]
                $CodeSigningCert=New-DarkCertificate -CN "$cn" -CAName "$CAName" -TemplateName $TemplateName
            }
            if($CodeSigningCert) {
                Write-Debug "[Code Signing Cert] $($CodeSigningCert.Thumbprint)"
                Get-ChildItem . -Recurse -Filter *.ps1 | Select-Object FullName | ForEach-Object {
                    Write-Debug "[Script] $($_.FullName)"
                    Set-AuthenticodeSignature "$($_.FullName)" -Certificate $CodeSigningCert | ft -AutoSize
                }
                Get-ChildItem . -Recurse -Filter *.psm1 | Select-Object FullName | ForEach-Object {
                    Write-Debug "[Module] $($_.FullName)"
                    Set-AuthenticodeSignature "$($_.FullName)" -Certificate $CodeSigningCert | ft -AutoSize
                }
                <#
                Get-ChildItem . -Recurse -Filter *.psd1 | Select-Object FullName | ForEach-Object {
                    Write-Debug "[Manifest] $($_.FullName)"
                    Set-AuthenticodeSignature "$($_.FullName)" -Certificate $CodeSigningCert | ft -AutoSize
                }
                #>
            }
        }
        function Backup-DarkScript{
            throw "Not implemented."
        }
        function Update-DarkScriptVersion{
            throw "Not implemented"
            <#
            param(
                $RootDirectory=$PSScriptRoot
            )
            $PreviousVersionDirectory="Versions"
            #$FileNames=Get-ChildItem $RootDirectory -Recurse -Exclude ("*{0}\*" -f $PreviousVersionDirectory) -Include *.ps1 | Select-Object FullName
            $FileNames=Get-ChildItem $RootDirectory -Recurse -Filter *.ps1 | Where { $_.FullName -notlike ("*{0}\*" -f $PreviousVersionDirectory) } | Select-Object FullName
            Write-Debug "FileCount: $($FileNames.Count)"
            $FileNames | ForEach-Object {
                Write-Debug " |-[Script] $($_.FullName)"
                
                # Check for "Previous Versions" folder

            }
            Write-Debug " \"
            #>
        }
        function New-DarkHelpFile{
            param(
                [String]$SourceFile
            )
            throw "Not implemented"
            <#    
            function Get-ImportedModules{
                param(
                    [String]$ModulePath,
                    [String]$ModuleName
                )
                return @(Get-Module -Name $ModuleName | Where { $_.Path -eq $ModulePath })
            }
            #>
            #etpImport-Module -ModuleName 
            #$ModuleInfo = Get-Module $Module -ListAvailable
            <#    
            if($null -ne $ModuleInfo){
                # Imports module if not currently imported
                #$ImportedModuleList = @(Get-Module -Name $ModuleInfo.Name | Where { $_.Path -eq $ModuleInfo.Path })
                #if($ImportedModuleList -gt 1){
                #    Remove-Module -Name $ModuleInfo.Name
                #}
        
                #if($ImportedModuleList.Count -eq 0){
                #    Import-Module $ModuleInfo.Path -Force
                #} else
        
                #$OutputFolder = Join-Path $ModuleInfo.ModuleBase "docs"
                $OutputFolder = ".\docs"
                $parameters = @{
                    Module = $Module
                    OutputFolder = $OutputFolder
                    AlphabeticParamsOrder = $true
                    WithModulePage = $true
                    ExcludeDontShow = $true
                    Encoding = 'UTF8BOM'
                }
        
                New-MarkdownHelp @parameters
                New-MarkdownAboutHelp -OutputFolder $OutputFolder -AboutName "topic_name"
            } else {
                throw "Module not available. [$Module]"
            }
            #>
            #$FileInfo = Get-Item $Module
            <#
            $CopyElements = @(
                "NAME"
                "SYNOPSIS"
                "DESCRIPTION"
                "SYNTAX"
                #"PARAMETERS"
                #"EXAMPLES"
                #"RETURNVALUES"
                #"INPUTTYPES"
            )
            $Help = Get-Help $SourceFile #-Full
            #$Help.PSObject.Properties.Name
            $Help.PSObject.Properties | Where { $_.Name.ToUpper() -in $CopyElements } | %{
                $Property = $_
                #Write-Host ("{0}: [{1}]" -f $Property.Name, $Property.Value)
                #$Property.Name = $Property.Name.ToUpper()
                switch($Property.Name){
                    "NAME" {
                        if($Property.Value -like "*\*"){
                            $Property.Value = Split-Path $Property.Value -Leaf
                        }
                        if($Property.Value -like "*.ps*"){
                            $Property.Value = $Property.Value.Substring(0, $Property.Value.LastIndexOf(".ps"))
                        }
                        if($Property.Value -like "*.*"){
                            $Property.Value = $Property.Value.Replace(".", "_")
                        }
                    }
                    default{
                        # Do Nothing
                    }
                }
        
                $Property
            } | FL *
            #>
        }
        function Update-DarkHelpFile{
            param(
                [String]$Module
            )
            throw "Not implemented."
        }
    #endregion
#endregion
#region Module Events
    <#
    $ExecutionContext.SessionState.Module.OnRemove = {

    }
    #>
#endregion