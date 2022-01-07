# DarkPoSh.BuildTools
#region Local Module Management
    #region Module Functions
        function _Initialize-Module{
            throw "Not implemented."
        }
        function _Dispose-Module{
            throw "Not implemented."
        }
        function _Handle-Exception{
            [CmdletBinding()]
            #[Alias('')]
            param(
                [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
                [Object]
                    $Message,
                [Parameter(ValueFromPipelineByPropertyName)]
                [object]
                    $AdditionalData,
                [Parameter(ValueFromPipelineByPropertyName)]
                [Switch]
                    $Throw
            )
            $ErrorObject  = $null

            switch ($Message.GetType().Name ) {
                "String" {
                    #$ErrorObject = [ModuleException]::Create($Message, $CallStack, $LastFunction, $AdditionalData)
                    try { $Message } catch { $ErrorObject = $_ }
                }
                "ErrorRecord" {
                    $ErrorObject = $Message
                }
                default { 
                    throw ("Unhandled parameter set encountered. {0} 'Function':'{2}', 'ParameterSetName':'{3}' {1}" -f "[", "}", $MyInvocation.MyCommand.Name, $PsCmdlet.ParameterSetName)
                }
            }

            if($null -ne $ErrorObject){
                # Add to session info object
                $script:ModuleInfo.Errors+=,$ErrorObject

                # Throw? or just Display?
                if($Throw){
                    throw $ErrorObject
                } else {
                    $MessageLineArray = @(
                        ("The following exception was encountered:")
                        $Indent=" ! "
                        ("{0}{1} : {2}" -f $Indent, $ErrorObject.InvocationInfo.InvocationName, $ErrorObject.Exception.Message)
                        @($ErrorObject.InvocationInfo.PositionMessage.Split([Environment]::NewLine).Where({ -Not [String]::IsNullOrWhiteSpace($_) })) | ForEach-Object{
                            ("{0}{1}" -f $Indent, $_)
                        }
                        ("{0}    + CategoryInfo          : {1}" -f $Indent, $ErrorObject.CategoryInfo.ToString())
                        ("{0}    + FullyQualifiedErrorId : {1}" -f $Indent, $ErrorObject.FullyQualifiedErrorId.ToString())
                    )
                    $MessageLineArray | ForEach-Object {
                        Write-Error ($MessageLineArray -join [Environment]::NewLine)
                    }
                }
            }
        }
    #endregion
    #region Module Events
        $ExecutionContext.SessionState.Module.OnRemove = {
            _Dispose-Module
        }
    #endregion
#endregion
#region Custom Functions
    #region Certificates and Signing
        function New-EncryptionCert{
            throw "Not implemented. [Get-EncryptionCert]"
        }
        function New-SelfSignedDocCert{
            param()
            # https://4sysops.com/archives/create-a-certificate-request-file-with-alias-support-using-a-powershell-script/
            # https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/protect-cmsmessage?view=powershell-7.2#examples
            #$User                = $env:username
            $User                = ([ADSI]"LDAP://<SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>").UserPrincipalName
            #-------------
            $KeyLength           = 3072
            $HashAlgorithm       = 'Sha256'
            $ValidityPeriod      = 'Years'
            $ValidityPeriodUnits = "1000"
            #-------------
            $TimeStamp           = Get-Date
            $TimeStampString     = $TimeStamp.ToString("yyyyMMddHHmmss")
            #-------------
            #$TMPFileName         = [System.IO.Path]::GetTempFileName()
            $WorkingDirectory    = "{0}\etp\auth\{1}" -f $env:tmp, $TimeStampString
            $FileNameBase        = "DocCert_{0}_{1}" -f $User, $TimeStampString
            $InfoFileName        = "{0}.inf" -f $FileNameBase
            $CertFileName        = "{0}.cer" -f $FileNameBase
        
        
            #$ValidStartTime
            #$ExpirationTime
        
            #Write-Host "Working Directory:  [$WorkingDirectory]"
            #------------------------------------------
            if(-Not (Test-Path -Path $WorkingDirectory)){
                New-Item -ItemType Directory -Path $WorkingDirectory
            }
            Push-Location $WorkingDirectory
        
            try{
                New-SelfSignedCertificate -Type DocumentEncryptionCert -Subject "cn=$User" -HashAlgorithm $HashAlgorithm -KeyLength $KeyLength -NotBefore $ValidStartTime -NotAfter $ExpirationTime
                #region The shitty way
                        <#
                        $CertInfoFileContents = @'
        [Version]
        Signature = '$Windows NT$'
        
        [Strings]
        szOID_ENHANCED_KEY_USAGE = '2.5.29.37'
        szOID_DOCUMENT_ENCRYPTION = '1.3.6.1.4.1.311.80.1'
        
        [NewRequest]
        Subject = 'cn=$UserPrincipalName'
        MachineKeySet = false
        KeyLength = $KeyLength
        KeySpec = AT_KEYEXCHANGE
        HashAlgorithm = $HashAlgorithm
        Exportable = true
        RequestType = Cert
        KeyUsage = 'CERT_KEY_ENCIPHERMENT_KEY_USAGE | CERT_DATA_ENCIPHERMENT_KEY_USAGE'
        ValidityPeriod = $ValidityPeriod
        ValidityPeriodUnits = $ValidityPeriodUnits
        
        [Extensions]
        %szOID_ENHANCED_KEY_USAGE% = "{text}%szOID_DOCUMENT_ENCRYPTION%"
        '@
        
                        $CertInfoFileContents | Out-File -FilePath $InfoFileName
        
                        # After you have created your certificate file, run the following command to add
                        # the certificate file to the certificate store. Now you are ready to encrypt and
                        # decrypt content with the next two examples.  
        & certreq.exe -new $InfoFileName $CertFileName
                #>
                #endregion
                #region Domain Certificate Way...
                    <#
                    hidden [System.String] GetEncryptionCert() {
                        $CertDNSName = "$($env:COMPUTERNAME)"
                        $CertPath = "Cert:\CurrentUser\My"
                        $CertSubject = $null
                        $Cert = (Get-Childitem -Path $CertPath | Select Thumbprint,SerialNumber,Subject,NotAfter,NotBefore,EnhancedKeyUsageList) | Where { (($_.EnhancedKeyUsageList | Select FriendlyName).FriendlyName) -contains "Document Encryption" }
                        $CertSubject = $Cert.Subject
                        if (-Not $Cert) {
                            if((Get-WMIObject win32_operatingsystem).Name -like '*Windows Server 2012*') {
                                #region Generate certificate
                                    $ExtensionsToAdd = @()
                                    # Get Subject
                                        $filter="(&(objectCategory=computer)(objectClass=computer)(cn=$($env:COMPUTERNAME)))"
                                        $Subject = ([adsisearcher]$filter).FindOne().Properties.distinguishedname
                                        $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
                                        $SubjectDN.Encode($Subject, 0x0)
                                    # Get Enhanced Key Usage
                                        $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
                                        $OID = New-Object -ComObject X509Enrollment.CObjectID
                                        $OID.InitializeFromValue("Document Encryption")
                                        # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
                                        $OIDs.Add($OID)
                                        $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
                                        $EKU.InitializeEncode($OIDs)
                                        $ExtensionsToAdd += "EKU"
                                    # Get Key Usage
                                        $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
                                        $KU.InitializeEncode([int]([Security.Cryptography.X509Certificates.X509KeyUsageFlags]"KeyEncipherment,DataEncipherment,KeyAgreement"))
                                        $KU.Critical = $true
                                        $ExtensionsToAdd += "KU"
                                    # Generate Private Key
                                        # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
                                        $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
                                        $PrivateKey.ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
                                        $AlgID = New-Object -ComObject X509Enrollment.CObjectId
                                        $AlgID.InitializeFromValue(([Security.Cryptography.Oid]"RSA").Value)
                                        $PrivateKey.Algorithm = $AlgID
                                        # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
                                        $PrivateKey.KeySpec = 1
                                        $PrivateKey.Length = 2048
                                        # key will be stored in current user certificate store
                                        $PrivateKey.MachineContext = $false
                                        $PrivateKey.ExportPolicy = 0
                                        $PrivateKey.Create()
                                    # Create Certificate
                                        # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
                                        $CertReq = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
                                        $CertReq.InitializeFromPrivateKey(0x1,$PrivateKey,"")
                                        $CertReq.Subject = $SubjectDN
                                        $CertReq.Issuer = $CertReq.Subject
                                        $CertReq.NotBefore = [DateTime]::Now.AddDays(-1)
                                        $CertReq.NotAfter = [DateTime]::Now.AddDays(364)
                                        foreach ($item in $ExtensionsToAdd) {$CertReq.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
                                        $SigOID = New-Object -ComObject X509Enrollment.CObjectId
                                        $SigOID.InitializeFromValue(([Security.Cryptography.Oid]"SHA256").Value)
                                        $CertReq.SignatureInformation.HashAlgorithm = $SigOID
                                        # completing certificate request template building
                                        $CertReq.Encode()
            
                                        # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
                                        $Request = New-Object -ComObject X509Enrollment.CX509enrollment
                                        $Request.InitializeFromRequest($CertReq)
                                        $Request.CertificateFriendlyName = ""
                                        $endCert = $Request.CreateRequest(0x1)
                                        $Request.InstallResponse(0x2,$endCert,0x1,"")
                                        [Byte[]]$CertBytes = [Convert]::FromBase64String($endCert)
                                        $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,$CertBytes)
                                #endregion
                                $CertSubject = $Cert.Subject
                            } else {
                                $Cert = New-SelfSignedCertificate -DnsName $CertDNSName -CertStoreLocation $CertPath -KeyUsage KeyEncipherment,DataEncipherment,KeyAgreement -Type DocumentEncryptionCert
                                $CertSubject = $Cert.Subject
                            }
                        }
                        return $Cert.Subject
                    }
                    #>
                #endregion
            } catch { 
                $_
            } finally {
                Write-Host "Working Directory:  [$WorkingDirectory]"
                Pop-Location
            }
        }
        
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
    #endregion
    #region Version Control / Backup
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
    #endregion
    #region Config File MGMT
        <#
        hidden [void] DumpToFile($FilePath, $Content) {
            $FileDir = Split-Path $FilePath
            if (!(Test-Path $FileDir)) {
                New-Item -Path $FileDir -ItemType Directory -Force
            }
            $EncryptionCert = $this.GetEncryptionCert()
            $ContentType = $Content.GetType()
            Switch ($ContentType) {
                pscredential { 
                    $Content | Export-CliXml -Path "$FilePath.tmp"
                    Get-Content -Path "$FilePath.tmp" | Protect-CmsMessage -To $EncryptionCert -OutFile $FilePath
                    Remove-Item -Path "$FilePath.tmp" -Force
                }
                default { 
                    $Content | Protect-CmsMessage -To $EncryptionCert -OutFile $FilePath 
                }
            }
        }
        hidden [void] LoadCachedCredentials() {
            [System.Management.Automation.PSCredential] $Creds = $null
            $FileName = $this.CredsCachePath
            if(Test-Path $FileName){
                $FileNameTemp = "$FileName.tmp"
                try{
                    Unprotect-CmsMessage -Path $FileName | Out-File $FileNameTemp
                    $this.APICreds = Import-CliXml -Path $FileNameTemp
                    Write-Debug "[Loaded cached credentials]"
                } catch {
                    $_
                } finally {
                    if (Test-Path $FileNameTemp) {
                        #Write-Host "Delete temp file. [$FileNameTemp]"
                        Remove-Item -Path $FileNameTemp -Force
                    }
                }
            } else {
                $this.RequestAPICreds()
            }
        }
        #>
        function New-SettingsFile{
            param(
                [String]$OutputFilePath,
                [Switch]$Encrypt
            )

            $ScriptSettings=[PSCustomObject]@{
                AppName = $null
                ADSyncTargets = @{}
                Exclusions = @()
            }

            #region Sub-functions
                function Get-ParamValue{
                    param(
                        [String]$Prefix = "",
                        [String]$ParamName,
                        [Switch]$Required
                    )
                    $ParamValue = Read-Host -Prompt ("{0}[{1}]" -f $Prefix, $ParamName)
                    if($Required -and [String]::IsNullOrWhiteSpace($ParamValue)){
                        Write-Host "** This value is required - please try again. **" -ForegroundColor Red
                        $ParamValue = Get-ParamValue $ParamName -Required:$Required
                    }
                    return $ParamValue
                }
                function Get-ParamArray{
                    param(
                        [String]$Prefix = "",
                        [String]$ParamName,
                        [Int32]$MinCountRequired = 0
                    )
                    $Continue = $true
                    $Values=@()
                    while($Continue) {
                        $ParamValue = Read-Host -Prompt ("{0}[{1}({2})]" -f $Prefix, $ParamName, $Values.Count)
                        if([String]::IsNullOrWhiteSpace($ParamValue)){
                            if($Values.Count -lt $MinCountRequired){
                                # REPROMPT
                                Write-Host ("** At least {0} value{1} required - please try again. **" -f $MinCountRequired, $(if($MinCountRequired -gt 1){ "s are" } else { " is" })) -ForegroundColor Red
                                $Values=Get-ParamArray -Prefix $Prefix -ParamName $ParamName -MinCountRequired:$MinCountRequired
                                $Continue = $false
                            } else {
                                # FINISHED
                                $Continue = $false
                            }
                        } else {
                            $Values += $ParamValue
                        }
                    } 
                    return $Values
                }
            #endregion

            Write-Host "###############################"
            Write-Host "## " -NoNewline; Write-Host "Application Sync Settings" -ForegroundColor Green -NoNewline;
            Write-Host "###############################"
            #---------------
            Write-Host "# Specify application name and choose a path to save output file. " 
            # Prompt for $AppName if invalid / not specified
            $ScriptSettings.AppName = Get-ParamValue -Prefix "#   |-" -ParamName "AppName" -Required
            # Prompt for destination path if invalid / not specified
            if([String]::IsNullOrWhiteSpace($OutputFilePath)){
                #Write-Host "# Please provide the desired output file path."
                $SaveChooser = New-Object -Typename System.Windows.Forms.SaveFileDialog
                $SaveChooser.InitialDirectory = $PSScriptRoot
                $SaveChooser.Filter = "Xml files (*.xml)|*.txt|All files (*.*)|*.*"
                $SaveChooser.ShowDialog()
                $OutputFilePath=$SaveChooser.Filename
                while([String]::IsNullOrWhiteSpace($OutputFilePath)){
                    Write-Host "** This value is required - please try again. **" -ForegroundColor Red
                    $SaveChooser.ShowDialog()
                    $OutputFilePath=$SaveChooser.Filename
                }
            }
            Write-Host "#   |-[Output Path]: $OutputFilePath"
            Write-Host "#   \"
            #---------
            <#
            Write-Host "# Specify ADSync TARGET group names to syncronize. " # -NoNewline
            $ADSyncTargetList = Get-ParamArray -Prefix "#   |-"  -ParamName "ADSyncTarget" -MinCountRequired 1
            Write-Host "#   \"
            $ADSyncTargetList | %{
                #----
                $ADSyncTargetName = $_
                $ADSyncTargetSettings = [PSCustomObject]@{
                    SyncMembersOf=@()
                    Exclusions=@()
                }
                Write-Host "# Specify ADSync SOURCE group names containg sync-users for [$ADSyncTargetName]"
                $ADSyncTargetSettings.SyncMembersOf = Get-ParamArray -Prefix "#   |-"   -ParamName "ADSyncSource" -MinCountRequired 1
                Write-Host "#   \"
                #-
                Write-Host "# Specify any exclusions specific to [$ADSyncTargetName]"
                $ADSyncTargetSettings.Exclusions = Get-ParamArray -Prefix "#   |-"   -ParamName "Exclusion" -MinCountRequired 0
                Write-Host "#   \"
                #----
                $AppSyncSettings.ADSyncTargets.Add($ADSyncTargetName, $ADSyncTargetSettings)
            }
            #---------
            Write-Host "# Add any EXCLUSIONS"
            $AppSyncSettings.Exclusions = Get-ParamArray -Prefix "#   |-" -ParamName "Exclusion"
            Write-Host "#   \"
            #---------------
            $AppSyncSettings | Export-Clixml -Path $OutputFilePath
            #>

            # If $Encrypt is specified, save initial export to a '.tmp' file
            $OutputFilePath_TMP = "{0}{1}" -f $OutputFilePath, $(if($Encrypt){ ".tmp" } )
            #--
            $ExportFile1 = if($Encrypt){ $OutputFilePath_TMP } else { $OutputFilePath }
            $ExportFile2 = "{0}.cms" -f $OutputFilePath.Substring(0, $OutputFilePath.LastIndexOf("."))
            #--
            # Dump settings to file
            $AppSettings | Export-Clixml -Path $ExportFile1
            # Encrypt, if specified and remove tmp files
            if($Encrypt){
                # Check for existing file encryption certificate
                Push-Location "Cert:\CurrentUser\My"
                $DocCerts = @(Get-ChildItem -DocumentEncryptionCert)
                Pop-Location
                if($DocCerts.Count -eq 0){
                    # Request new cert or renew existing
                    $EncryptionCert = New-EncryptionCert
                } else {
                    # Save the encrypted file without a file extension.
                    Get-Content -Path $ExportFile1 | Protect-CmsMessage -To $EncryptionCert -OutFile $ExportFile2
                    # Clean-up '.tmp' files.
                    Remove-Item -Path $ExportFile1 -Force
                }
            } 
        }        
        function Load-SettingsFile{
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNull()]
                [String]$SettingsFilePath
            )
            Write-Host "###############################"
            Write-Host "## " -NoNewline; Write-Host "Loading Application Sync Settings..." -ForegroundColor Green;
            Write-Host "###############################"
            #---------------
            #if(-Not (Test-Path $SettingsFilePath)){
            #    Write-Host "# Please provide the desired output file path."
                #Write-Host "# Please provide the desired output file path."
                #$LoadChooser = New-Object -Typename System.Windows.Forms.OpenFileDialog
                #$LoadChooser.InitialDirectory = $PSScriptRoot
                #$LoadChooser.Filter = "Xml files (*.xml)|*.txt|All files (*.*)|*.*"
                #$LoadChooser.ShowDialog()
                #$SettingsFilePath=$LoadChooser.Filename
                #while([String]::IsNullOrWhiteSpace($OutputFilePath)){
                #    Write-Host "** This value is required - please try again. **" -ForegroundColor Red
                #    $SaveChooser.ShowDialog()
                #    $OutputFilePath=$SaveChooser.Filename
                #}
            #}
            Protect-CmsMessage 
            $AppSyncSettings=Import-Clixml -Path $SettingsFilePath
            return $AppSyncSettings
        }
    #endregion
    #region Help Content MGMT
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
            #Import-DarkModule -ModuleName 
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
    function Archive-Results{
        param(
            [String]$Timestamp=(Get-Date).ToString("yyyyMMddHHmmss"),
            [String]$RootDirectory,
            [Hashtable]$IncludedContent,
            [Switch]$TestMode
        )
        $Success=$false
        $ReturnValue=$null
        try{
            $LRFileSuffix="LAST_RUN"
            $InstanceDirectory=Join-Path $RootDirectory $Timestamp
            if(-Not (Test-Path $InstanceDirectory)){
                New-Item -Path $InstanceDirectory -ItemType Directory -Force:$true -Confirm:$false | Out-Null
            }
            $ReturnValue=$InstanceDirectory

            $IncludedContent.Keys | %{

                $ItemName  = $_
                $ItemValue = $IncludedContent[$_]
                
                $FileName_LR=Join-Path $RootDirectory     ("{0}_{1}" -f $(if($TestMode){ "TEST_$($ItemName)" } else { $ItemName }), $LRFileSuffix)
                $FileName_TS=Join-Path $InstanceDirectory ("{0}_{1}" -f $(if($TestMode){ "TEST_$($ItemName)" } else { $ItemName }), $TargetGroupName.Replace(" ", "").Replace("_", ""))
                
                #    $CurrentValue=$DICT_ClassifierValues[$_]
                #    if(($null -ne $CurrentValue) -and $CurrentValue.Count -gt 0){
                #        #if(-Not $script:TestMode){
                #            # Overwrite the "LAST_RUN" file
                #            $CurrentValue | ConvertTo-Json -Depth 3 -Compress | Out-File ("{0}.{1}" -f $FileName_LR, 'json') -Encoding utf8 -Force:$true -Confirm:$false -WhatIf:($script:TestMode) #| Out-Null 
                #            #$CurrentValue | Export-Csv ("{0}.{1}" -f $FileName_LR, 'csv') -NoClobber -NoTypeInformation -Encoding ascii -Force:$true -Confirm:$false -WhatIf:($script:TestMode) | Out-Null 
                #        #}
                #        # Save results to a datestamped folder
                #        $CurrentValue | ConvertTo-Json -Depth 3 -Compress | Out-File ("{0}.{1}" -f $FileName_TS, 'json') -Encoding utf8 -Force:$true -Confirm:$false | Out-Null
                #        $CurrentValue | Export-Csv ("{0}.{1}" -f $FileName_TS, 'csv') -NoClobber -NoTypeInformation -Encoding utf8 -Force:$true -Confirm:$false | Out-Null 
                #    }
                #    $Success=$true

                $Success = $true

            }
        } catch {
            $Success = $false
            Write-Error $_
        }
        return $Success    
        #return $ReturnValue
    }
#endregion