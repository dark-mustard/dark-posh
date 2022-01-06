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
    #region Helper Functions
        function _Get-RequiredParam{
            param(
                [String]$ParamName,
                [String]$ParamValue=$null
            )
            $Message="Please provide a string value for [$ParamName]:"
            if(-Not $ParamValue) {
                $ParamValue = Read-Host -Prompt $Message
            }
            return $ParamValue
        }
        function _Get-SecureString{
            param(
                [String]$TextString=$null,
                [String]$Message="Please provide a string value to encrypt"
            )
            if($TextString) {
                $secureString = ConvertTo-SecureString $TextString -AsPlainText -Force
            } else {
                $secureString = Read-Host -AsSecureString -Prompt $Message
            }
            $secureString
        }
        function _Encrypt-String{
            param(
                [String]$TextString=$null
            )
            $secureString = _Get-SecureString -TextString $TextString
            return (ConvertFrom-SecureString -SecureString $secureString)
        }
        function _Decrypt-String{
            param(
                [object]$EncryptedString=$null
            )
            if($null -ne $EncryptedString) {
                switch($EncryptedString.GetType().Name){
                    ("String"){
                        $secureString = ConvertTo-SecureString $EncryptedString
                    }
                    ("SecureString"){
                        $secureString = $EncryptedString
                        # DO NOTHING
                    }
                }
            } else {
                $secureString = Read-Host -AsSecureString -Prompt "Please provide a string value to decrypt"
            }
            return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
        }
    #endregion
#endregion
#region DarkPoSh.BuildTools
    #region Types and Enums
        
    #endregion
    #region Custom Functions
        function dpExport-MFT {
            <#
            .SYNOPSIS
                Extracts master file table from volume.
                Version: 0.1
                Author : Jesse Davis (@secabstraction)
                License: BSD 3-Clause
            .DESCRIPTION
                This module exports the master file table (MFT) and writes it to $env:TEMP.
                The object(s) output by this module specify the path of the written MFT file for retrieval via Copy-Item -Path \\NetworkPath\C$
            .PARAMETER ComputerName 
                Specify host(s) to retrieve data from.
            .PARAMETER ThrottleLimit 
                Specify maximum number of simultaneous connections.
            .PARAMETER Volume 
                Specify a volume to retrieve its master file table.
            .PARAMETER CSV 
                Specify path to output file, output is formatted as comma separated values.
            .EXAMPLE
                The following example extracts the master file table from the local system volume and writes it to TEMP.
                PS C:\> Export-MFT
            .EXAMPLE
                The following example extracts the master file table from the system volume of Server01 and writes it to TEMP.
                PS C:\> Export-MFT -ComputerName Server01
            .EXAMPLE
                The following example extracts the master file table from the F volume on Server01 and writes it to TEMP.
                PS C:\> Export-MFT -ComputerName Server01 -Volume F
            .NOTES
            .INPUTS
            .OUTPUTS
            .LINK
            #>
            [CmdLetBinding()]
            Param(
                [Parameter(Position = 0, ValueFromPipeline = $true)]
                [ValidateNotNullOrEmpty()]
                [String[]]$ComputerName,

                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [Int]$ThrottleLimit = 10,

                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [Char]$Volume = 0,

                [Parameter()]
                [ValidateNotNullOrEmpty()]
                [String]$CSV
            ) #End Param
        
            $ScriptTime = [Diagnostics.Stopwatch]::StartNew()

            $RemoteScriptBlock = {
                Param($Volume)

                if ($Volume -ne 0) { 
                    $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($Volume):'"
                    if ($Win32_Volume.FileSystem -ne "NTFS") { 
                        Write-Error "$Volume is not an NTFS filesystem."
                        break
                    }
                }
                else {
                    $Win32_Volume = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter LIKE '$($env:SystemDrive)'"
                    if ($Win32_Volume.FileSystem -ne "NTFS") { 
                        Write-Error "$env:SystemDrive is not an NTFS filesystem."
                        break
                    }
                }

                $OutputFilePath = $env:TEMP + "\$([IO.Path]::GetRandomFileName())"

                #region WinAPI

                $GENERIC_READWRITE = 0x80000000
                $FILE_SHARE_READWRITE = 0x02 -bor 0x01
                $OPEN_EXISTING = 0x03

                $DynAssembly = New-Object System.Reflection.AssemblyName('MFT')
                $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemory', $false)

                $TypeBuilder = $ModuleBuilder.DefineType('kernel32', 'Public, Class')
                $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
                $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
                    @('kernel32.dll'),
                    [Reflection.FieldInfo[]]@($SetLastError),
                    @($True))

                #CreateFile
                $PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CreateFile', 'kernel32.dll',
                    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                    [Reflection.CallingConventions]::Standard,
                    [IntPtr],
                    [Type[]]@([String], [Int32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]),
                    [Runtime.InteropServices.CallingConvention]::Winapi,
                    [Runtime.InteropServices.CharSet]::Ansi)
                $PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

                #CloseHandle
                $PInvokeMethodBuilder = $TypeBuilder.DefinePInvokeMethod('CloseHandle', 'kernel32.dll',
                    ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
                    [Reflection.CallingConventions]::Standard,
                    [Bool],
                    [Type[]]@([IntPtr]),
                    [Runtime.InteropServices.CallingConvention]::Winapi,
                    [Runtime.InteropServices.CharSet]::Auto)
                $PInvokeMethodBuilder.SetCustomAttribute($SetLastErrorCustomAttribute)

                $Kernel32 = $TypeBuilder.CreateType()

                #endregion WinAPI

                # Get handle to volume
                if ($Volume -ne 0) { $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $Volume + ':'), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero) }
                else { 
                    $VolumeHandle = $Kernel32::CreateFile(('\\.\' + $env:SystemDrive), $GENERIC_READWRITE, $FILE_SHARE_READWRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero) 
                    $Volume = ($env:SystemDrive).TrimEnd(':')
                }
        
                if ($VolumeHandle -eq -1) { 
                    Write-Error "Unable to obtain read handle for volume."
                    break 
                }         
        
                # Create a FileStream to read from the volume handle
                $FileStream = New-Object IO.FileStream($VolumeHandle, [IO.FileAccess]::Read)                   

                # Read VBR from volume
                $VolumeBootRecord = New-Object Byte[](512)                                                     
                if ($FileStream.Read($VolumeBootRecord, 0, $VolumeBootRecord.Length) -ne 512) { Write-Error "Error reading volume boot record." }

                # Parse MFT offset from VBR and set stream to its location
                $MftOffset = [Bitconverter]::ToInt32($VolumeBootRecord[0x30..0x37], 0) * 0x1000
                $FileStream.Position = $MftOffset

                # Read MFT's file record header
                $MftFileRecordHeader = New-Object byte[](48)
                if ($FileStream.Read($MftFileRecordHeader, 0, $MftFileRecordHeader.Length) -ne $MftFileRecordHeader.Length) { Write-Error "Error reading MFT file record header." }

                # Parse values from MFT's file record header
                $OffsetToAttributes = [Bitconverter]::ToInt16($MftFileRecordHeader[0x14..0x15], 0)
                $AttributesRealSize = [Bitconverter]::ToInt32($MftFileRecordHeader[0x18..0x21], 0)

                # Read MFT's full file record
                $MftFileRecord = New-Object byte[]($AttributesRealSize)
                $FileStream.Position = $MftOffset
                if ($FileStream.Read($MftFileRecord, 0, $MftFileRecord.Length) -ne $AttributesRealSize) { Write-Error "Error reading MFT file record." }
        
                # Parse MFT's attributes from file record
                $Attributes = New-object byte[]($AttributesRealSize - $OffsetToAttributes)
                [Array]::Copy($MftFileRecord, $OffsetToAttributes, $Attributes, 0, $Attributes.Length)
        
                # Find Data attribute
                $CurrentOffset = 0
                do {
                    $AttributeType = [Bitconverter]::ToInt32($Attributes[$CurrentOffset..$($CurrentOffset + 3)], 0)
                    $AttributeSize = [Bitconverter]::ToInt32($Attributes[$($CurrentOffset + 4)..$($CurrentOffset + 7)], 0)
                    $CurrentOffset += $AttributeSize
                } until ($AttributeType -eq 128)
        
                # Parse data attribute from all attributes
                $DataAttribute = $Attributes[$($CurrentOffset - $AttributeSize)..$($CurrentOffset - 1)]

                # Parse MFT size from data attribute
                $MftSize = [Bitconverter]::ToUInt64($DataAttribute[0x30..0x37], 0)
        
                # Parse data runs from data attribute
                $OffsetToDataRuns = [Bitconverter]::ToInt16($DataAttribute[0x20..0x21], 0)        
                $DataRuns = $DataAttribute[$OffsetToDataRuns..$($DataAttribute.Length -1)]
        
                # Convert data run info to string[] for calculations
                $DataRunStrings = ([Bitconverter]::ToString($DataRuns)).Split('-')
        
                # Setup to read MFT
                $FileStreamOffset = 0
                $DataRunStringsOffset = 0        
                $TotalBytesWritten = 0
                $MftData = New-Object byte[](0x1000)
                $OutputFileStream = [IO.File]::OpenWrite($OutputFilePath)

                do {
                    $StartBytes = [int]($DataRunStrings[$DataRunStringsOffset][0]).ToString()
                    $LengthBytes = [int]($DataRunStrings[$DataRunStringsOffset][1]).ToString()
            
                    $DataRunStart = "0x"
                    for ($i = $StartBytes; $i -gt 0; $i--) { $DataRunStart += $DataRunStrings[($DataRunStringsOffset + $LengthBytes + $i)] }

                    $DataRunLength = "0x"
                    for ($i = $LengthBytes; $i -gt 0; $i--) { $DataRunLength += $DataRunStrings[($DataRunStringsOffset + $i)] }

                    $FileStreamOffset += ([int]$DataRunStart * 0x1000)
                    $FileStream.Position = $FileStreamOffset           

                    for ($i = 0; $i -lt [int]$DataRunLength; $i++) {
                        if ($FileStream.Read($MftData, 0, $MftData.Length) -ne $MftData.Length) { 
                            Write-Warning "Possible error reading MFT data on $env:COMPUTERNAME." 
                        }
                        $OutputFileStream.Write($MftData, 0, $MftData.Length)
                        $TotalBytesWritten += $MftData.Length
                    }
                    $DataRunStringsOffset += $StartBytes + $LengthBytes + 1
                } until ($TotalBytesWritten -eq $MftSize)
        
                $FileStream.Dispose()
                $OutputFileStream.Dispose()

                $Properties = @{
                    NetworkPath = "\\$($env:COMPUTERNAME)\C$\$($OutputFilePath.TrimStart('C:\'))"
                    ComputerName = $env:COMPUTERNAME
                    'MFT Size' = "$($MftSize / 1024 / 1024) MB"
                    'MFT Volume' = $Volume
                    'MFT File' = $OutputFilePath
                }
                New-Object -TypeName PSObject -Property $Properties
            }

            if ($PSBoundParameters['ComputerName']) {   
                $ReturnedObjects = Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoteScriptBlock -ArgumentList @($Volume) -SessionOption (New-PSSessionOption -NoMachineProfile) -ThrottleLimit $ThrottleLimit
            }
            else { $ReturnedObjects = Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($Volume) }

            if ($ReturnedObjects -ne $null) {
                if ($PSBoundParameters['CSV']) { $ReturnedObjects | Export-Csv -Path $OutputFilePath -Append -NoTypeInformation -ErrorAction SilentlyContinue }
                else { Write-Output $ReturnedObjects }
            }

            [GC]::Collect()
            $ScriptTime.Stop()
            Write-Verbose "Done, execution time: $($ScriptTime.Elapsed)"
        }
    #endregion

#endregion

_Initialize-Module