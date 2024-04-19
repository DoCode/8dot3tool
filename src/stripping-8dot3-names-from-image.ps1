#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]] $IsoImages,

    [Parameter()]
    [string] $WorkingRootPath = $PSScriptRoot,

    [Parameter()]
    [string] $MountRootPath = (Join-Path $WorkingRootPath 'm'),

    [Parameter()]
    [switch] $WhatIf,

    [Parameter(ValueFromRemainingArguments = $true)]
    $Vars
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Import modules
try { Import-Module SmartLogging } catch { Install-Module SmartLogging -Scope CurrentUser -Force; Import-Module SmartLogging }
try { Import-Module Execution } catch { Install-Module Execution -Scope CurrentUser -Force; Import-Module Execution }

Set-ScriptArgs $MyInvocation.BoundParameters $MyInvocation.UnboundArguments

Invoke-SelfElevation

function Get-Key() {
    return -join (1..6 | % { ((48..57) + (65..90) + (97..122) | % { [char]$_ }) + (0..9) | Get-Random })
}

function Expand-IsoImage([string] $isoImagePath, [string] $destinationPath) {
    Log info "Expand image '$isoImagePath' -> '$destinationPath'"
    if (-not $WhatIf) {
        # Start-NativeExecution 'C:\Program Files\7-Zip\7z.exe' x -o$destinationPath $isoImagePath
        # Start-Process -FilePath $7zipCommand -ArgumentList @('x', "-o$destinationPath", $isoImagePath) -NoNewWindow -Wait
        & $7zipCommand x "-o$($destinationPath)" $isoImagePath
    }
}

function Convert-ImageEsdToWim([string] $esdFilePath, [string] $wimFilePath) {
    Log trace "Convert-ImageEsdToWim esdFilePath: $esdFilePath, wimFilePath: $wimFilePath"

    $logLevel = @{ LogLevel = 'Errors' }

    foreach ($image in Get-WindowsImage -ImagePath $esdFilePath @logLevel) {
        Log info "Convert edition '$($image.ImageName)' -> '$wimFilePath'"
        if (-not $WhatIf) {
            Export-WindowsImage -SourceImagePath $esdFilePath -SourceIndex $image.ImageIndex -DestinationImagePath $wimFilePath -DestinationName $image.ImageName -CheckIntegrity -CompressionType max
        }
    }
}

function Convert-ImageWimToEsd([string] $wimFilePath, [string] $esdFilePath) {
    Log trace "Convert-ImageWimToEsd wimFilePath: $wimFilePath, esdFilePath: $esdFilePath"

    $logLevel = @{ LogLevel = 'Errors' }

    foreach ($image in Get-WindowsImage -ImagePath $wimFilePath @logLevel) {
        Log info "Convert edition '$($image.ImageName)' -> '$esdFilePath'"

        $dismArgs = @(
            '/export-image',
            "/sourceimagefile:$wimFilePath",
            "/sourceindex:$($image.ImageIndex)",
            "/destinationimagefile:$esdFilePath",
            "/destinationname:'$($image.ImageName)'",
            '/compress:recovery',
            '/checkintegrity'
        )

        Log trace "dismArgs: $dismArgs"
        if (-not $WhatIf) {
            & $DismCommand @dismArgs
        }
    }
}

function Invoke-Strip8Dot3Name([string] $wimFilePath, [string] $destinationDir) {
    Log trace "Invoke-Strip8Dot3Name wimFilePath: $wimFilePath, destinationDir: $destinationDir"

    $logLevel = @{ LogLevel = 'Errors' }

    foreach ($image in Get-WindowsImage -ImagePath $wimFilePath @logLevel) {
        $imageKey = Get-Key

        try {
            $mountPath = Join-Path $MountRootPath $destinationDir $imageKey

            Log info "Create mount directory -> '$mountPath'"
            if (-not $WhatIf) {
                New-Item -Path $mountPath -ItemType Directory -Force > $null
            }

            Log info "Mount edition '$($image.ImageName)' -> mounted at '$mountPath'"
            if (-not $WhatIf) {
                Mount-WindowsImage -Path $mountPath -ImagePath $wimFilePath -Name $image.ImageName @logLevel > $null
            }

            Log info 'Load registry hives'
            if (-not $WhatIf) {
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-components" (Join-Path $mountPath 'Windows\System32\config\COMPONENTS')
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-default" (Join-Path $mountPath 'Windows\System32\config\DEFAULT')
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-drivers" (Join-Path $mountPath 'Windows\System32\config\DRIVERS')
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-software" (Join-Path $mountPath 'Windows\System32\config\SOFTWARE')
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-system" (Join-Path $mountPath 'Windows\System32\config\SYSTEM')
                & "$env:windir\system32\reg.exe" load "HKLM\mnt-$imageKey-user-default" (Join-Path $mountPath 'Users\Default\NTUSER.DAT')
            }

            Log info 'Stripping 8dot3 names in mounted registry and mounted directory'
            if (-not $WhatIf) {
                & "$env:windir\system32\fsutil.exe" 8dot3name strip /f /l nul /s $mountPath
            }

            Log info 'Enable Long Paths in mounted registry'
            if (-not $WhatIf) {
                New-ItemProperty -Path "Registry::HKLM\mnt-$imageKey-system\ControlSet001\Control\FileSystem" -Name 'LongPathsEnabled' -PropertyType DWord -Value 1 -Force > $null
            }

            Log info 'Disable 8dot3 names in mounted registry'
            if (-not $WhatIf) {
                New-ItemProperty -Path "Registry::HKLM\mnt-$imageKey-system\ControlSet001\Control\FileSystem" -Name 'NtfsDisable8dot3NameCreation' -PropertyType DWord -Value 1 -Force > $null
            }

            Log info 'Unload registry hives'
            if (-not $WhatIf) {
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-components"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-default"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-drivers"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-software"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-system"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-user-default"
            }

            Log info "Dismount edition '$($image.ImageName)' -> mounted at '$mountPath'"
            if (-not $WhatIf) {
                Dismount-WindowsImage -Path $mountPath -Save @logLevel > $null
            }

            Log info "Remove mount directory -> '$mountPath'"
            if (-not $WhatIf) {
                Remove-Item $mountPath -Recurse -Force > $null
            }
        } catch {
            # Cleanup goes here

            Log error "Something went wrong: $_"
            Log trace "Exception: $($_.Exception)"
            Log trace "StackTrace: $($_.ScriptStackTrace)"

            Log warn 'Start Cleanup...'

            Log warn 'Unload registry hives'
            if (-not $WhatIf) {
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-components"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-default"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-drivers"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-software"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-system"
                & "$env:windir\system32\reg.exe" unload "HKLM\mnt-$imageKey-user-default"
            }

            Log info "Dismount edition '$($image.ImageName)' -> mounted at '$mountPath'"
            if (-not $WhatIf) {
                Dismount-WindowsImage -Path $mountPath -Discard @logLevel > $null
            }

            Log info "Remove mount directory -> '$mountPath'"
            if (-not $WhatIf) {
                Remove-Item $mountPath -Recurse -Force > $null
            }

            throw
        }
    }
}

function New-ImageIso([string] $destinationPath, [string] $isoDestinationFile, [string] $isoLabel) {
    Log info "Create new ISO image from '$destinationPath' -> '$isoDestinationFile' (Label: $isoLabel)"

    $oscdImgArgs = @(
        '-u2',
        '-udfver102',
        '-o',
        "-l$isoLabel",
        '-m',
        "-bootdata:2#p0,e,b$(Join-Path $destinationPath 'boot\etfsboot.com')#pEF,e,b$(Join-Path $destinationPath 'efi\microsoft\boot\efisys.bin')"
        $destinationPath,
        $isoDestinationFile
    )

    Log trace "oscdImgArgs: $oscdImgArgs"
    if (-not $WhatIf) {
        & $OscdImgCommand @oscdImgArgs
    }
}

$ExitCode = 0

try {
    # Code goes here

    # Convert vars to hashtable
    $UnboundArgs = @{}
    if ($null -ne $Vars) {
        $Vars | ForEach-Object {
            if ($_ -match '^-') {
                # New parameter
                $lastvar = $_ -replace '^-'
                $UnboundArgs[$lastvar] = $true
            } else {
                # Value
                $UnboundArgs[$lastvar] = $_
            }
        }
    }

    $7zipCommand = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
    $DismCommand = Join-Path $env:windir 'System32\Dism.exe'
    $OscdImgCommand = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe'

    foreach ($isoImage in $IsoImages) {
        $destinationDir = Get-Key
        $isoImagePath = Resolve-Path $isoImage
        $destinationPath = Join-Path $WorkingRootPath $destinationDir

        Log info "Create destination directory -> '$destinationPath'"
        if (-not $WhatIf) {
            New-Item -Path $destinationPath -ItemType Directory -Force > $null
        }

        # Expand ISO image
        Expand-IsoImage -isoImagePath $isoImagePath -destinationPath $destinationPath

        $esdImage = (Join-Path $destinationPath 'sources\install.esd')
        $wimImage = (Join-Path $destinationPath 'sources\install.wim')

        $isEsdImage = Test-Path $esdImage
        if ($isEsdImage) {
            # Windows 10/11
            Log info 'Execute Windows image'
            Convert-ImageEsdToWim -esdFilePath $esdImage -wimFilePath $wimImage

            Log info "Remove old image '$esdImage'"
            if (-not $WhatIf) {
                Remove-Item $esdImage -Force > $null
            }
        } else {
            # Windows Server 2019/2022
            Log info 'Execute Windows Server image'
        }

        Invoke-Strip8Dot3Name -wimFilePath $wimImage -destinationDir $destinationDir

        if ($isEsdImage) {
            $esdImage = Convert-ImageWimToEsd -wimFilePath $wimImage -esdFilePath $esdImage

            Log info "Remove old image '$wimImage'"
            if (-not $WhatIf) {
                Remove-Item $wimImage -Force > $null
            }
        }

        # Create new ISO Image
        $isoDestinationFile = Join-Path (Split-Path $isoImagePath -Parent) "$(Split-Path $isoImagePath -LeafBase)-disabled-8dot3-name.iso"
        $isoLabel = (& $7zipCommand l -slt $isoImagePath | Where-Object { $_ -like '*LogicalVolumeId:*' }).Trim('LogicalVolumeId: ')
        New-ImageIso -destinationPath $destinationPath -isoDestinationFile $isoDestinationFile -isoLabel $isoLabel

        Log info "Remove destination directory -> '$destinationPath'"
        if (-not $WhatIf) {
            Remove-Item $destinationPath -Recurse -Force > $null
        }
    }

    Log info 'Successfully'
    $ExitCode = 0
} catch {
    Log error "Something went wrong: $_"
    Log trace "Exception: $($_.Exception)"
    Log trace "StackTrace: $($_.ScriptStackTrace)"
    $ExitCode = 1
} finally {
    # Cleanup goes here

    if (Test-Path $MountRootPath) {
        Log info "Remove mount root directory -> '$MountRootPath'"
        if (-not $WhatIf) {
            Remove-Item $MountRootPath -Recurse -Force > $null
        }
    }
}

Exit-WithAndWaitOnExplorer $ExitCode