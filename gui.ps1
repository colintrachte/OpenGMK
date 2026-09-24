<#
.SYNOPSIS
    OpenGMK Decompiler Studio GUI
    Drag-and-drop front-end for GameMaker executable decompilation with smart
    heuristic version guessing, output health validation, interactive resolution options,
    non-blocking notification drawer, and automated fallback cascading.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$InputExe = "",

    [Parameter()]
    [switch]$NonInteractiveTest
)

# Enforce STA mode for WPF if started directly in PowerShell console
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Host "[OpenGMK] Re-launching in STA mode for WPF..." -ForegroundColor Cyan
    $argList = @("-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($InputExe) { $argList += "`"$InputExe`"" }
    if ($NonInteractiveTest) { $argList += "-NonInteractiveTest" }
    Start-Process powershell.exe -ArgumentList $argList
    exit
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Drawing, System.Windows.Forms

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) { $ScriptDir = Get-Location }

# Locate decompiler binary
function Get-DecompilerExe {
    $candidates = @(
        (Join-Path $ScriptDir "target\release\gm8decompiler.exe"),
        (Join-Path $ScriptDir "target\debug\gm8decompiler.exe"),
        (Join-Path $ScriptDir "gm8decompiler.exe")
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { return $cand }
    }
    return $null
}

# ---------------------------------------------------------------------------------------
# Binary Inspection & GameMaker Version Guessing Heuristics
# ---------------------------------------------------------------------------------------
function Analyze-GameMakerBinary {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        return @{ Error = "File not found: $FilePath" }
    }

    $fileInfo = Get-Item $FilePath
    $fileLength = $fileInfo.Length
    if ($fileLength -lt 0x40) {
        return @{ Version = "Corrupt File"; Short = "INVALID"; Confidence = "0%"; Reason = "File too small (<64 bytes)" }
    }

    $stream = [System.IO.File]::OpenRead($FilePath)
    $reader = New-Object System.IO.BinaryReader($stream)

    try {
        # Check MZ signature
        $mz = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(2))
        if ($mz -ne "MZ") {
            return @{ Version = "Non-PE File"; Short = "NON_PE"; Confidence = "0%"; Reason = "Missing MZ DOS header" }
        }

        # PE offset at 0x3C
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset + 24 -gt $fileLength) {
            return @{ Version = "Corrupt PE"; Short = "INVALID"; Confidence = "0%"; Reason = "Invalid PE offset" }
        }

        $stream.Position = $peOffset
        $peSig = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(4))
        if ($peSig -ne "PE`0`0") {
            return @{ Version = "Invalid PE"; Short = "INVALID"; Confidence = "0%"; Reason = "Invalid PE signature" }
        }

        $machine = $reader.ReadUInt16()
        $numSections = $reader.ReadUInt16()
        $stream.Position = $peOffset + 20
        $optHeaderSize = $reader.ReadUInt16()
        $stream.Position = $peOffset + 24 + $optHeaderSize

        # Scan section headers to compute PE runner disk bounds
        $maxRawOffset = 0
        $hasUpx = $false
        for ($i = 0; $i -lt $numSections; $i++) {
            $sectNameBytes = $reader.ReadBytes(8)
            $sectName = [System.Text.Encoding]::ASCII.GetString($sectNameBytes).TrimEnd("`0")
            $virtSize = $reader.ReadUInt32()
            $virtAddr = $reader.ReadUInt32()
            $rawSize = $reader.ReadUInt32()
            $rawAddr = $reader.ReadUInt32()
            $stream.Position += 16

            if ($sectName -like "UPX*") { $hasUpx = $true }
            $sectEnd = $rawAddr + $rawSize
            if ($sectEnd -gt $maxRawOffset) {
                $maxRawOffset = $sectEnd
            }
        }

        # Heuristic 1: GM 5.0 / 5.3 check (Magic 1230500 + generic swap table cipher)
        $gm5CandidateOffsets = @(1250000, 1500000, 1400000, 1420000, 1600000, $maxRawOffset, 0)
        foreach ($offset in $gm5CandidateOffsets) {
            if ($offset + 48 -le $fileLength) {
                $stream.Position = $offset
                $m = $reader.ReadUInt32()
                if ($m -eq 1230500) {
                    $swapSeed = $reader.ReadUInt32()
                    $table0 = New-Object byte[] 256
                    $invTable = New-Object byte[] 256
                    for ($i = 0; $i -lt 256; $i++) { $table0[$i] = [byte]$i }
                    for ($i = 1; $i -le 10000; $i++) {
                        $j = [int](1 + (([uint64]$i * [uint64]$swapSeed) % 254))
                        $temp = $table0[$j]; $table0[$j] = $table0[$j + 1]; $table0[$j + 1] = $temp
                    }
                    for ($i = 1; $i -lt 256; $i++) {
                        $invTable[$table0[$i]] = [byte]$i
                    }

                    $testLen = [Math]::Min(256, [int]($fileLength - ($offset + 8)))
                    $encSample = $reader.ReadBytes($testLen)
                    $decSample = New-Object byte[] $testLen
                    for ($b = 0; $b -lt $testLen; $b++) {
                        $decSample[$b] = $invTable[$encSample[$b]]
                    }

                    for ($b = 0; $b -le $testLen - 8; $b++) {
                        $mVal = [BitConverter]::ToUInt32($decSample, $b)
                        $vVal = [BitConverter]::ToUInt32($decSample, $b + 4)
                        if ($mVal -eq 1234321) {
                            $verName = if ($vVal -eq 530) { "GameMaker 5.3" } else { "GameMaker 5.0" }
                            return @{
                                Version = $verName
                                Short = "GM5"
                                Confidence = "100%"
                                Strategy = "GM5"
                                RecommendedExt = ".gmd"
                                PayloadOffset = $offset
                                SwapSeed = $swapSeed
                                SubVersion = $vVal
                                HasUPX = $hasUpx
                                Details = "Detected GM5 magic 1230500 (swap seed $swapSeed, sub-version $vVal) at offset $offset"
                            }
                        }
                    }
                }
            }
        }

        # Heuristic 2: GM 6.0 / 6.1 check
        $gm6Offsets = @(0, 700000, 800000, 1420000, 1600000, $maxRawOffset)
        foreach ($offset in $gm6Offsets) {
            if ($offset + 8 -le $fileLength) {
                $stream.Position = $offset
                $m = $reader.ReadUInt32()
                $v = $reader.ReadUInt32()
                if ($m -eq 1234321 -and $v -eq 600) {
                    return @{
                        Version = "GameMaker 6.0 / 6.1"
                        Short = "GM6"
                        Confidence = "98%"
                        Strategy = "GM6"
                        RecommendedExt = ".gmk"
                        PayloadOffset = $offset
                        HasUPX = $hasUpx
                        Details = "Detected GM6 magic 1234321 and version 600 at offset $offset"
                    }
                }
            }
        }

        # Heuristic 3: GM 7.0 check
        $gm7Offsets = @(1980000, $maxRawOffset)
        foreach ($offset in $gm7Offsets) {
            if ($offset + 8 -le $fileLength) {
                $stream.Position = $offset
                $m = $reader.ReadUInt32()
                $v = $reader.ReadUInt32()
                if ($m -eq 1234321 -and $v -eq 700) {
                    return @{
                        Version = "GameMaker 7.0"
                        Short = "GM7"
                        Confidence = "98%"
                        Strategy = "GM7"
                        RecommendedExt = ".gmk"
                        PayloadOffset = $offset
                        HasUPX = $hasUpx
                        Details = "Detected GM7 magic 1234321 and version 700 at offset $offset"
                    }
                }
            }
        }

        # Heuristic 4: GM 8.1 search for magic value 0xF7140067 or 0xF7140017
        $scanStart = [Math]::Max(0, [int]($maxRawOffset - 65536))
        $scanLen = [Math]::Min(131072, [int]($fileLength - $scanStart))
        if ($scanLen -gt 16) {
            $stream.Position = $scanStart
            $scanBytes = $reader.ReadBytes($scanLen)
            for ($b = 0; $b -le $scanLen - 4; $b++) {
                $val = [BitConverter]::ToUInt32($scanBytes, $b)
                if ($val -eq 0xF7140067 -or $val -eq 0xF7140017) {
                    return @{
                        Version = "GameMaker 8.1"
                        Short = "GM81"
                        Confidence = "95%"
                        Strategy = "GM81"
                        RecommendedExt = ".gm81"
                        PayloadOffset = ($scanStart + $b)
                        HasUPX = $hasUpx
                        Details = "Detected GM8.1 header signature (0x{0:X8}) at offset {1}" -f $val, ($scanStart + $b)
                    }
                }
            }
        }

        # Heuristic 5: GameMaker Studio (IFF FORM chunk)
        $stream.Position = [Math]::Max(0, [int]($maxRawOffset))
        if ($fileLength - $stream.Position -ge 16) {
            $head = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(4))
            if ($head -eq "FORM") {
                return @{
                    Version = "GameMaker Studio (1.x / 2.x)"
                    Short = "GMS"
                    Confidence = "99%"
                    Strategy = "GMS"
                    RecommendedExt = ".win"
                    PayloadOffset = $maxRawOffset
                    HasUPX = $hasUpx
                    Details = "Detected IFF FORM chunk (GameMaker Studio data.win container). Use UTMT/UndertaleModTool."
                }
            }
        }

        # Heuristic 6: Delphi Runner Size analysis
        if ($maxRawOffset -ge 2000000 -and $maxRawOffset -le 2400000) {
            return @{
                Version = "GameMaker 8.0 (Inferred)"
                Short = "GM80"
                Confidence = "80%"
                Strategy = "GM80"
                RecommendedExt = ".gmk"
                PayloadOffset = $maxRawOffset
                HasUPX = $hasUpx
                Details = "PE runner size is $($maxRawOffset) bytes (characteristic of GM8.0 runtime)"
            }
        } elseif ($maxRawOffset -gt 2400000 -and $maxRawOffset -le 3200000) {
            return @{
                Version = "GameMaker 8.1 (Inferred)"
                Short = "GM81"
                Confidence = "80%"
                Strategy = "GM81"
                RecommendedExt = ".gm81"
                PayloadOffset = $maxRawOffset
                HasUPX = $hasUpx
                Details = "PE runner size is $($maxRawOffset) bytes (characteristic of GM8.1 runtime)"
            }
        }

        return @{
            Version = "GameMaker (Generic / Legacy)"
            Short = "GM_UNKNOWN"
            Confidence = "50%"
            Strategy = "GENERIC"
            RecommendedExt = ".gmk"
            PayloadOffset = $maxRawOffset
            HasUPX = $hasUpx
            Details = "Standard PE binary ($([Math]::Round($fileLength / 1MB, 2)) MB); cascading fallbacks will test GM8 -> GM7 -> GM6 -> GM5"
        }
    } finally {
        $reader.Close()
        $stream.Close()
    }
}

# ---------------------------------------------------------------------------------------
# Health Check Validation
# ---------------------------------------------------------------------------------------
function Test-DecompileHealth {
    param(
        [string]$OutputFile,
        [long]$InputExeLength,
        [int]$ExitCode
    )

    if (-not (Test-Path $OutputFile)) {
        return @{
            Healthy = $false
            Reason = "Output file was not created by the decompiler"
            Size = 0
        }
    }

    $outInfo = Get-Item $OutputFile
    $outSize = $outInfo.Length

    # Check 1: Empty file
    if ($outSize -eq 0) {
        return @{
            Healthy = $false
            Reason = "Output file is empty (0 bytes)"
            Size = 0
        }
    }

    # Check 2: Header stub (most failed decompilers crash after writing an 800-1500 byte stub header)
    if ($InputExeLength -gt 100000 -and $outSize -lt 2048) {
        return @{
            Healthy = $false
            Reason = "Output file is an incomplete stub ($outSize bytes, expected full project)"
            Size = $outSize
        }
    }

    # Check 3: Abnormally small (< 1% of input exe when exe > 1MB)
    if ($InputExeLength -gt 1000000 -and $outSize -lt ($InputExeLength * 0.01) -and $outSize -lt 15000) {
        return @{
            Healthy = $false
            Reason = "Output file is suspiciously small ($outSize bytes vs $([Math]::Round($InputExeLength / 1MB, 2)) MB executable)"
            Size = $outSize
        }
    }

    # Check 4: Non-zero exit code when output is questionable
    if ($ExitCode -ne 0 -and $outSize -lt 10000) {
        return @{
            Healthy = $false
            Reason = "Decompiler process failed (exit code $ExitCode) with undersized output ($outSize bytes)"
            Size = $outSize
        }
    }

    return @{
        Healthy = $true
        Reason = "Output healthy: $([Math]::Round($outSize / 1MB, 2)) MB ($outSize bytes)"
        Size = $outSize
    }
}

# ---------------------------------------------------------------------------------------
# Emergency Direct Payload Extraction (Fallback for GM5)
# ---------------------------------------------------------------------------------------
function Invoke-DirectGm5Extraction {
    param(
        [string]$ExePath,
        [string]$OutputPath,
        [long]$PayloadOffset,
        [uint32]$SwapSeed
    )

    try {
        $bytes = [System.IO.File]::ReadAllBytes($ExePath)
        if ($bytes.Length -lt $PayloadOffset + 8) { return $false }

        # Decrypt payload starting from offset + 8
        $table0 = New-Object byte[] 256
        $invTable = New-Object byte[] 256
        for ($i = 0; $i -lt 256; $i++) { $table0[$i] = [byte]$i }
        for ($i = 1; $i -le 10000; $i++) {
            $j = [int](1 + (([uint64]$i * [uint64]$SwapSeed) % 254))
            $temp = $table0[$j]; $table0[$j] = $table0[$j + 1]; $table0[$j + 1] = $temp
        }
        for ($i = 1; $i -lt 256; $i++) {
            $invTable[$table0[$i]] = [byte]$i
        }

        $encLen = $bytes.Length - ($PayloadOffset + 8)
        $dec = New-Object byte[] $encLen
        for ($i = 0; $i -lt $encLen; $i++) {
            $dec[$i] = $invTable[$bytes[$PayloadOffset + 8 + $i]]
        }

        # Find magic 1234321
        for ($i = 0; $i -le $encLen - 8; $i++) {
            $m = [BitConverter]::ToUInt32($dec, $i)
            if ($m -eq 1234321) {
                # Project payload begins at offset $i
                $gmdBytes = New-Object byte[] ($encLen - $i)
                [Array]::Copy($dec, $i, $gmdBytes, 0, $gmdBytes.Length)
                [System.IO.File]::WriteAllBytes($OutputPath, $gmdBytes)
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------------------
# Cascading Strategy Pipeline Execution with Real-Time Streaming
# ---------------------------------------------------------------------------------------
function Invoke-DecompilationPipeline {
    param(
        [string]$ExePath,
        [hashtable]$Analysis,
        [scriptblock]$LogCallback,
        [scriptblock]$StatusCallback,
        [string]$EngineOverride = "Auto",
        [string]$ModeOverride = "Auto"
    )

    $decompilerBin = Get-DecompilerExe
    if (-not $decompilerBin) {
        & $LogCallback "[ERROR] Could not find gm8decompiler.exe in target/release/ or script root."
        & $LogCallback "[INFO] Please run 'cargo build --release --bin gm8decompiler' first."
        return @{ Success = $false; Error = "gm8decompiler.exe not found" }
    }

    # Apply Engine Override if selected
    $effectiveAnalysis = @{}
    foreach ($k in $Analysis.Keys) { $effectiveAnalysis[$k] = $Analysis[$k] }

    switch ($EngineOverride) {
        "GameMaker 7.0" {
            $effectiveAnalysis.Version = "GameMaker 7.0"
            $effectiveAnalysis.Short = "GM7"
            $effectiveAnalysis.Strategy = "GM7"
            $effectiveAnalysis.RecommendedExt = ".gmk"
            & $LogCallback "[OVERRIDE] Forcing Engine Version: GameMaker 7.0"
        }
        "GameMaker 8.0" {
            $effectiveAnalysis.Version = "GameMaker 8.0"
            $effectiveAnalysis.Short = "GM80"
            $effectiveAnalysis.Strategy = "GM80"
            $effectiveAnalysis.RecommendedExt = ".gmk"
            & $LogCallback "[OVERRIDE] Forcing Engine Version: GameMaker 8.0"
        }
        "GameMaker 8.1" {
            $effectiveAnalysis.Version = "GameMaker 8.1"
            $effectiveAnalysis.Short = "GM81"
            $effectiveAnalysis.Strategy = "GM81"
            $effectiveAnalysis.RecommendedExt = ".gm81"
            & $LogCallback "[OVERRIDE] Forcing Engine Version: GameMaker 8.1"
        }
        "GameMaker 6.0 / 6.1" {
            $effectiveAnalysis.Version = "GameMaker 6.0 / 6.1"
            $effectiveAnalysis.Short = "GM6"
            $effectiveAnalysis.Strategy = "GM6"
            $effectiveAnalysis.RecommendedExt = ".gmk"
            & $LogCallback "[OVERRIDE] Forcing Engine Version: GameMaker 6.0 / 6.1"
        }
        "GameMaker 5.0 / 5.3" {
            $effectiveAnalysis.Version = "GameMaker 5.0 / 5.3"
            $effectiveAnalysis.Short = "GM5"
            $effectiveAnalysis.Strategy = "GM5"
            $effectiveAnalysis.RecommendedExt = ".gmd"
            & $LogCallback "[OVERRIDE] Forcing Engine Version: GameMaker 5.0 / 5.3"
        }
    }

    $inputInfo = Get-Item $ExePath
    $exeDir = $inputInfo.DirectoryName
    $exeBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
    $primaryExt = $effectiveAnalysis.RecommendedExt
    if (-not $primaryExt) { $primaryExt = ".gmk" }

    # Define prioritized fallback strategy sequence
    $strategies = [System.Collections.Generic.List[hashtable]]::new()

    if ($ModeOverride -eq "Standard Only") {
        $strategies.Add(@{
            Name = "Attempt 1 (Standard Primary: $primaryExt)"
            Extension = $primaryExt
            Flags = @()
            Description = "Standard decompiler pass for $($effectiveAnalysis.Version)"
        })
    } elseif ($ModeOverride -eq "Lazy Mode (-l)") {
        $strategies.Add(@{
            Name = "Manual Attempt (Lazy Mode: -l)"
            Extension = $primaryExt
            Flags = @("-l")
            Description = "Bypasses asset data integrity assertions"
        })
    } elseif ($ModeOverride -eq "Preserve Mode (-p)") {
        $strategies.Add(@{
            Name = "Manual Attempt (Preserve Mode: -p)"
            Extension = $primaryExt
            Flags = @("-p")
            Description = "Preserves unparsed code actions without failing"
        })
    } elseif ($ModeOverride -eq "Lazy + Preserve (-l -p)") {
        $strategies.Add(@{
            Name = "Manual Attempt (Lazy + Preserve: -l -p)"
            Extension = $primaryExt
            Flags = @("-l", "-p")
            Description = "Combined fault-tolerant parsing"
        })
    } else {
        # Full Cascade (Default)
        $strategies.Add(@{
            Name = "Attempt 1 (Standard Primary: $primaryExt)"
            Extension = $primaryExt
            Flags = @()
            Description = "Standard decompiler pass for $($effectiveAnalysis.Version)"
        })

        $strategies.Add(@{
            Name = "Attempt 2 (Lazy Mode: -l)"
            Extension = $primaryExt
            Flags = @("-l")
            Description = "Bypasses asset data integrity assertions"
        })

        $strategies.Add(@{
            Name = "Attempt 3 (Preserve Mode: -p)"
            Extension = $primaryExt
            Flags = @("-p")
            Description = "Preserves unparsed code actions without failing"
        })

        $strategies.Add(@{
            Name = "Attempt 4 (Lazy + Preserve: -l -p)"
            Extension = $primaryExt
            Flags = @("-l", "-p")
            Description = "Combined fault-tolerant parsing"
        })

        $strategies.Add(@{
            Name = "Attempt 5 (Deobfuscator Disabled: -l -p -d off)"
            Extension = $primaryExt
            Flags = @("-l", "-p", "-d", "off")
            Description = "Skips AST deobfuscation to avoid syntax transformer panics"
        })

        if ($primaryExt -eq ".gmd") {
            $strategies.Add(@{
                Name = "Attempt 6 (Format Swap: .gmk)"
                Extension = ".gmk"
                Flags = @("-l", "-p")
                Description = "Try writing output as GMK format"
            })
        } elseif ($primaryExt -eq ".gm81") {
            $strategies.Add(@{
                Name = "Attempt 6 (Format Swap: .gmk)"
                Extension = ".gmk"
                Flags = @("-l", "-p")
                Description = "Try writing output as GM8.0 GMK format"
            })
        } else {
            $strategies.Add(@{
                Name = "Attempt 6 (Format Swap: .gmd)"
                Extension = ".gmd"
                Flags = @("-l", "-p")
                Description = "Try writing output as legacy GMD format"
            })
        }

        # Check for External Tools in tools/
        $toolsDir = Join-Path $ScriptDir "tools"
        if (Test-Path $toolsDir) {
            $externalTools = Get-ChildItem -Path $toolsDir -Filter "*.exe" -File
            foreach ($tool in $externalTools) {
                $strategies.Add(@{
                    Name = "External Tool: $($tool.Name)"
                    ExternalExe = $tool.FullName
                    Flags = @()
                    Description = "External helper tool in tools/"
                })
            }
        }

        # Direct payload extractor if GM5
        if ($effectiveAnalysis.Short -eq "GM5" -and $effectiveAnalysis.SwapSeed) {
            $strategies.Add(@{
                Name = "Direct GMD Stream Decryptor"
                IsDirectGm5 = $true
                Extension = ".gmd"
                Description = "Pure cipher payload extraction directly from executable stream"
            })
        }
    }

    & $LogCallback "========================================================"
    & $LogCallback "Target Executable: $($inputInfo.FullName)"
    & $LogCallback "File Size: $([Math]::Round($inputInfo.Length / 1MB, 2)) MB ($($inputInfo.Length) bytes)"
    & $LogCallback "Active Engine Profile: $($effectiveAnalysis.Version) (Confidence: $($effectiveAnalysis.Confidence))"
    & $LogCallback "Technical Details: $($effectiveAnalysis.Details)"
    & $LogCallback "Execution Queue: $($strategies.Count) strategies configured"
    & $LogCallback "========================================================"

    $attemptIndex = 0
    foreach ($strat in $strategies) {
        $attemptIndex++
        $targetOut = Join-Path $exeDir "$exeBaseName$($strat.Extension)"

        & $StatusCallback "Running $($strat.Name)..."
        & $LogCallback ""
        & $LogCallback ">>> [$attemptIndex/$($strategies.Count)] $($strat.Name)"
        & $LogCallback "    Description: $($strat.Description)"
        & $LogCallback "    Target Output: $targetOut"

        # If previous output exists and was a failure, remove it before this attempt
        if (Test-Path $targetOut) {
            Remove-Item $targetOut -Force -ErrorAction SilentlyContinue
        }

        $exitCode = 0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        if ($strat.IsDirectGm5) {
            & $LogCallback "    Executing direct cipher extraction..."
            $directSuccess = Invoke-DirectGm5Extraction -ExePath $ExePath -OutputPath $targetOut -PayloadOffset $effectiveAnalysis.PayloadOffset -SwapSeed $effectiveAnalysis.SwapSeed
            $stopwatch.Stop()
            if (-not $directSuccess) { $exitCode = 1 }
        } elseif ($strat.ExternalExe) {
            & $LogCallback "    Launching external tool: $($strat.ExternalExe)..."
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $strat.ExternalExe
            $psi.Arguments = "`"$ExePath`""
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            $proc.EnableRaisingEvents = $true

            $proc.add_OutputDataReceived({
                param($s, $e)
                if ($e.Data) { & $LogCallback "    [tool] $($e.Data)" }
            })
            $proc.add_ErrorDataReceived({
                param($s, $e)
                if ($e.Data) { & $LogCallback "    [tool err] $($e.Data)" }
            })

            $proc.Start() | Out-Null
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()
            $proc.WaitForExit()
            $exitCode = $proc.ExitCode
            $stopwatch.Stop()
        } else {
            # Run gm8decompiler with non-interactive flags and asynchronous real-time streaming
            $argList = @("-y", "-o", "`"$targetOut`"")
            if ($strat.Flags) { $argList += $strat.Flags }
            $argList += "`"$ExePath`""

            $argString = $argList -join " "
            & $LogCallback "    Command: gm8decompiler $argString"

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $decompilerBin
            $psi.Arguments = $argString
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.RedirectStandardInput = $true
            $psi.EnvironmentVariables["MSYSTEM"] = "1"
            $psi.CreateNoWindow = $true

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi
            $proc.EnableRaisingEvents = $true

            $proc.add_OutputDataReceived({
                param($s, $e)
                if ($e.Data) { & $LogCallback "    [stdout] $($e.Data)" }
            })
            $proc.add_ErrorDataReceived({
                param($s, $e)
                if ($e.Data) { & $LogCallback "    [stderr] $($e.Data)" }
            })

            $proc.Start() | Out-Null
            $proc.StandardInput.Close()
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()
            $proc.WaitForExit()
            $exitCode = $proc.ExitCode
            $stopwatch.Stop()
        }

        # Check Output Health
        $health = Test-DecompileHealth -OutputFile $targetOut -InputExeLength $inputInfo.Length -ExitCode $exitCode
        & $LogCallback "    Elapsed Time: $($stopwatch.ElapsedMilliseconds) ms"
        & $LogCallback "    Health Status: $(if ($health.Healthy) { 'HEALTHY' } else { 'FAILED' }) - $($health.Reason)"

        if ($health.Healthy) {
            & $StatusCallback "SUCCESS: $($strat.Name)"
            & $LogCallback ""
            & $LogCallback "********************************************************"
            & $LogCallback "  DECOMPILATION SUCCESSFUL!"
            & $LogCallback "  Strategy: $($strat.Name)"
            & $LogCallback "  Output File: $targetOut"
            & $LogCallback "  Output Size: $([Math]::Round($health.Size / 1MB, 2)) MB ($($health.Size) bytes)"
            & $LogCallback "********************************************************"

            return @{
                Success = $true
                Strategy = $strat.Name
                OutputFile = $targetOut
                OutputSize = $health.Size
                ExitCode = $exitCode
                ElapsedMs = $stopwatch.ElapsedMilliseconds
            }
        } else {
            & $LogCallback "    Attempt failed. Cascading to next fallback strategy..."
        }
    }

    & $StatusCallback "FAILED: All strategies exhausted"
    & $LogCallback ""
    & $LogCallback "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    & $LogCallback "  ERROR: All $($strategies.Count) fallback strategies exhausted."
    & $LogCallback "  No healthy project file could be extracted."
    & $LogCallback "  Recommendation: Check if the executable is encrypted with a third-party packer,"
    & $LogCallback "  or uses GameMaker: Studio (YYC / IFF data.win) rather than legacy GameMaker."
    & $LogCallback "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

    return @{
        Success = $false
        Error = "All fallback strategies exhausted"
    }
}

# ---------------------------------------------------------------------------------------
# Non-Interactive Test Mode (CLI Automation / CI)
# ---------------------------------------------------------------------------------------
if ($NonInteractiveTest) {
    if (-not $InputExe) {
        Write-Error "NonInteractiveTest requires -InputExe <path>"
        exit 1
    }
    Write-Host "[OpenGMK Test] Analyzing binary: $InputExe" -ForegroundColor Cyan
    $analysis = Analyze-GameMakerBinary $InputExe
    Write-Host "[OpenGMK Test] Detected: $($analysis.Version) ($($analysis.Confidence))" -ForegroundColor Green
    Write-Host "[OpenGMK Test] Strategy: $($analysis.Strategy) (Ext: $($analysis.RecommendedExt))"

    $logFn = { param($msg) Write-Host $msg }
    $statusFn = { param($msg) Write-Host "[STATUS] $msg" -ForegroundColor Yellow }

    $res = Invoke-DecompilationPipeline -ExePath $InputExe -Analysis $analysis -LogCallback $logFn -StatusCallback $statusFn
    if ($res.Success) {
        Write-Host "`n[OpenGMK Test] Pipeline PASSED with output: $($res.OutputFile) ($($res.OutputSize) bytes)" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`n[OpenGMK Test] Pipeline FAILED: $($res.Error)" -ForegroundColor Red
        exit 2
    }
}

# ---------------------------------------------------------------------------------------
# WPF GUI Definition with Non-Blocking Notification Drawer & XML Entity Typography
# ---------------------------------------------------------------------------------------

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="OpenGMK Decompiler Studio" Height="820" Width="880" MinHeight="660" MinWidth="740"
        WindowStartupLocation="CenterScreen" Background="#181825"
        Foreground="#CDD6F4" FontFamily="Segoe UI" AllowDrop="True">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#313244"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              Margin="{TemplateBinding Padding}"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#45475A"/>
                                <Setter TargetName="border" Property="BorderBrush" Value="#89B4FA"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#585B70"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Opacity" Value="0.4"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#313244"/>
            <Setter Property="Foreground" Value="#CDD6F4"/>
            <Setter Property="BorderBrush" Value="#45475A"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="6,2"/>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>   <!-- 0: Header -->
            <RowDefinition Height="125"/>    <!-- 1: Drop Zone -->
            <RowDefinition Height="Auto"/>   <!-- 2: Binary Analysis Card -->
            <RowDefinition Height="Auto"/>   <!-- 3: Non-blocking Notification Drawer -->
            <RowDefinition Height="*"/>      <!-- 4: Activity Console -->
            <RowDefinition Height="Auto"/>   <!-- 5: Bottom Actions -->
        </Grid.RowDefinitions>

        <!-- Header -->
        <Grid Grid.Row="0" Margin="0,0,0,14">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Orientation="Vertical">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="&#x26A1; OpenGMK" FontSize="24" FontWeight="Bold" Foreground="#89B4FA"/>
                    <TextBlock Text=" Decompiler Studio" FontSize="24" FontWeight="Bold" Foreground="#F5E0DC"/>
                    <Border Background="#A6E3A1" CornerRadius="4" Margin="12,0,0,0" Padding="6,2" VerticalAlignment="Center">
                        <TextBlock Text="v0.2.1" FontSize="11" FontWeight="Bold" Foreground="#11111B"/>
                    </Border>
                </StackPanel>
                <TextBlock Text="Smart Version Detection &#x2022; Health Checking &#x2022; Cascading Fallback Engine"
                           FontSize="12" Foreground="#A6ADC8" Margin="2,4,0,0"/>
            </StackPanel>
            <Button x:Name="BtnBrowse" Grid.Column="1" Content="&#x1F4C1; Select .EXE..." VerticalAlignment="Center" Height="36"/>
        </Grid>

        <!-- Drag & Drop Zone -->
        <Border x:Name="DropZone" Grid.Row="1" Background="#1E1E2E" BorderBrush="#45475A"
                BorderThickness="2" CornerRadius="10" Margin="0,0,0,12" Cursor="Hand" AllowDrop="True">
            <Grid>
                <StackPanel HorizontalAlignment="Center" VerticalAlignment="Center">
                    <TextBlock x:Name="DropIcon" Text="&#x2B07;" FontSize="32" HorizontalAlignment="Center" Foreground="#89B4FA"/>
                    <TextBlock x:Name="DropTextMain" Text="Drag &amp; Drop GameMaker Executable (.exe) Here"
                               FontSize="15" FontWeight="SemiBold" HorizontalAlignment="Center" Foreground="#CDD6F4" Margin="0,3,0,0"/>
                    <TextBlock x:Name="DropTextSub" Text="Automatic version detection, cascading fallbacks and non-blocking diagnostics"
                               FontSize="11" Foreground="#6C7086" HorizontalAlignment="Center" Margin="0,2,0,0"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- Binary Analysis Card (Initially collapsed) -->
        <Border x:Name="AnalysisCard" Grid.Row="2" Background="#1E1E2E" BorderBrush="#313244"
                BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="14" Visibility="Collapsed">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <Grid Grid.Row="0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Vertical">
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                            <TextBlock Text="TARGET: " FontSize="11" FontWeight="Bold" Foreground="#6C7086"/>
                            <TextBlock x:Name="TxtFileName" Text="game.exe" FontSize="13" FontWeight="Bold" Foreground="#F5E0DC"/>
                            <TextBlock x:Name="TxtFileSize" Text=" (7.2 MB)" FontSize="12" Foreground="#A6ADC8"/>
                        </StackPanel>
                        <StackPanel Orientation="Horizontal" Margin="0,6,0,0" VerticalAlignment="Center">
                            <TextBlock Text="DETECTED: " FontSize="11" FontWeight="Bold" Foreground="#6C7086" VerticalAlignment="Center"/>
                            <Border x:Name="BadgeVersion" Background="#A6E3A1" CornerRadius="4" Padding="6,2" Margin="4,0,8,0">
                                <TextBlock x:Name="TxtBadgeVersion" Text="GameMaker 7.0" FontSize="11" FontWeight="Bold" Foreground="#11111B"/>
                            </Border>
                            <TextBlock x:Name="TxtConfidence" Text="Confidence: 98%" FontSize="11" Foreground="#89B4FA" VerticalAlignment="Center"/>
                        </StackPanel>
                        <TextBlock x:Name="TxtDetails" Text="Payload offset: 1980000 | Magic: 1234321" FontSize="11"
                                   Foreground="#BAC2DE" Margin="0,6,0,0" TextWrapping="Wrap"/>
                    </StackPanel>

                    <!-- Pipeline Status Badge -->
                    <StackPanel Grid.Column="1" HorizontalAlignment="Right" VerticalAlignment="Center">
                        <Border x:Name="BadgeStatus" Background="#313244" CornerRadius="6" Padding="10,6">
                            <TextBlock x:Name="TxtStatus" Text="READY" FontSize="12" FontWeight="Bold" Foreground="#89B4FA"/>
                        </Border>
                    </StackPanel>
                </Grid>

                <!-- Interactive Resolution Controls -->
                <Border Grid.Row="1" Margin="0,10,0,0" Padding="0,10,0,0" BorderBrush="#25273A" BorderThickness="0,1,0,0">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                            <TextBlock Text="ENGINE OVERRIDE: " FontSize="11" FontWeight="Bold" Foreground="#6C7086" VerticalAlignment="Center"/>
                            <ComboBox x:Name="CmbEngineOverride" Width="185" Height="26" Margin="4,0,12,0" FontSize="11">
                                <ComboBoxItem Content="Auto-Detect (Heuristic)" IsSelected="True"/>
                                <ComboBoxItem Content="GameMaker 7.0"/>
                                <ComboBoxItem Content="GameMaker 8.0"/>
                                <ComboBoxItem Content="GameMaker 8.1"/>
                                <ComboBoxItem Content="GameMaker 6.0 / 6.1"/>
                                <ComboBoxItem Content="GameMaker 5.0 / 5.3"/>
                            </ComboBox>

                            <TextBlock Text="MODE: " FontSize="11" FontWeight="Bold" Foreground="#6C7086" VerticalAlignment="Center"/>
                            <ComboBox x:Name="CmbExtractionMode" Width="150" Height="26" Margin="4,0,8,0" FontSize="11">
                                <ComboBoxItem Content="Cascading (Auto)" IsSelected="True"/>
                                <ComboBoxItem Content="Standard Only"/>
                                <ComboBoxItem Content="Lazy Mode (-l)"/>
                                <ComboBoxItem Content="Preserve Mode (-p)"/>
                                <ComboBoxItem Content="Lazy + Preserve (-l -p)"/>
                            </ComboBox>
                        </StackPanel>

                        <Button x:Name="BtnReRun" Grid.Column="1" Content="&#x25B6; Decompile" Height="28" Padding="14,3"
                                Background="#89B4FA" Foreground="#11111B" FontWeight="Bold"/>
                    </Grid>
                </Border>
            </Grid>
        </Border>

        <!-- Non-Blocking Notification Drawer / Toast Banner (Zero modal popups) -->
        <Border x:Name="NotificationDrawer" Grid.Row="3" Background="#182A24" BorderBrush="#A6E3A1"
                BorderThickness="1" CornerRadius="8" Margin="0,0,0,12" Padding="14,10" Visibility="Collapsed">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock x:Name="TxtDrawerIcon" Grid.Column="0" Text="&#x2139;" FontSize="20" FontWeight="Bold"
                           VerticalAlignment="Center" Margin="0,0,12,0" Foreground="#89B4FA"/>

                <StackPanel Grid.Column="1" VerticalAlignment="Center" Margin="0,0,12,0">
                    <TextBlock x:Name="TxtDrawerTitle" Text="Notification" FontSize="13" FontWeight="Bold" Foreground="#CDD6F4"/>
                    <TextBlock x:Name="TxtDrawerMessage" Text="Details and actionable guidance..." FontSize="11" Foreground="#BAC2DE" TextWrapping="Wrap" Margin="0,2,0,0"/>
                </StackPanel>

                <!-- Actionable Buttons inside Drawer -->
                <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,8,0">
                    <Button x:Name="BtnDrawerAction1" Content="Action 1" Height="28" Padding="10,2" Margin="0,0,6,0" Visibility="Collapsed"/>
                    <Button x:Name="BtnDrawerAction2" Content="Action 2" Height="28" Padding="10,2" Margin="0,0,6,0" Visibility="Collapsed"/>
                    <Button x:Name="BtnDrawerCopyLog" Content="Copy Diagnostic" Height="28" Padding="10,2" Margin="0,0,6,0" Visibility="Collapsed"/>
                </StackPanel>

                <!-- Dismiss Button -->
                <Button x:Name="BtnDrawerDismiss" Grid.Column="3" Content="&#x2715;" Height="26" Width="26" Padding="0"
                        VerticalAlignment="Center" Background="Transparent" BorderThickness="0" Foreground="#A6ADC8" Cursor="Hand"/>
            </Grid>
        </Border>

        <!-- Activity Console -->
        <Grid Grid.Row="4" Margin="0,0,0,14">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
            </Grid.RowDefinitions>
            <StackPanel Orientation="Horizontal" Margin="0,0,0,6">
                <TextBlock Text="ACTIVITY &amp; DECOMPILER LOGS" FontSize="11" FontWeight="Bold" Foreground="#6C7086"/>
                <TextBlock x:Name="TxtStrategyCount" Text="" FontSize="11" Foreground="#89B4FA" Margin="10,0,0,0"/>
            </StackPanel>
            <Border Grid.Row="1" Background="#11111B" BorderBrush="#313244" BorderThickness="1" CornerRadius="8">
                <TextBox x:Name="TxtConsole" Background="Transparent" Foreground="#A6ADC8" FontFamily="Consolas, Cascadia Code, Courier New"
                         FontSize="12" BorderThickness="0" Padding="10" IsReadOnly="True"
                         TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" AcceptsReturn="True"/>
            </Border>
        </Grid>

        <!-- Bottom Action Bar -->
        <Grid Grid.Row="5">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock x:Name="TxtFooter" Text="Ready to analyze executables." FontSize="12" Foreground="#6C7086"/>
            </StackPanel>

            <StackPanel Grid.Column="1" Orientation="Horizontal">
                <Button x:Name="BtnCopyLog" Content="&#x1F4CB; Copy Log" Margin="0,0,8,0"/>
                <Button x:Name="BtnOpenFolder" Content="&#x1F4C2; Open Output Folder" IsEnabled="False" Margin="0,0,8,0"
                        Background="#89B4FA" Foreground="#11111B"/>
                <Button x:Name="BtnOpenFile" Content="&#x1F680; Open Project" IsEnabled="False"
                        Background="#A6E3A1" Foreground="#11111B"/>
            </StackPanel>
        </Grid>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

# Element lookups
$dropZone = $window.FindName("DropZone")
$dropTextMain = $window.FindName("DropTextMain")
$dropTextSub = $window.FindName("DropTextSub")
$btnBrowse = $window.FindName("BtnBrowse")
$analysisCard = $window.FindName("AnalysisCard")
$txtFileName = $window.FindName("TxtFileName")
$txtFileSize = $window.FindName("TxtFileSize")
$badgeVersion = $window.FindName("BadgeVersion")
$txtBadgeVersion = $window.FindName("TxtBadgeVersion")
$txtConfidence = $window.FindName("TxtConfidence")
$txtDetails = $window.FindName("TxtDetails")
$badgeStatus = $window.FindName("BadgeStatus")
$txtStatus = $window.FindName("TxtStatus")
$cmbEngineOverride = $window.FindName("CmbEngineOverride")
$cmbExtractionMode = $window.FindName("CmbExtractionMode")
$btnReRun = $window.FindName("BtnReRun")
$notificationDrawer = $window.FindName("NotificationDrawer")
$txtDrawerIcon = $window.FindName("TxtDrawerIcon")
$txtDrawerTitle = $window.FindName("TxtDrawerTitle")
$txtDrawerMessage = $window.FindName("TxtDrawerMessage")
$btnDrawerAction1 = $window.FindName("BtnDrawerAction1")
$btnDrawerAction2 = $window.FindName("BtnDrawerAction2")
$btnDrawerCopyLog = $window.FindName("BtnDrawerCopyLog")
$btnDrawerDismiss = $window.FindName("BtnDrawerDismiss")
$txtStrategyCount = $window.FindName("TxtStrategyCount")
$txtConsole = $window.FindName("TxtConsole")
$txtFooter = $window.FindName("TxtFooter")
$btnCopyLog = $window.FindName("BtnCopyLog")
$btnOpenFolder = $window.FindName("BtnOpenFolder")
$btnOpenFile = $window.FindName("BtnOpenFile")

$activeOutputFile = $null
$currentLoadedFile = $null
$cachedAnalysis = $null
$isProcessing = $false
$drawerAction1Handler = $null
$drawerAction2Handler = $null

# Helper for thread-safe UI updates
function Append-LogLine {
    param([string]$Message)
    $window.Dispatcher.Invoke([Action]{
        $timestamp = (Get-Date).ToString("HH:mm:ss")
        $txtConsole.AppendText("[$timestamp] $Message`r`n")
        $txtConsole.ScrollToEnd()
    })
}

function Update-PipelineStatus {
    param(
        [string]$StatusText,
        [string]$BgColor = "#313244",
        [string]$FgColor = "#89B4FA"
    )
    $window.Dispatcher.Invoke([Action]{
        $txtStatus.Text = $StatusText
        $txtStatus.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($FgColor)
        $badgeStatus.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($BgColor)
    })
}

# Non-blocking notification drawer (Zero modal popups)
function Show-NotificationDrawer {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Success", "Error", "Warning", "Info")]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Action1Text = $null,
        [scriptblock]$Action1Script = $null,

        [string]$Action2Text = $null,
        [scriptblock]$Action2Script = $null,

        [switch]$ShowCopyLog
    )

    $window.Dispatcher.Invoke([Action]{
        $notificationDrawer.Visibility = [System.Windows.Visibility]::Visible

        switch ($Type) {
            "Success" {
                $notificationDrawer.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#182A24")
                $notificationDrawer.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#A6E3A1")
                $txtDrawerIcon.Text = [char]0x2714 # Checkmark
                $txtDrawerIcon.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#A6E3A1")
                $txtDrawerTitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#A6E3A1")
            }
            "Error" {
                $notificationDrawer.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#2E1820")
                $notificationDrawer.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F38BA8")
                $txtDrawerIcon.Text = [char]0x2716 # Cross
                $txtDrawerIcon.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F38BA8")
                $txtDrawerTitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F38BA8")
            }
            "Warning" {
                $notificationDrawer.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#2E2418")
                $notificationDrawer.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FAB387")
                $txtDrawerIcon.Text = [char]0x26A0 # Warning triangle
                $txtDrawerIcon.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FAB387")
                $txtDrawerTitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FAB387")
            }
            "Info" {
                $notificationDrawer.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#182234")
                $notificationDrawer.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#89B4FA")
                $txtDrawerIcon.Text = [char]0x2139 # Info
                $txtDrawerIcon.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#89B4FA")
                $txtDrawerTitle.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#89B4FA")
            }
        }

        $txtDrawerTitle.Text = $Title
        $txtDrawerMessage.Text = $Message

        # Action 1
        if ($Action1Text -and $Action1Script) {
            $btnDrawerAction1.Content = $Action1Text
            $btnDrawerAction1.Visibility = [System.Windows.Visibility]::Visible
            $script:drawerAction1Handler = $Action1Script
        } else {
            $btnDrawerAction1.Visibility = [System.Windows.Visibility]::Collapsed
        }

        # Action 2
        if ($Action2Text -and $Action2Script) {
            $btnDrawerAction2.Content = $Action2Text
            $btnDrawerAction2.Visibility = [System.Windows.Visibility]::Visible
            $script:drawerAction2Handler = $Action2Script
        } else {
            $btnDrawerAction2.Visibility = [System.Windows.Visibility]::Collapsed
        }

        # Copy Log Button
        if ($ShowCopyLog) {
            $btnDrawerCopyLog.Visibility = [System.Windows.Visibility]::Visible
        } else {
            $btnDrawerCopyLog.Visibility = [System.Windows.Visibility]::Collapsed
        }
    })
}

function Hide-NotificationDrawer {
    $window.Dispatcher.Invoke([Action]{
        $notificationDrawer.Visibility = [System.Windows.Visibility]::Collapsed
    })
}

# Drawer Event Handlers
$btnDrawerDismiss.Add_Click({
    Hide-NotificationDrawer
})

$btnDrawerAction1.Add_Click({
    if ($script:drawerAction1Handler) {
        & $script:drawerAction1Handler
    }
})

$btnDrawerAction2.Add_Click({
    if ($script:drawerAction2Handler) {
        & $script:drawerAction2Handler
    }
})

$btnDrawerCopyLog.Add_Click({
    try {
        [System.Windows.Clipboard]::SetText($txtConsole.Text)
        $txtFooter.Text = "Diagnostic log copied to clipboard."
    } catch {}
})

# Main Execution Trigger
function Start-ProcessFile {
    param([string]$FilePath)

    if ($script:isProcessing) {
        Append-LogLine "[WARN] Pipeline is currently busy processing another file."
        return
    }

    if (-not (Test-Path $FilePath)) {
        Append-LogLine "[ERROR] Selected path does not exist: $FilePath"
        Show-NotificationDrawer -Type "Error" -Title "File Not Found" -Message "Path does not exist: $FilePath"
        return
    }

    $script:currentLoadedFile = $FilePath
    $script:isProcessing = $true
    $script:activeOutputFile = $null
    $btnOpenFolder.IsEnabled = $false
    $btnOpenFile.IsEnabled = $false
    $btnReRun.IsEnabled = $false
    Hide-NotificationDrawer
    $txtConsole.Clear()

    $fileInfo = Get-Item $FilePath
    $txtFileName.Text = $fileInfo.Name
    $txtFileSize.Text = " ($([Math]::Round($fileInfo.Length / 1MB, 2)) MB)"
    $analysisCard.Visibility = [System.Windows.Visibility]::Visible

    # Run binary inspection
    $analysis = Analyze-GameMakerBinary $FilePath
    $script:cachedAnalysis = $analysis
    $txtBadgeVersion.Text = $analysis.Version
    $txtConfidence.Text = "Confidence: $($analysis.Confidence)"
    $txtDetails.Text = $analysis.Details

    # Badge coloring
    $badgeBg = switch -regex ($analysis.Short) {
        "GM5" { "#A6E3A1" } # Mint green
        "GM6" { "#94E2D5" } # Teal
        "GM7" { "#89DCEB" } # Sky blue
        "GM8" { "#89B4FA" } # Blue
        "GMS" { "#CBA6F7" } # Mauve/Purple
        default { "#FAB387" } # Peach/Amber
    }
    $badgeVersion.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($badgeBg)

    Update-PipelineStatus "ANALYZING..." "#313244" "#89B4FA"
    $txtFooter.Text = "Decompiling $($fileInfo.Name)..."

    # Extract user interactive overrides from ComboBoxes
    $engineOverrideText = $cmbEngineOverride.Text
    $modeOverrideText = $cmbExtractionMode.Text

    # Warn if GameMaker Studio file detected
    if ($analysis.Short -eq "GMS") {
        Show-NotificationDrawer -Type "Warning" -Title "GameMaker Studio Executable Detected" `
            -Message "This file contains an IFF FORM chunk (data.win container). Legacy GMK decompilers cannot reconstruct Studio bytecode. UndertaleModTool (UTMT) is recommended for Studio titles." `
            -ShowCopyLog
    }

    # Run cascading decompiler pipeline on background thread
    [System.Threading.Tasks.Task]::Run([Action]{
        try {
            $logBlock = { param($msg) Append-LogLine $msg }
            $statusBlock = { param($msg) Update-PipelineStatus $msg }

            $result = Invoke-DecompilationPipeline -ExePath $FilePath -Analysis $analysis `
                -LogCallback $logBlock -StatusCallback $statusBlock `
                -EngineOverride $engineOverrideText -ModeOverride $modeOverrideText

            $window.Dispatcher.Invoke([Action]{
                if ($result.Success) {
                    $script:activeOutputFile = $result.OutputFile
                    Update-PipelineStatus "SUCCESS" "#A6E3A1" "#11111B"
                    $txtFooter.Text = "Decompiled successfully to: $($result.OutputFile)"
                    $btnOpenFolder.IsEnabled = $true
                    $btnOpenFile.IsEnabled = $true

                    Show-NotificationDrawer -Type "Success" -Title "Decompilation Completed" `
                        -Message "Extracted via $($result.Strategy) ($([Math]::Round($result.OutputSize / 1MB, 2)) MB in $($result.ElapsedMs) ms)." `
                        -Action1Text "Open Output Folder" -Action1Script {
                            if ($script:activeOutputFile) { Start-Process "explorer.exe" -ArgumentList "/select,`"$($script:activeOutputFile)`"" }
                        } `
                        -Action2Text "Open Project" -Action2Script {
                            if ($script:activeOutputFile) { Start-Process "$($script:activeOutputFile)" }
                        }
                } else {
                    Update-PipelineStatus "FAILED" "#F38BA8" "#11111B"
                    $txtFooter.Text = "Decompilation failed across all fallback strategies."

                    Show-NotificationDrawer -Type "Error" -Title "Decompilation Incomplete" `
                        -Message "All fallback strategies exhausted. You can retry with Lazy mode (-l) to bypass asset checks, or force a different engine version above." `
                        -Action1Text "Try Lazy Mode (-l)" -Action1Script {
                            $cmbExtractionMode.SelectedIndex = 2
                            Start-ProcessFile -FilePath $script:currentLoadedFile
                        } `
                        -Action2Text "Force GM8 Mode" -Action2Script {
                            $cmbEngineOverride.SelectedIndex = 2
                            Start-ProcessFile -FilePath $script:currentLoadedFile
                        } `
                        -ShowCopyLog
                }
                $script:isProcessing = $false
                $btnReRun.IsEnabled = $true
            })
        } catch {
            $err = $_
            $window.Dispatcher.Invoke([Action]{
                Append-LogLine "[FATAL ERROR] $err"
                Update-PipelineStatus "ERROR" "#F38BA8" "#11111B"
                $script:isProcessing = $false
                $btnReRun.IsEnabled = $true
                Show-NotificationDrawer -Type "Error" -Title "Execution Error" `
                    -Message "An unhandled exception occurred in the decompiler pipeline: $err" `
                    -ShowCopyLog
            })
        }
    })
}

# Re-run Button in Analysis Card
$btnReRun.Add_Click({
    if ($script:currentLoadedFile) {
        Start-ProcessFile $script:currentLoadedFile
    }
})

# ---------------------------------------------------------------------------------------
# Drag & Drop Event Handlers
# ---------------------------------------------------------------------------------------

$dropZone.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $e.Effects = [System.Windows.DragDropEffects]::Copy
        $dropZone.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#89B4FA")
        $dropZone.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#25273A")
        $dropTextMain.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#89B4FA")
    } else {
        $e.Effects = [System.Windows.DragDropEffects]::None
    }
    $e.Handled = $true
})

$dropZone.Add_DragOver({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $e.Effects = [System.Windows.DragDropEffects]::Copy
    }
    $e.Handled = $true
})

$dropZone.Add_DragLeave({
    param($sender, $e)
    $dropZone.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#45475A")
    $dropZone.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E1E2E")
    $dropTextMain.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#CDD6F4")
    $e.Handled = $true
})

$dropZone.Add_Drop({
    param($sender, $e)
    $dropZone.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#45475A")
    $dropZone.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E1E2E")
    $dropTextMain.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#CDD6F4")

    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $files = $e.Data.GetData([System.Windows.DataFormats]::FileDrop)
        if ($files -and $files.Length -gt 0) {
            Start-ProcessFile $files[0]
        }
    }
    $e.Handled = $true
})

# Allow dropping anywhere on the window
$window.Add_Drop({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.DataFormats]::FileDrop)) {
        $files = $e.Data.GetData([System.Windows.DataFormats]::FileDrop)
        if ($files -and $files.Length -gt 0) {
            Start-ProcessFile $files[0]
        }
    }
})

# Browse Button & DropZone Click
$browseAction = {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "GameMaker Executables (*.exe)|*.exe|All Files (*.*)|*.*"
    $dialog.Title = "Select GameMaker Executable"
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Start-ProcessFile $dialog.FileName
    }
}

$btnBrowse.Add_Click($browseAction)
$dropZone.Add_MouseDown({
    param($sender, $e)
    if ($e.LeftButton -eq [System.Windows.Input.MouseButtonState]::Pressed) {
        & $browseAction
    }
})

# Copy Log Button
$btnCopyLog.Add_Click({
    try {
        [System.Windows.Clipboard]::SetText($txtConsole.Text)
        $txtFooter.Text = "Log copied to clipboard!"
    } catch {
        $txtFooter.Text = "Failed to copy log."
    }
})

# Open Output Folder Button
$btnOpenFolder.Add_Click({
    if ($script:activeOutputFile -and (Test-Path $script:activeOutputFile)) {
        Start-Process "explorer.exe" -ArgumentList "/select,`"$($script:activeOutputFile)`""
    }
})

# Open Project Button
$btnOpenFile.Add_Click({
    if ($script:activeOutputFile -and (Test-Path $script:activeOutputFile)) {
        Start-Process $script:activeOutputFile
    }
})

# Initial Log Welcome
Append-LogLine "OpenGMK Decompiler Studio initialized."
$decompilerPath = Get-DecompilerExe
if ($decompilerPath) {
    Append-LogLine "Active decompiler: $decompilerPath"
} else {
    Append-LogLine "[WARN] Release decompiler binary not found. Please run 'run_gui.bat' to build it."
}
Append-LogLine "Ready for input. Drag & drop an .exe or click 'Select .EXE...' to begin."

# If file passed via CLI argument, kick it off immediately on load
if ($InputExe) {
    $window.Add_Loaded({
        Start-ProcessFile $InputExe
    })
}

# Set Window Icon if available
$iconPath = Join-Path $ScriptDir "assets\logo\gm8dec.ico"
if (-not (Test-Path $iconPath)) {
    $iconPath = Join-Path $ScriptDir "assets\logo\opengmk.ico"
}
if (Test-Path $iconPath) {
    try {
        $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create([System.Uri]::new($iconPath))
    } catch {}
}

# Show GUI
$app = New-Object System.Windows.Application
$app.Run($window) | Out-Null
