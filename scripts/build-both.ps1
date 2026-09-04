param(
    [switch]$Offline,
    [string]$ZigPath
)

$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$cacheRoot = 'E:\Catch\Cargo\Catch'
$rustupRoot = 'E:\Catch\Cargo\.rustup'
$tempRoot = Join-Path $cacheRoot 'tmp'
$zigbuildCacheRoot = Join-Path $cacheRoot 'zigbuild'
$targetRoot = Join-Path $projectRoot 'target'
$cargoBin = Join-Path $cacheRoot 'bin'

New-Item -ItemType Directory -Force -Path $tempRoot, $zigbuildCacheRoot, $targetRoot | Out-Null

function Resolve-ExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$Fallback
    )

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    if ($Fallback -and (Test-Path -LiteralPath $Fallback -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $Fallback).Path
    }
    throw "找不到 $Name；请将它加入 PATH，或放到 $Fallback。"
}

function Resolve-ZigPath {
    if ($ZigPath) {
        if (-not (Test-Path -LiteralPath $ZigPath -PathType Leaf)) {
            throw "指定的 Zig 不存在: $ZigPath"
        }
        return (Resolve-Path -LiteralPath $ZigPath).Path
    }

    $command = Get-Command zig -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        'G:\zig.exe',
        'G:\zig\zig.exe'
    )
    $zigDirectories = Get-ChildItem -LiteralPath 'G:\Program Files' -Directory -Filter 'zig-*' -ErrorAction SilentlyContinue
    foreach ($directory in $zigDirectories) {
        $candidates += Join-Path $directory.FullName 'zig.exe'
    }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw '找不到 Zig；请使用 -ZigPath G:\...\zig.exe 指定。'
}

$cargo = Resolve-ExecutablePath -Name 'cargo' -Fallback (Join-Path $cargoBin 'cargo.exe')
$cargoZigbuild = Resolve-ExecutablePath -Name 'cargo-zigbuild' -Fallback (Join-Path $cargoBin 'cargo-zigbuild.exe')
$zig = Resolve-ZigPath
$rustup = Resolve-ExecutablePath -Name 'rustup'

$installedTargets = & $rustup target list --installed
if ($LASTEXITCODE -ne 0) {
    throw '无法读取 rustup target 列表。'
}
foreach ($target in @('x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu')) {
    if ($installedTargets -notcontains $target) {
        throw "缺少 Rust target $target；先执行: rustup target add $target"
    }
}

$zigDirectory = Split-Path -Parent $zig
$toolPath = "$cargoBin;$zigDirectory;$env:PATH"
$commonEnvironment = @{
    CARGO_HOME = $cacheRoot
    RUSTUP_HOME = $rustupRoot
    TEMP = $tempRoot
    TMP = $tempRoot
    CARGO_ZIGBUILD_CACHE_DIR = $zigbuildCacheRoot
    PATH = $toolPath
    CARGO_TERM_COLOR = 'always'
}

$buildEnvironment = $commonEnvironment.Clone()
$buildEnvironment['CARGO_TARGET_DIR'] = $targetRoot

$baseArguments = @('--release', '--locked')
if ($Offline) {
    $baseArguments += '--offline'
}
$windowsArguments = @('build') + $baseArguments + @('--target', 'x86_64-pc-windows-msvc')
$linuxArguments = @('zigbuild') + $baseArguments + @('--target', 'x86_64-unknown-linux-gnu')

Write-Host "启动串行构建" -ForegroundColor Cyan
Write-Host "  Windows: $($windowsArguments -join ' ')" -ForegroundColor DarkGray
Write-Host "  Linux:   cargo-zigbuild $($linuxArguments -join ' ')" -ForegroundColor DarkGray
Write-Host "  缓存:    $cacheRoot" -ForegroundColor DarkGray
Write-Host "  产物:    $targetRoot" -ForegroundColor DarkGray

function Invoke-BuildStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host "[$Label]" -ForegroundColor Cyan
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $projectRoot `
        -Environment $buildEnvironment `
        -NoNewWindow `
        -Wait `
        -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$Label 失败，退出码 $($process.ExitCode)。"
    }
}

Invoke-BuildStep -Label '清理' -FilePath $cargo -Arguments @('clean')
Invoke-BuildStep -Label 'Windows' -FilePath $cargo -Arguments $windowsArguments
Invoke-BuildStep -Label 'Linux' -FilePath $cargoZigbuild -Arguments $linuxArguments

$windowsArtifact = Join-Path $targetRoot 'x86_64-pc-windows-msvc\release\RemoteOpenPower.exe'
$linuxArtifact = Join-Path $targetRoot 'x86_64-unknown-linux-gnu\release\RemoteOpenPower'
if (-not (Test-Path -LiteralPath $windowsArtifact -PathType Leaf)) {
    throw "Windows 构建完成但未找到产物: $windowsArtifact"
}
if (-not (Test-Path -LiteralPath $linuxArtifact -PathType Leaf)) {
    throw "Linux 构建完成但未找到产物: $linuxArtifact"
}

Write-Host '串行构建完成' -ForegroundColor Green
Write-Host "  Windows: $windowsArtifact"
Write-Host "  Linux:   $linuxArtifact"
