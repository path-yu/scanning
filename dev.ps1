[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$SkipInstall,
    [switch]$BuildHook,
    [string]$ApiAddr = '127.0.0.1:8898',
    [int]$WebPort = 5173,
    [string]$DataDir = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

function Write-Step([string]$Message) {
    Write-Host "[dev] $Message" -ForegroundColor Cyan
}

function Write-Warn([string]$Message) {
    Write-Host "[dev] $Message" -ForegroundColor Yellow
}

function Show-LogTail([string]$Path, [string]$Label, [int]$Lines = 20) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Write-Host "----- $Label（最后 $Lines 行）-----" -ForegroundColor DarkGray
    try {
        Get-Content -LiteralPath $Path -Tail $Lines | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } catch {
        # 日志文件可能仍被进程占用，忽略读取失败。
    }
}

function Require-Command([string]$Name, [string]$Hint) {
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) { throw "未找到 $Name。$Hint" }
    return $command.Source
}

function Assert-PortFree([string]$Addr, [string]$Label) {
    $parts = $Addr.Split(':')
    $port = 0
    if (-not [int]::TryParse($parts[$parts.Length - 1], [ref]$port)) {
        throw "$Label 地址无效: $Addr"
    }
    $hostName = if ($parts.Length -gt 1) { ($parts[0..($parts.Length - 2)] -join ':') } else { '127.0.0.1' }
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq $hostName -or $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::' } |
        Select-Object -First 1
    if ($listener) {
        $owner = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        $name = if ($owner) { $owner.ProcessName } else { '未知进程' }
        throw "$Label 端口 $port 已被 $name（PID $($listener.OwningProcess)）占用。请先停止它，或用 -ApiAddr / -WebPort 指定其他端口。"
    }
}

function Wait-Endpoint([string]$Url, [System.Diagnostics.Process]$Process, [string]$Label, [int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($Process -and $Process.HasExited) {
            throw "$Label 进程已退出（exit code $($Process.ExitCode)）。"
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) { return }
        } catch {
            # 服务尚未就绪，继续等待。
        }
        Start-Sleep -Milliseconds 300
    }
    throw "等待 $Label 就绪超时（$TimeoutSeconds 秒）：$Url"
}

$backend = $null
$web = $null
$backendOut = ''
$backendErr = ''
$webOut = ''
$webErr = ''
$exitCode = 0

try {
    $go = Require-Command 'go' '请安装 Go 1.24+ 并加入 PATH。'
    $node = Require-Command 'node' '请安装 Node.js 20+ 并加入 PATH。'
    $npm = Require-Command 'npm' '请安装 Node.js 20+ 并加入 PATH。'

    $webDir = Join-Path $root 'web'
    $viteEntry = Join-Path $webDir 'node_modules/vite/bin/vite.js'
    if (-not (Test-Path -LiteralPath $viteEntry)) {
        if ($SkipInstall) { throw 'web/node_modules 不存在；请先运行 npm install，或去掉 -SkipInstall。' }
        Write-Step '安装前端依赖（npm install）...'
        Push-Location -LiteralPath $webDir
        try {
            & $npm install --no-audit --no-fund
            if ($LASTEXITCODE -ne 0) { throw 'npm install 失败。' }
        } finally {
            Pop-Location
        }
    }

    $hookDll = Join-Path $root 'bin/hook/scanning_hook_x64.dll'
    $zig = Get-Command 'zig' -ErrorAction SilentlyContinue
    if ($BuildHook -or -not (Test-Path -LiteralPath $hookDll)) {
        if ($zig) {
            Write-Step '编译进程注入 Hook DLL ...'
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $hookDll) | Out-Null
            & $zig.Source cc -target x86_64-windows-gnu -shared -O2 -o $hookDll internal/hook/native/scanning_hook.c -lws2_32
            if ($LASTEXITCODE -ne 0) {
                if ($BuildHook) { throw 'Hook DLL 编译失败。' }
                Write-Warn 'Hook DLL 编译失败；进程注入功能不可用。'
            }
        } elseif ($BuildHook) {
            throw '未找到 zig，无法编译 Hook DLL。请安装 Zig 并加入 PATH。'
        } else {
            Write-Warn '未找到 Hook DLL，且未找到 zig；进程注入功能不可用，其他功能不受影响。'
        }
    }

    Assert-PortFree $ApiAddr 'API'
    Assert-PortFree "127.0.0.1:$WebPort" '前端'

    $devDir = Join-Path $root '.tmp/dev'
    $logDir = Join-Path $devDir 'logs'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $devBin = Join-Path $devDir 'scanning-dev.exe'

    Write-Step '编译后端（-tags dev）...'
    & $go build -tags dev -o $devBin ./cmd/scanning
    if ($LASTEXITCODE -ne 0) { throw '后端编译失败。' }

    $backendOut = Join-Path $logDir 'backend.log'
    $backendErr = Join-Path $logDir 'backend.err.log'
    Remove-Item -LiteralPath $backendOut, $backendErr -Force -ErrorAction SilentlyContinue

    $backendArgs = '--dev --no-open --addr "' + $ApiAddr + '"'
    if ($DataDir) { $backendArgs += ' --data-dir "' + $DataDir + '"' }
    Write-Step "启动后端：$devBin $backendArgs"
    $backend = Start-Process -FilePath $devBin -ArgumentList $backendArgs -WorkingDirectory $root -PassThru -NoNewWindow -RedirectStandardOutput $backendOut -RedirectStandardError $backendErr

    $apiUrl = "http://$ApiAddr/api/v1/health"
    Write-Step "等待后端就绪：$apiUrl"
    Wait-Endpoint -Url $apiUrl -Process $backend -Label '后端'

    $webOut = Join-Path $logDir 'web.log'
    $webErr = Join-Path $logDir 'web.err.log'
    Remove-Item -LiteralPath $webOut, $webErr -Force -ErrorAction SilentlyContinue
    $viteArgs = '"' + $viteEntry + '" --host 127.0.0.1 --port ' + [string]$WebPort + ' --strictPort'
    Write-Step "启动前端：node $viteEntry --port $WebPort"
    $web = Start-Process -FilePath $node -ArgumentList $viteArgs -WorkingDirectory $webDir -PassThru -NoNewWindow -RedirectStandardOutput $webOut -RedirectStandardError $webErr

    $webUrl = "http://127.0.0.1:$WebPort/"
    Write-Step "等待前端就绪：$webUrl"
    Wait-Endpoint -Url $webUrl -Process $web -Label '前端'

    $proxyAddr = '127.0.0.1:8899'
    $resolvedDataDir = if ($DataDir) { $DataDir } else { Join-Path $env:APPDATA 'Scanning' }
    try {
        $info = Invoke-RestMethod -Uri "http://$ApiAddr/api/v1/system/info" -TimeoutSec 3
        if ($info.data.proxy.addr) { $proxyAddr = $info.data.proxy.addr }
        if ($info.data.dataDir) { $resolvedDataDir = $info.data.dataDir }
    } catch {
        # 信息接口失败不影响启动，使用默认值展示。
    }

    Write-Host ''
    Write-Host 'Scanning 开发环境已启动' -ForegroundColor Green
    Write-Host "  前端  : http://127.0.0.1:$WebPort/"
    Write-Host "  API   : http://$ApiAddr  （--dev 已跳过鉴权）"
    Write-Host "  代理  : http://$proxyAddr"
    Write-Host "  数据  : $resolvedDataDir"
    Write-Host "  日志  : $logDir"
    Write-Host '  按 Ctrl+C 停止前后端。'

    if (-not $NoBrowser) {
        Start-Process "http://127.0.0.1:$WebPort/"
    }

    while ($true) {
        if ($backend.HasExited) { throw "后端已退出（exit code $($backend.ExitCode)）。" }
        if ($web.HasExited) { throw "前端已退出（exit code $($web.ExitCode)）。" }
        Start-Sleep -Milliseconds 500
    }
} catch {
    Write-Host "[dev] 错误：$($_.Exception.Message)" -ForegroundColor Red
    Show-LogTail $backendErr '后端错误日志' 30
    Show-LogTail $backendOut '后端输出' 15
    Show-LogTail $webErr '前端错误日志' 30
    Show-LogTail $webOut '前端输出' 15
    $exitCode = 1
} finally {
    foreach ($process in @($backend, $web)) {
        if ($null -eq $process) { continue }
        try {
            if (-not $process.HasExited) {
                & taskkill /PID $process.Id /T /F 2>$null | Out-Null
            }
        } catch {
            # 进程可能已退出，忽略清理失败。
        }
    }
    if ($backend -or $web) {
        Write-Host '[dev] 已停止开发进程。' -ForegroundColor DarkGray
    }
}

exit $exitCode
