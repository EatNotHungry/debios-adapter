# 一键推送脚本（Windows PowerShell）
# 用法：右键“使用 PowerShell 运行”，或在终端里：
#     .\push.ps1 -User 你的GitHub用户名 -Repo 仓库名
#
# 前提：仓库名必须先在 GitHub 上创建好（空的即可，不要勾 README/.gitignore/License）
# 推送时会弹窗要求登录 GitHub（用浏览器授权 或 粘贴 Personal Access Token）

param(
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Repo,
    [string]$Email = "",
    [string]$Name  = ""
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

Write-Host "==== 1) 检查 git ====" -ForegroundColor Cyan
git --version
if (-not (git rev-parse --is-inside-work-tree 2>$null)) {
    Write-Host "[*] 初始化仓库"
    git init -b main
}

Write-Host "`n==== 2) 配置提交身份（没配过才需要）====" -ForegroundColor Cyan
$curName  = git config --global user.name
$curEmail = git config --global user.email
if (-not $curName -or -not $curEmail) {
    if (-not $Name)  { $Name  = Read-Host "请输入 git 用户名（随便，会显示在提交记录里）" }
    if (-not $Email) { $Email = Read-Host "请输入邮箱（随便，不会验证）" }
    git config --global user.name  $Name
    git config --global user.email $Email
    Write-Host "[+] 已设置: $Name <$Email>"
} else {
    Write-Host "[=] 已有身份: $curName <$curEmail>"
}

Write-Host "`n==== 3) 启用 LFS（base.ipa 走 LFS）====" -ForegroundColor Cyan
git lfs install --local
git lfs track "ci/*.ipa" | Out-Null
Write-Host "[+] .gitattributes:"; Get-Content .gitattributes

Write-Host "`n==== 4) 提交 ====" -ForegroundColor Cyan
git add -A
git status --short
git commit -m "T3 adapter: CI + adapter source + base ipa" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "[=] 没有新改动可提交" }

Write-Host "`n==== 5) 设置远端 ====" -ForegroundColor Cyan
$url = "https://github.com/$User/$Repo.git"
git remote remove origin 2>$null
git remote add origin $url
Write-Host "[+] origin = $url"

Write-Host "`n==== 6) 推送（会弹浏览器/让你贴 token）====" -ForegroundColor Cyan
git push -u origin main

Write-Host "`n==== 完成 ====" -ForegroundColor Green
Write-Host "打开: https://github.com/$User/$Repo/actions"
Write-Host "首次 push 会自动触发一次构建（因为 ci/base.ipa 已经在仓库里）"
