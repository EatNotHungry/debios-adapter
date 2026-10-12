# 一键推送脚本（私有仓库版）
# 用法：
#     .\push-private.ps1 -User 你的GitHub用户名 -Repo debios
#
# 与公开库版的区别：
#   1. 会问你要一个 GitHub Personal Access Token（用于 git 推送 + LFS 拉取）
#   2. 本地把 LFS 的 URL 指向带 token 的形式，避免私有库 LFS 认证失败
#   3. 提醒你：私有库跑 macOS runner 会扣分钟数（10 倍计费）

param(
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Repo,
    [string]$Email = "",
    [string]$Name  = ""
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "==== 0) 读取 token ====" -ForegroundColor Cyan
Write-Host "去这里建一个: https://github.com/settings/tokens  (勾 repo + workflow)"
$Token = Read-Host "粘贴 GitHub Personal Access Token (输入时不显示)" -AsSecureString
$TokenPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token))
if (-not $TokenPlain) { Write-Host "[!] token 为空，退出"; exit 1 }

Write-Host "`n==== 1) 检查 git ====" -ForegroundColor Cyan
git --version
if (-not (git rev-parse --is-inside-work-tree 2>$null)) { git init -b main }

Write-Host "`n==== 2) 提交身份 ====" -ForegroundColor Cyan
if (-not (git config --global user.name) -or -not (git config --global user.email)) {
    if (-not $Name)  { $Name  = Read-Host "git 用户名（随便）" }
    if (-not $Email) { $Email = Read-Host "邮箱（随便）" }
    git config --global user.name  $Name
    git config --global user.email $Email
}
Write-Host "[=] $(git config --global user.name) <$(git config --global user.email)>"

Write-Host "`n==== 3) LFS ====" -ForegroundColor Cyan
git lfs install --local
git lfs track "ci/*.ipa" | Out-Null
# 私有库：把 LFS 端点带上 token（只写在本地 .git/config，不会提交）
git config --local lfs.url "https://${User}:${TokenPlain}@github.com/${User}/${Repo}.git/info/lfs"
Write-Host "[+] lfs.url 已配置（本地）.gitattributes:"; Get-Content .gitattributes -ErrorAction SilentlyContinue

Write-Host "`n==== 4) 提交 ====" -ForegroundColor Cyan
git add -A
git -c user.name="$User" -c user.email="$(git config --global user.email)" `
    commit -m "T3 adapter: CI + adapter source + base ipa" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "[=] 无改动可提交" }
git log --oneline | Select-Object -First 3

Write-Host "`n==== 5) 远端（URL 里带 token，省得弹窗）====" -ForegroundColor Cyan
$url = "https://${User}:${TokenPlain}@github.com/${User}/${Repo}.git"
git remote remove origin 2>$null
git remote add origin $url
git remote -v

Write-Host "`n==== 6) 推送 ====" -ForegroundColor Cyan
git push -u origin main --force

Write-Host "`n==== 7) 提醒：把 token 存进 Secrets，CI 才能拉 LFS ====" -ForegroundColor Yellow
Write-Host "打开: https://github.com/$User/$Repo/settings/secrets/actions"
Write-Host "  New repository secret"
Write-Host "  Name : LFS_TOKEN"
Write-Host "  Value: （同一个 token）"
Write-Host ""
Write-Host "然后去 Actions 看看那次自动构建，或手动 Run workflow："
Write-Host "  https://github.com/$User/$Repo/actions"
