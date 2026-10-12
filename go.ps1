# =====================================================================
#  go.ps1 —— 一键搞定（建仓库 → 加 Secret → 推送 → 等 CI → 报结果）
#
#  用法（在解压出来的仓库目录里打开 PowerShell）：
#      .\go.ps1 -User EatNotHungry -Repo debios
#
#  需要：GitHub CLI（gh）。没有的话脚本会告诉你怎么装。
# =====================================================================

param(
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Repo,
    [switch]$Public,              # 加这个参数 = 建公开库（免费不限量），不加 = 私有库
    [switch]$SkipWait             # 不等待 CI，直接看完地址就退出
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Step($n, $t) { Write-Host "`n==== $n) $t ====" -ForegroundColor Cyan }
function Ok($t)   { Write-Host "  [OK] $t"   -ForegroundColor Green }
function Warn($t) { Write-Host "  [!]  $t"   -ForegroundColor Yellow }
function Die($t)  { Write-Host "  [X]  $t"   -ForegroundColor Red; exit 1 }

# ---------- 0. 检查 gh ----------
Step 0 "检查 GitHub CLI"
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Warn "没装 gh。二选一："
    Write-Host "     winget install --id GitHub.cli -e"
    Write-Host "     或去 https://cli.github.com/ 下载安装"
    Write-Host ""
    Write-Host "  装完重开一个 PowerShell，再跑一次本脚本。"
    Write-Host "  不想装 gh → 用 push.ps1 / push-private.ps1（手动建库 + 手动加 Secret）"
    exit 1
}
gh --version | Select-Object -First 1 | ForEach-Object { Ok $_ }

# ---------- 1. 登录 ----------
Step 1 "GitHub 登录状态"
gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Warn "还没登录，下面会弹设备码，去浏览器输一下"
    gh auth login --hostname github.com --git-protocol https --web
}
$who = (gh api user --jq .login)
Ok "已登录为 $who"

# ---------- 2. 建仓库（已存在就跳过） ----------
Step 2 "创建仓库 $User/$Repo"
$exists = $false
gh repo view "$User/$Repo" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { $exists = $true; Ok "仓库已存在，跳过创建" }
if (-not $exists) {
    if ($Public) {
        gh repo create "$User/$Repo" --public  --description "T3 adapter build" | Out-Null
        Ok "已创建公开仓库"
    } else {
        gh repo create "$User/$Repo" --private --description "T3 adapter build" | Out-Null
        Ok "已创建私有仓库"
    }
}

# ---------- 3. 建一个 PAT 给 CI 拉 LFS 用 ----------
Step 3 "准备 LFS_TOKEN（CI 拉 LFS 用）"
Write-Host "  去这里建 token（勾 repo + workflow）: https://github.com/settings/tokens"
$tok = Read-Host "  粘贴 token（私有库必填；公开库直接回车跳过）" -AsSecureString
$tokPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tok))
$tokPlain = $tokPlain.Trim()

# ---------- 4. git 身份 ----------
Step 4 "git 提交身份"
if (-not (git config --global user.name))  { git config --global user.name  $User }
if (-not (git config --global user.email)) { git config --global user.email "$User@users.noreply.github.com" }
Ok "$(git config --global user.name) <$(git config --global user.email)>"

# ---------- 5. LFS + 提交 + 推送 ----------
Step 5 "LFS / 提交 / 推送"
git lfs install --local | Out-Null
git lfs track "ci/*.ipa" | Out-Null
git add -A
git -c user.name="$User" -c user.email="$(git config --global user.email)" `
    commit -m "T3 adapter: CI + adapter source + base ipa" 2>$null
if ($LASTEXITCODE -ne 0) { Warn "无新改动可提交，沿用已有 commit" }

git remote remove origin 2>$null
git remote add origin "https://github.com/$User/$Repo.git"

if ($tokPlain) {
    # 带 token 推，避免弹窗
    git push -f "https://${User}:${tokPlain}@github.com/${User}/${Repo}.git" "HEAD:refs/heads/main"
    git config --local lfs.url "https://${User}:${tokPlain}@github.com/${User}/${Repo}.git/info/lfs"
    git lfs push --all "https://${User}:${tokPlain}@github.com/${User}/${Repo}.git" main
} else {
    git push -u origin main
    git lfs push --all origin main
}
Ok "推送完成"

# 默认分支名兜底
if ($tokPlain) {
    try {
        gh api -X PATCH "repos/$User/$Repo" -f default_branch=main | Out-Null
    } catch { }
}

# ---------- 6. 写 Secret ----------
Step 6 "写入 LFS_TOKEN Secret"
if ($tokPlain) {
    $tokPlain | gh secret set LFS_TOKEN --repo "$User/$Repo"
    Ok "LFS_TOKEN 已写入"
} else {
    Warn "没给 token，跳过。私有库必须手动加："
    Write-Host "     https://github.com/$User/$Repo/settings/secrets/actions"
}

# ---------- 7. 触发 + 等 CI ----------
Step 7 "触发构建"
gh workflow run "build.yml" --repo "$User/$Repo" --ref main 2>&1 | Out-Null
Start-Sleep -Seconds 6
$runId = gh run list --repo "$User/$Repo" --limit 1 --json databaseId --jq '.[0].databaseId'
Ok "已触发，run id = $runId"
Write-Host "  页面: https://github.com/$User/$Repo/actions"

if (-not $SkipWait) {
    Write-Host "`n  正在等构建结束（首次要装 ldid，约 3~6 分钟）..." -ForegroundColor Yellow
    gh run watch $runId --repo "$User/$Repo" --exit-status
    if ($LASTEXITCODE -eq 0) {
        Ok "构建成功，开始下载产物"
        New-Item -ItemType Directory -Force -Path out | Out-Null
        gh run download $runId --repo "$User/$Repo" --dir out
        Get-ChildItem -Recurse out | Select-Object FullName, Length | Format-Table -AutoSize
        Ok "产物在 .\out\ 下面"
    } else {
        Warn "构建失败，打印最后 120 行日志："
        gh run view $runId --repo "$User/$Repo" --log-failed | Select-Object -Last 120
    }
}

Write-Host "`n==== 全部完成 ====" -ForegroundColor Green
Write-Host "仓库:  https://github.com/$User/$Repo"
Write-Host "构建:  https://github.com/$User/$Repo/actions"
