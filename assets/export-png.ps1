$ErrorActionPreference = "Continue"
$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$assets = "C:\LifeVault\LifeVault_Modern_UI_v3_Google\assets"
$work   = Join-Path $env:TEMP "lifevault_logo_png"
New-Item -ItemType Directory -Force -Path $work | Out-Null

function New-Shot([string]$name, [int]$w, [int]$h, [string]$body, [string]$out) {
    $html = "<!doctype html><html><head><meta charset='utf-8'><style>html,body{margin:0;padding:0;background:transparent}img{display:block}</style></head><body>$body</body></html>"
    $file = Join-Path $work "$name.html"
    Set-Content -Path $file -Value $html -Encoding ascii
    $png = Join-Path $work "$name.png"
    if (Test-Path $png) { Remove-Item $png -Force }
    $chromeArgs = @("--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
              "--default-background-color=00000000", "--window-size=$w,$h",
              "--screenshot=$png", "file:///$($file -replace '\\','/')")
    Start-Process -FilePath $chrome -ArgumentList $chromeArgs -Wait -WindowStyle Hidden | Out-Null
    Start-Sleep -Milliseconds 300
    if (Test-Path $png) {
        Copy-Item $png (Join-Path $assets $out) -Force
        Write-Output "OK  $out"
    } else {
        Write-Output "FAIL $out"
    }
}

# --- Mark at each pixel size ---
foreach ($s in @(16, 32, 64, 128, 256, 512)) {
    $body = "<img src='../lifevault-logo.svg' width='$s' height='$s'>"
    New-Shot -name "mark$s" -w $s -h $s -body $body -out "lifevault-logo-$s.png"
}

# --- Favicon set ---
foreach ($s in @(16, 32, 48)) {
    $body = "<img src='../lifevault-favicon.svg' width='$s' height='$s'>"
    New-Shot -name "fav$s" -w $s -h $s -body $body -out "lifevault-favicon-$s.png"
}

# --- Rounded app-icon tile 512 ---
$tile = "<div style='width:512px;height:512px;border-radius:114px;background:linear-gradient(155deg,#1D6B91 0%,#123554 52%,#0A1120 100%);display:flex;align-items:center;justify-content:center'>" +
        "<img src='../lifevault-logo.svg' width='384' height='384'></div>"
New-Shot -name "tile512" -w 512 -h 512 -body $tile -out "lifevault-app-icon-512.png"

# --- Horizontal lockup 3x ---
New-Shot -name "lock1332" -w 1332 -h 420 -body "<img src='../lifevault-logo-lockup.svg' width='1332' height='420'>" -out "lifevault-lockup.png"

# --- Horizontal lockup, dark background 3x ---
$dark = "<div style='width:1332px;height:420px;background:#0B1220;display:flex;align-items:center;padding-left:30px'>" +
        "<img src='../lifevault-logo.svg' width='228' height='228' style='margin-right:54px'>" +
        "<div><div style='font-family:Segoe UI,sans-serif;font-size:162px;font-weight:700;letter-spacing:-1.5px;color:#fff;line-height:1'>Life<span style='color:#67E8F9'>Vault</span></div>" +
        "<div style='font-family:Segoe UI,sans-serif;font-size:37px;font-weight:600;letter-spacing:7.2px;color:#7DD3FC;margin-top:12px'>DOCUMENT &amp; EMERGENCY VAULT</div></div></div>"
New-Shot -name "lockdark" -w 1332 -h 420 -body $dark -out "lifevault-lockup-dark.png"
