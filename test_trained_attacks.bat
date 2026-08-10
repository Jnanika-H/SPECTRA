@echo off
echo ========================================
echo Creating Test Folders for SPECTRA
echo ========================================
echo.

REM Test 1: Trained Attack Types (should score HIGH 80-98)
echo Creating C:\TrainedAttackTest...
mkdir "C:\TrainedAttackTest" 2>nul

echo test > "C:\TrainedAttackTest\ddos_attack.exe"
echo test > "C:\TrainedAttackTest\ddos_tool.exe"
echo test > "C:\TrainedAttackTest\infiltration.exe"
echo test > "C:\TrainedAttackTest\apt_malware.exe"
echo test > "C:\TrainedAttackTest\sql_injection.exe"
echo test > "C:\TrainedAttackTest\xss_exploit.exe"
echo test > "C:\TrainedAttackTest\bruteforce.exe"
echo test > "C:\TrainedAttackTest\password_cracker.exe"

echo [OK] Created 8 files in C:\TrainedAttackTest
echo.

REM Test 2: Unseen Attack Type (PortScan - should score MEDIUM-HIGH 60-85)
echo Creating C:\UnseenAttackTest...
mkdir "C:\UnseenAttackTest" 2>nul

echo test > "C:\UnseenAttackTest\portscan.exe"
echo test > "C:\UnseenAttackTest\network_scanner.exe"
echo test > "C:\UnseenAttackTest\nmap.exe"
echo test > "C:\UnseenAttackTest\port_probe.exe"
echo test > "C:\UnseenAttackTest\recon_tool.exe"

echo [OK] Created 5 files in C:\UnseenAttackTest
echo.

REM Test 3: Benign Files (should score LOW 0-10)
echo Creating C:\BenignTest...
mkdir "C:\BenignTest" 2>nul

echo test > "C:\BenignTest\report.pdf"
echo test > "C:\BenignTest\data.xlsx"
echo test > "C:\BenignTest\document.docx"
echo test > "C:\BenignTest\notes.txt"
echo test > "C:\BenignTest\image.jpg"

echo [OK] Created 5 files in C:\BenignTest
echo.

echo ========================================
echo Test Folders Created Successfully!
echo ========================================
echo.
echo NEXT STEPS:
echo.
echo 1. Open SPECTRA: http://localhost:3000
echo 2. Login: admin / admin123
echo 3. Go to Ingest tab
echo.
echo TEST 1 - Trained Attacks (should score 80-98):
echo    Path: C:\TrainedAttackTest
echo    Case ID: CASE-TRAINED
echo    Click: Ingest -^> Run Analysis
echo    Expected: All files score 80-98 (Critical/High)
echo.
echo TEST 2 - Unseen Attacks (should score 60-85):
echo    Path: C:\UnseenAttackTest
echo    Case ID: CASE-UNSEEN
echo    Click: Ingest -^> Run Analysis
echo    Expected: All files score 60-85 (Medium/High)
echo.
echo TEST 3 - Benign Files (should score 0-10):
echo    Path: C:\BenignTest
echo    Case ID: CASE-BENIGN
echo    Click: Ingest -^> Run Analysis
echo    Expected: All files score 0-10 (Informational)
echo.
echo ========================================
pause
