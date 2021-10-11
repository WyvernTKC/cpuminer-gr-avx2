@echo off
@SetLocal EnableExtensions
@SetLocal EnableDelayedExpansion
@cd /d "%~dp0"

REM Add proper binary instruction set in INST_OVERRIDE to force use those binaries.
REM To check whichi ones are avaliable refer to readme.txt or use program like CPU-Z. 
REM Binaries: sse2 sse42 aes-sse42 avx avx2 zen zen2 zen3 avx512 avx512-sha avx512-sha-vaes
set INST_OVERRIDE=
if NOT "%INST_OVERRIDE%" == "" (
  call :RunOverride %INST_OVERRIDE% "User Defined"
)

for /f "tokens=1 delims=" %%a in ('wmic cpu get Manufacturer') do for %%b in (%%a) do set MANUFACTURER=%%a
for /f "tokens=1 delims=" %%a in ('wmic cpu get Caption') do for %%b in (%%a) do set CPUCAPTION=%%a
for /f "tokens=1 delims=" %%a in ('wmic cpu get Description') do for %%b in (%%a) do set CPUDESCRIPTION=%%a

call :Trim MANUFACTURER %MANUFACTURER%
call :Trim CPUCAPTION %CPUCAPTION%
call :Trim CPUDESCRIPTION %CPUDESCRIPTION%

set /a CPU_FAMILY=0
set /a CPU_MODEL=0

set /a TYPE=0
for %%a in (%CPUCAPTION%) do ( 
  if !TYPE! equ 1 (
    set /a CPU_FAMILY="%%a"
    set /a TYPE=0
  )
  if !TYPE! equ 2 (
    set /a CPU_MODEL="%%a"
    set /a TYPE=0
  )
  if /I "%%a" == "Family" ( set /a TYPE=1 )
  if /I "%%a" == "Model" ( set /a TYPE=2 )
)
set USE_UNKNOWN=sse2


REM MANUFACTURER -> Manufacturer of the CPU. GenuineIntel or AuthenticAMD
REM CPU_FAMILY & CPU_MODEL can be used to determine instruction set.
echo Detected CPU Family: %CPU_FAMILY%
echo Detected CPU Model:  %CPU_MODEL%


REM Detected Intel
if /I !MANUFACTURER! == GenuineIntel (
  echo Detected %MANUFACTURER% CPU
  if NOT !CPU_FAMILY! EQU 6 (
    echo Unknowsn CPU Family - %CPU_FAMILY%
    call :RunUnknown "Unknown Intel Family"
  )
  
  REM CPU family == 6 - Default Intel family of consumer and server CPUs.
  REM List of used CPU Model numbers taken from: https://en.wikichip.org/wiki/intel/cpuid
  REM Big Cores (Client)
  REM Alder Lake S, P
  if !CPU_MODEL! EQU 151 ( call :RunBinary avx512-sha "Alder Lake (C)" )
  if !CPU_MODEL! EQU 154 ( call :RunBinary avx512-sha "Alder Lake (C)" )
  REM Rocket Lake S
  if !CPU_MODEL! EQU 167 ( call :RunBinary avx512-sha-vaes "Rocket Lake (C)" )
  REM Tiger Lake H, U
  if !CPU_MODEL! EQU 141 ( call :RunBinary avx512-sha "Tiger Lake (C)" )
  if !CPU_MODEL! EQU 140 ( call :RunBinary avx512-sha "Tiger Lake (C)" )
  REM Ice Lake U & Y
  if !CPU_MODEL! EQU 126 ( call :RunBinary avx512-sha-vaes "Ice Lake (C)" )
  if !CPU_MODEL! EQU 125 ( call :RunBinary avx512-sha-vaes "Ice Lake (C)" )
  REM Comet Lake S, H
  if !CPU_MODEL! EQU 165 ( call :RunBinary avx2 "Comet Lake (C)" )
  REM Comet Lake U & Amber Lake Y & Whiskey Lake U
  if !CPU_MODEL! EQU 142 ( call :RunBinary avx2 "Comet Lake & Amber Lake & Whiskey Lake (C)" )
  REM Cannon Lake U
  if !CPU_MODEL! EQU 102 ( call :RunBinary avx512-sha "Cannon Lake (C)" )
  REM Coffee Lake S, H, E & U
  if !CPU_MODEL! EQU 158 ( call :RunBinary avx2 "Coffee Lake (C)" )
  if !CPU_MODEL! EQU 142 ( call :RunBinary avx2 "Coffee Lake (C)" )
  REM Kaby Lake DT, H, S, X & Y, U
  if !CPU_MODEL! EQU 158 ( call :RunBinary avx2 "Kaby Lake (C)" )
  if !CPU_MODEL! EQU 142 ( call :RunBinary avx2 "Kaby Lake (C)" )
  REM Skylake (Client) DT, H, S & Y, U
  if !CPU_MODEL! EQU 94 ( call :RunBinary avx2 "Skylake (C)" )
  if !CPU_MODEL! EQU 78 ( call :RunBinary avx2 "Skylake (C)" )
  REM Broadwell (Client) C, W, H & U, Y, S
  if !CPU_MODEL! EQU 71 ( call :RunBinary avx2 "Broadwell (C)" )
  if !CPU_MODEL! EQU 61 ( call :RunBinary avx2 "Broadwell (C)" )
  REM Haswell (Client) GT3E & ULT & S
  if !CPU_MODEL! EQU 74 ( call :RunBinary avx2 "Haswell (C)" )
  if !CPU_MODEL! EQU 71 ( call :RunBinary avx2 "Haswell (C)" )
  if !CPU_MODEL! EQU 69 ( call :RunBinary avx2 "Haswell (C)" )
  if !CPU_MODEL! EQU 61 ( call :RunBinary avx2 "Haswell (C)" )
  if !CPU_MODEL! EQU 60 ( call :RunBinary avx2 "Haswell (C)" )
  REM Ivy Bridge (Client) M, H, Gladden
  if !CPU_MODEL! EQU 58 ( call :RunBinary avx "Ivy Bridge (C)" )
  REM Sandy Bridge (Client) M, H
  if !CPU_MODEL! EQU 42 ( call :RunBinary avx "Sandy Bridge (C)" )
  REM Westmere (Client) Arrandale, Clarkdale
  if !CPU_MODEL! EQU 37 ( call :RunBinary aes-sse42 "Westmere (C)" )
  REM Nehalem (Client) Auburndale, Havendale & Clarksfield
  if !CPU_MODEL! EQU 31 ( call :RunBinary sse42 "Nehalem (C)" )
  if !CPU_MODEL! EQU 30 ( call :RunBinary sse42 "Nehalem (C)" )
  
  REM Big Cores (Server)
  REM Sapphire Rapids
  if !CPU_MODEL! EQU 143 ( call :RunBinary avx512-sha "Sapphire Rapids (S)" )
  REM Ice Lake (Server) DE & SP
  if !CPU_MODEL! EQU 108 ( call :RunBinary avx512-sha-vaes "Ice Lake (S)" )
  if !CPU_MODEL! EQU 106 ( call :RunBinary avx512-sha-vaes "Ice Lake (S)" )
  REM Cooper Lake & Cascade Lake SP, X, W & Skylake (Server) SP, X, DE, W
  if !CPU_MODEL! EQU 85 ( call :RunBinary avx512 "Copper Lake & Cascade Lake & Skylake (S)" )
  REM Broadwell (Server) E, EP, EX & DE, Hewitt Lake
  if !CPU_MODEL! EQU 79 ( call :RunBinary avx2 "Broadwell & Hewitt Lake (S)" )
  if !CPU_MODEL! EQU 86 ( call :RunBinary avx2 "Broadwell & Hewitt Lake (S)" )
  REM Haswell (Server) E, EP, EX
  if !CPU_MODEL! EQU 63 ( call :RunBinary avx2 "Haswell (S)" )
  REM Ivy Bridge (Server) E, EN, EP, EX
  if !CPU_MODEL! EQU 62 ( call :RunBinary avx "Ivy Bridge (S)" )
  REM Sandy Bridge (Server) E, EN, EP
  if !CPU_MODEL! EQU 45 ( call :RunBinary avx "Sandy Bridge (S)" )
  REM Westmere (Server) Gulftown, EP & EX
  if !CPU_MODEL! EQU 44 ( call :RunBinary aes-sse42 "Westmere (S)" )
  if !CPU_MODEL! EQU 47 ( call :RunBinary aes-sse42 "Westmere (S)" )
  REM Nehalem (Server) EX & Lynnfield & Bloomfield, EP, WS
  if !CPU_MODEL! EQU 46 ( call :RunBinary sse42 "Nehalem (S)" )
  if !CPU_MODEL! EQU 30 ( call :RunBinary sse42 "Nehalem (S)" )
  if !CPU_MODEL! EQU 26 ( call :RunBinary sse42 "Nehalem (S)" )
  REM Penryn (Server) Dunnington & Harpertown, QC, Wolfdale, Yorkfield
  if !CPU_MODEL! EQU 29 ( call :RunBinary sse2 "Penryn (S)" )
  if !CPU_MODEL! EQU 23 ( call :RunBinary sse2 "Penryn (S)" )

  call :RunBinary sse2 "Generic"
)

REM Detected AMD
if /I !MANUFACTURER! == AuthenticAMD (
  echo Detected %MANUFACTURER% CPU
  if !CPU_FAMILY! EQU 25 (
    echo Detected Zen3 CPU
    call :RunBinary zen3 "Zen3"
  )

  if !CPU_FAMILY! EQU 24 (
    echo Detected Zen CPU
    call :RunBinary zen "Zen"
  )

  if !CPU_FAMILY! EQU 23 (
    REM Detect Zen2
    if !CPU_MODEL! EQU 144 ( call :RunBinary zen2 "Zen2" )
    if !CPU_MODEL! EQU 113 ( call :RunBinary zen2 "Zen2" )
    if !CPU_MODEL! EQU 104 ( call :RunBinary zen2 "Zen2" )
    if !CPU_MODEL! EQU 96 ( call :RunBinary zen2 "Zen2" )
    if !CPU_MODEL! EQU 71 ( call :RunBinary zen2 "Zen2" )
    if !CPU_MODEL! EQU 49 ( call :RunBinary zen2 "Zen2" )

    REM Detect Zen+
    if !CPU_MODEL! EQU 24 ( call :RunBinary zen "Zen+" )
    if !CPU_MODEL! EQU 8 ( call :RunBinary zen "Zen+" )
    
    REM Detect Zen
    if !CPU_MODEL! EQU 32 ( call :RunBinary zen "Zen" )
    if !CPU_MODEL! EQU 24 ( call :RunBinary zen "Zen" )
    if !CPU_MODEL! EQU 17 ( call :RunBinary zen "Zen" )
    if !CPU_MODEL! EQU 1 ( call :RunBinary zen "Zen" )

    echo Detected unknown Ryzen CPU.
    call :RunUnknown "Unknown Ryzen"
  )

  if !CPU_FAMILY! EQU 21 (
    REM Detect Bulldozer
    if !CPU_MODEL! EQU 1 ( call :RunBinary avx "Bulldozer" )
    
    REM Detect Piledriver
    if !CPU_MODEL! EQU 2 ( call :RunBinary avx "Piledriver" )
    if !CPU_MODEL! EQU 17 ( call :RunBinary avx "Piledriver" )
    if !CPU_MODEL! EQU 19 ( call :RunBinary avx "Piledriver" )

    REM Detect Steamroller
    if !CPU_MODEL! EQU 48 ( call :RunBinary avx "Steamroller" )
    if !CPU_MODEL! EQU 56 ( call :RunBinary avx "Steamroller" )
    
    REM Detect Excavator
    if !CPU_MODEL! EQU 96 ( call :RunBinary avx2 "Excavator" )
    if !CPU_MODEL! EQU 101 ( call :RunBinary avx2 "Excavator" )
    if !CPU_MODEL! EQU 112 ( call :RunBinary avx2 "Excavator" )

    echo Detected unknown non-Ryzen CPU.
    call :RunUnknown "Unknown non-Ryzen"
  )
  
  echo Detected unknown AMD CPU.
  call :RunUnknown "Unknown AMD"
)

REM Unknown CPU? use SSE2 to be safe.
echo Detected Unknown CPU - %MANUFACTURER%
echo Detected CPU Caption - %CPUCAPTION%
echo Detected CPU Description - %CPUDESCRIPTION%
call :RunUnknown "Unknown"

:Trim
SetLocal EnableDelayedExpansion
set Params=%*
for /f "tokens=1*" %%a in ("!Params!") do EndLocal & set %1=%%b
exit /b

:RunUnknown
echo Using %USE_UNKNOWN% by default. Change line 6 and 9 if CPU was not detected properly.
echo Detected Unknown CPU - %MANUFACTURER%
echo Detected CPU Caption - %CPUCAPTION%
echo Detected CPU Description - %CPUDESCRIPTION%
call :RunBinary %USE_UNKNOWN% %1

:RunOverride
call :RunBinary %1 %2

:RunBinary
echo Detected %1 compatible binary with %2 architecture
echo Change line 6 and 9 if CPU was not detected properly.

binaries\cpuminer-%1.exe --config=config.json
timeout 5 > NUL
call :RunBinary %1 %2

:Exit
pause
exit
