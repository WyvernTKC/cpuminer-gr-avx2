#!/bin/bash

YELLOW='\033[1;31m'
SEA='\033[38;5;49m'
NC='\033[0m'

# Run miner.
function start_mining {
  echo -e "Starting ${SEA}${1}${NC} variant of the binaries."

  INST="$1"
  ./binaries/cpuminer-${INST} --config=config.json
  exit
}

# Override binaries to what user wants.
if [[ ! -z $1 ]]; then
  echo -e "${SEA}Running ${1} binaries specified by user.${NC}"
  start_mining "$1"
fi


# Detect all CPU parameters.
if [[ $USER != "root" ]]; then
  echo -e "${YELLOW}Please consider runnig as 'root' to enable MSR and Large Pages${NC}"
fi

LSCPU=$(lscpu)
MODEL_NAME=$(lscpu | egrep "Model name" | tr -s " " | cut -d":" -f 2-)

if lscpu | egrep -i "GenuineIntel" 1>/dev/null; then
  CPU_VENDOR="Intel"
  echo -n "Detected Intel CPU: "
elif lscpu | egrep -i "AuthenticAMD" 1>/dev/null; then
  CPU_VENDOR="AMD"
  CPU_FAMILY=$(lscpu | egrep -o -i "CPU family: +[0-9]+" | awk '{ print $3 }')
  if [[ $CPU_FAMILY == 25 ]]; then
    ZEN="zen3"
    echo -n "Detected AMD zen3 CPU: "
  elif [[ $CPU_FAMILY == 23 ]]; then
    CPU_MODEL=$(lscpu | egrep -o -i "Model: +[0-9]+" | awk '{ print $2 }')
    if [[ $CPU_MODEL == 1 || $CPU_MODEL == 17 || \
          $CPU_MODEL == 24 || $CPU_MODEL == 32 ]]; then
      ZEN="zen"
      echo -n "Detected AMD zen CPU: "
    elif [[ $CPU_MODEL == 8 || $CPU_MODEL == 24 ]]; then
      ZEN="zen+"
      echo -n "Detected AMD zen+ CPU: "
    elif [[ $CPU_MODEL == 49  || $CPU_MODEL == 71 || $CPU_MODEL == 96  || \
            $CPU_MODEL == 104 || $CPU_MODEL == 113 || $CPU_MODEL == 144 ]]; then
      ZEN="zen2"
      echo -n "Detected AMD zen2 CPU: "
    else
      echo -n "Detected AMD non-ZEN CPU: "
    fi
  fi
else
  CPU_VENDOR="Unknown"
  echo -n "Detected Unknown CPU: "
fi
echo -e "${SEA}${MODEL_NAME}${NC}"
if [[ $CPU_VENDOR == "AMD" ]]; then
  if echo $MODEL_NAME | egrep -i " ([53][69]00(X|XT)?|[0-9]{4}(U|H|HX|HS)) " 1>/dev/null; then
    if cat config.json | egrep -i "\"tune-full\" *: *false" 1>/dev/null 2>/dev/null; then
      echo -e "${SEA}Detected CPU model is very likely to benefit from 'tune-full'${NC}"  
      echo -e "${YELLOW}Changing 'tune-full' to 'true' in config.json is recommended!${NC}" 
    fi
  fi
fi

echo -ne "Available CPU Instructions: ${SEA}"

# Check AVX512 / AVX2 / AVX / SSE4.2
if lscpu | egrep -i " avx512f( |$)" 1>/dev/null && \
   lscpu | egrep -i " avx512dq( |$)" 1>/dev/null && \
   lscpu | egrep -i " avx512bw( |$)" 1>/dev/null && \
   lscpu | egrep -i " avx512vl( |$)" 1>/dev/null; then
  HAS_AVX512=1
  echo -n "AVX512 "
fi
if lscpu | egrep -i " avx2( |$)" 1>/dev/null; then
  HAS_AVX2=1
  echo -n "AVX2 "
fi
if lscpu | egrep -i " avx( |$)" 1>/dev/null; then
  HAS_AVX=1
  echo -n "AVX "
fi
if lscpu | egrep -i " sse4_2( |$)" 1>/dev/null; then
  HAS_SSE42=1
  echo -n "SSE42 "
fi

# Check VAES / AES
if lscpu | egrep -i " vaes( |$)" 1>/dev/null; then
  HAS_VAES=1
  echo -n "VAES "
fi
if lscpu | egrep -i " aes(_ni|-ni)?( |$)" 1>/dev/null; then
  HAS_AES=1
  echo -n "AES "
fi

# Check SHA
if lscpu | egrep -i " sha(_ni)?( |$)" 1>/dev/null; then
  HAS_SHA=1
  echo -n "SHA "
fi
echo -e "${NC}"


if [[ $ZEN == "zen" || $ZEN == "zen+" ]]; then
  # Sanity check
  if [[ $HAS_SHA && $HAS_AVX2 && $HAS_AES ]]; then
    start_mining "zen"
  else
    echo Problem detecting zen CPU? Instruction set does not match the model!
  fi
elif [[ $ZEN == "zen2" ]]; then
  # Sanity check
  if [[ $HAS_SHA && $HAS_AVX2 && $HAS_AES ]]; then
    start_mining "zen2"
  else
    echo Problem detecting zen2 CPU? Instruction set does not match the model!
  fi
elif [[ $ZEN == "zen3" ]]; then
  # Sanity check
  if [[ $HAS_SHA && $HAS_AVX2 && $HAS_VAES ]]; then
    start_mining "zen3"
  else
    echo Problem detecting zen3 CPU? Instruction set does not match the model!
  fi
fi

# Fallback for Intels and incorrectly detected AMDs and non-Ryzens.
if [[ $HAS_AVX512 && $HAS_SHA && $HAS_VAES ]]; then
  INST="avx512-sha-vaes"
elif [[ $HAS_AVX512 && $HAS_SHA ]]; then
  INST="avx512-sha"
elif [[ $HAS_AVX512 ]]; then
  INST="avx512"
elif [[ $HAS_AVX2 ]]; then
  INST="avx2"
elif [[ $HAS_AVX && $HAS_AES ]]; then
  # It is possible to have AVX but not AES.
  # Some OEM laptops have it disabled by default in the bios.
  INST="avx"
elif [[ $HAS_SSE42 && $HAS_AES ]]; then
  INST="aes-sse42"
elif [[ $HAS_SSE42 ]]; then
  INST="sse42"
else
  INST="sse2"
fi

start_mining "$INST"
