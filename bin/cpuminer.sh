#!/usr/bin/env bash
# -*- sh-basic-offset: 2; -*-

location=$(dirname -- "$0")
config=$location/config.json

hl () {
  echo $'\e[38;5;49m'"$*"$'\e[0m'
}

warn () {
  echo $'\e[1;33m'"$*"$'\e[0m'
}

# Run miner.
start_mining () {
  echo "Starting $(hl "$1") variant of the binaries."
  exec "$location/binaries/cpuminer-$1" --config="$config"
}

# Parse /proc/cpuinfo into outer assoc array $cpu.
parse_cpuinfo () {
  local key val
  cpu=()

  while IFS=: read -r key val; do
    # Cores in input are separated with empty lines. Only parse the
    # first core.
    [[ -n $key ]] || break

    key=${key%${key##*[^[:blank:]]}} # rtrim
    val=${val#${val%%[^[:blank:]]*}} # ltrim

    # Replace spaces with underscores in keys.
    key=${key// /_}

    cpu[${key,,}]=$val
  done < /proc/cpuinfo
}

# Extend outer assoc array $cpu with some keys:
# - vendor
# - vendor_long (optional)
# - zen (zen cpus only)
cpu_set_extra () {
  case ${cpu[vendor_id],,} in
    genuineintel)
      cpu[vendor]=Intel ;;

    authenticamd)
      cpu[vendor]=AMD

      # https://en.wikichip.org/wiki/amd/cpuid
      case ${cpu[cpu_family]} in
        25)
          cpu[zen]=zen3 ;;

        23)
          case ${cpu[model]} in
            1|17|32)
              cpu[zen]=zen ;;

            8|24)
              cpu[zen]=zen+ ;;

            49|71|96|104|113|144)
              cpu[zen]=zen2 ;;
          esac ;;
      esac

      cpu[vendor_long]="AMD ${cpu[zen]-non-ZEN}" ;;

    *)
      cpu[vendor]=Unknown ;;
  esac
}

check_tune_full () {
  if [[ ${cpu[vendor],,} == amd ]] &&
       [[ ${cpu[model_name]^^} =~ [[:space:]]([53][69]00(X|XT)?|[0-9]{4}(U|H|HX|HS))[[:space:]] ]] &&
       grep -qiE '"tune-full" *: *false' "$config" 2>/dev/null; then

    hl "Detected CPU model is very likely to benefit from 'tune-full'."
    warn "Changing 'tune-full' to 'true' in config.json is recommended!"
  fi
}

# Parse ${cpu[flags]} into outer array $features and prepare outer
# $_features string to match for words in has().
parse_features () {
  features=()

  # Make if easy to match for words.
  local flags=,${cpu[flags]// /,},

  # Check AVX512 / AVX2 / AVX / SSE4.2
  [[ $flags =~ ,avx512(f|dq|bw|vl), ]] && features+=(avx512)
  [[ $flags =~ ,avx2, ]] && features+=(avx2)
  [[ $flags =~ ,avx, ]] && features+=(avx)
  [[ $flags =~ ,sse4_2, ]] && features+=(sse42)

  # Check VAES / AES
  [[ $flags =~ ,vaes, ]] && features+=(vaes)
  [[ $flags =~ ,aes([_-]ni)?, ]] && features+=(aes)

  # Check SHA
  [[ $flags =~ ,sha(_ni)?, ]] && features+=(sha)

  # Stringify the array.
  printf -v _features ',%s' "${features[@]}"
  _features+=,
}

# Match for words (all must match) in outer string $_features.
has () {
  local arg
  for arg; do
    [[ $_features =~ ,"$arg", ]] || return
  done
}

# Override binaries to what user wants.
if [[ -n $1 ]]; then
  hl "Running $1 binaries specified by user."
  start_mining "$1"
fi

[[ $EUID == 0 ]] || warn "Please consider running as 'root' to enable MSR and Large Pages."

# Detect all CPU parameters.

declare -A cpu
parse_cpuinfo
cpu_set_extra

echo "Detected ${cpu[vendor_long]-${cpu[vendor]}} CPU: $(hl "${cpu[model_name]}")"

check_tune_full

declare features _features
parse_features

echo "Available CPU Instructions: $(hl "${features[@]^^}")"

if [[ -v cpu[zen] ]]; then
  case ${cpu[zen]} in
    zen|'zen+')
      has avx2 sha aes && start_mining zen ;;
    zen2)
      has avx2 sha aes && start_mining zen2 ;;
    zen3)
      has avx2 sha vaes && start_mining zen3 ;;
  esac

  echo "Problem detecting ${cpu[zen]} CPU?" "$(warn 'Instruction set does not match the model!')"
fi

# Fallback for Intels and incorrectly detected AMDs and non-Ryzens.
if has avx512 sha vaes; then
  arch=avx512-sha-vaes
elif has avx512 sha; then
  arch=avx512-sha
elif has avx512; then
  arch=avx512
elif has avx2 sha vaes; then
  if [[ ${cpu[vendor],,} == amd ]]; then
    # zen3 fallback in case of non English locale.
    arch=zen3
  else
    # Intel Alder Lake
    arch=avx2-sha-vaes
  fi
elif has avx2 sha aes; then
  # zen2 fallback in case of non English locale.
  # In theory can also be zen/zen+
  arch=zen2
elif has avx2 aes; then
  arch=avx2
elif has avx2; then
  warn 'Detected AVX2 CPU but not AES support.'
  warn 'Please check BIOS settings and enable it!'
  warn 'Running without hardware AES leads major decrease in performance!'

  arch=sse42
elif has avx aes; then
  # It is possible to have AVX but not AES.
  # Some OEM laptops have it disabled by default in the bios.
  arch=avx
elif has sse42 aes; then
  arch=aes-sse42
elif has sse42; then
  arch=sse42
else
  arch=sse2
fi

start_mining "$arch"
