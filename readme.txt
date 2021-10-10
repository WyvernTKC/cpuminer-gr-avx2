Tuning:
Tuning starts automaticaly with the start of the miner. If previous tuning file `tune_config`
exists (or `--tune-config=FILE` flag is used), it is used instead. This behavior
can be overridden by `--no-tune` or `--force-tune`.
On non-AVX2 CPUs default tuning process takes ~69 minutes to finish.
On AVX2 CPUs default tuning process takes ~155 minutes to finish.


To add or use options from the miner, use included config.json file.
All options should be presented in JSON format like:
"long-flag-name": "Some_value"

Some examples:
"tune-full": true
"tune-config": "tune_config"
"url": "stratum+tcp://YOUR_POOL_ADDRESS:PORT"
"user": "YOUR_WALLET"


Help from the miner:
  -a, --algo=ALGO       specify the algorithm to use
                          gr            Ghost Rider - Raptoreum (RTM)
  -N, --param-n         N parameter for scrypt based algos
  -R, --param-r         R parameter for scrypt based algos
  -K, --param-key       Key (pers) parameter for algos that use it
  -o, --url=URL         URL of mining server
      --url-backup=URL  URL of backup mining server (experimental)
  -O, --userpass=U:P    username:password pair for mining server
  -u, --user=USERNAME   username for mining server
  -p, --pass=PASSWORD   password for mining server
      --cert=FILE       certificate for mining server using SSL
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy
  -t, --threads=N       number of miner threads (default: number of processors)
  -r, --retries=N       number of times to retry if a network call fails
                          (default: retry indefinitely)
      --retry-pause=N   time to pause between retries, in seconds (default: 5)
      --time-limit=N    maximum time [s] to mine before exiting the program.
  -T, --timeout=N       timeout for long poll and stratum (default: 240 seconds)
  -s, --scantime=N      upper bound on time spent scanning current work when
                          long polling is unavailable, in seconds (default: 5)
      --randomize       Randomize scan range start to reduce duplicates
  -f, --diff-factor     Divide req. difficulty by this factor (std is 1.0)
  -m, --diff-multiplier Multiply difficulty by this factor (std is 1.0)
      --hash-meter      Display thread hash rates
      --coinbase-addr=ADDR  payout address for solo mining
      --coinbase-sig=TEXT  data to insert in the coinbase when possible
      --no-longpoll     disable long polling support
      --no-getwork      disable getwork support
      --no-gbt          disable getblocktemplate support
      --no-stratum      disable X-Stratum support
      --no-extranonce   disable Stratum extranonce support
      --no-redirect     ignore requests to change the URL of the mining server
  -q, --quiet           enable less output
      --no-color        disable colored output
  -D, --debug           enable debug output
  -P, --protocol-dump   verbose dump of protocol-level activities
  -S, --syslog          use system log for output messages
  -B, --background      run the miner in the background
      --benchmark       run in offline benchmark mode
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1
      --cpu-priority    set process priority (default: 0 idle, 2 normal to 5 highest)
  -b, --api-bind=address[:port]   IP address for the miner API, default port is 4048)
      --api-remote      Allow remote control
      --max-temp=N      Only mine if cpu temp is less than specified value (linux)
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value
      --max-diff=N      Only mine if net difficulty is less than specified value
  -c, --config=FILE     load a JSON-format configuration file
      --data-file       path and name of data file
      --verify          enable additional time consuming start up tests
  -V, --version         display version information and exit
      --log=FILE        path to the file that will include a copy of miner output. File is not cleared after restart.
  -d, --donation=VAL    donation value in %. Default is 1.75
  -y  --no-msr          disable application of MSR mod on the system
      --force-tune      Force tuning of the miner before mining even if tune config file exists.
      --no-tune         disable tuning of the miner before mining. Tuning takes ~69 (non-AVX2) or ~154 (AVX2+) minutes. 
      --tune-full       enable full tuning. Include All 4way Cryptonight variants. Tuning takes ~222 minutes. Only available on AVX2+
      --tune-config=FILE  Point to the already created tune config. Default file created by the miner is tune_config
  -h, --help            display this help text and exit


Information about different binaries and required Processor instructions.
Correct binaries should be selected automaticaly from the provided .sh/.bat script

# Compiled as AMD Zen1 AVX2 SHA
# AMD Zen & Zen+ - 1000 & 2000 series (3000 Mobile)
cpuminer-zen"

# Compiled as AMD Zen2 AVX2 SHA
# AMD Zen2 - 3000 (Desktop) & 4000 series
cpuminer-zen2

# Compiled as AMD Zen3 AVX2 SHA VAES
# AMD Zen3 - 5000 series
cpuminer-zen3

# Compiled as Icelake AVX512 SHA VAES
# Ice Lake (10th gen, 10000 series Mobile)
# Rocket Lake (11th gen, 11000 series)
cpuminer-avx512-sha-vaes

# Compiled as Rocket Lake AVX512 SHA AES
?
cpuminer-avx512-sha

# Compiled as Skylake-X AVX512 AES
# Skylake-X/SP/W - HEDT 7000 & 9000 series, Xeon-W, Xeon Bronze/Silver/Gold/Platinum
# Tiger Lake (11th gen, 11000 series Mobile)
cpuminer-avx512

# Compiled as Haswell AVX2 AES
# Haswell (4th gen, 4000 series / 5000 HEDT) - All except i3-4000m, Pentium and Celeron
# Broadwell (5th gen, 5000 series / 6000 HEDT) - All except Pentium and Celeron
# Skylake (6th gen, 6000 series)
# Kaby Lake (7th gen, 7000 series)
# Coffee Lake (8 & 9th gen, 8000/9000 series)
# Cascade Lake / Cannon Lake (10th gen, 10000 series)
cpuminer-avx2

# Compiled as Sandybridge AVX AES
# Sandybridge (2nd gen, 2000 series / 3000 HEDT) - All i5, i7. Some i3. Xeon v1
# Ivy Bridge (3rd gen, 3000 series / 4000 HEDT) - All i5, i7, Xeon v2
cpuminer-avx

# Compiled as Westmere SSE4.2 AES
# Westmere-EP (1st gen) - Xeon 5600 series
# Clarkdale & Arrandale - All except Celeron, Pentium, i3 and i5-4XXM
cpuminer-aes-sse42

# Compiled as Nehalem SSE4.2
cpuminer-sse42"

# Compiled as Core2 SSSE3
cpuminer-ssse3"

# Compiled as Generic SSE2
cpuminer-sse2
