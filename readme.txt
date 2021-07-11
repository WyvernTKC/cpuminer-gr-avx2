./cpiminer-INSTRUCTIONS -a gr -o stratum+tcp://r-pool.net:3008 -u RQKcAZBtsSacMUiGNnbk3h3KJAN94tstvt -p x

-h                         -> Display full help and all available options.
Useful options:
-a gr                      -> Use GR algorithm.
-o stratum+tcp://URL:PORT  -> Your stratum URL. stratum+tcp://rtm.suprnova.cc:6273
-u WALLET_ADDR.WORKER_NAME -> Your wallet address. You can add "." and some text to differentiate between different workers.
-p PASSWORD                -> Password to your user/worker on the pool. Most of the time "x" or not used is enough.
-t VAL                     -> Use VAL number of threads. If not set, miner defaults to all threads.
-d VAL                     -> Change dev fee percentage. Defaults to 1%.
-y                         -> Disable MSR mod. Defaults to enabled and can improve performance. Only supported on builds with AES instructions. Requires root privileges
--benchmark                -> 300s benchmark that measures average performance of the GR algorithm. Uses blocktimes from 16 days to determine rotation time ratio.
--force-tune               -> Forces tuning of the miner regardless of `tune_config` file.
--no-tune                  -> Disable tuning of the miner.
--tune-config=FILE         -> Use already generated tuning configure file or point to where config file should be saved.

AVX2+:
--tune-simple              -> Decrease complexity of the tuning process. It should take 54 minutes.
--tune-full                -> Increase complexity of the tuning process. It should take 115 minutes.

Tuning:
Tuning starts automaticaly with the start of the miner. If previous tuning file `tune_config`
exists (or `--tune-config=FILE` flag is used), it is used instead. This behavior
can be overridden by `--no-tune` or `--force-tune`.
On non-AVX2 CPUs default tuning process takes 35 minutes to finish.
On AVX2 CPUs default tuning process takes 80 minutes to finish.

--tune-config:
There is a folder tune_presets where community members contributed their tuning configs
so users can start with something reasonable instead of tining it yourself.
Tuning yourself is recommended for the most accurate and best performance!

Information about different binaries and required Processor instructions.

# Compiled as AMD Zen1 AVX2 SHA
# AMD Zen & Zen+ - 1000 & 2000 series
cpuminer-zen"

# Compiled as AMD Zen2 AVX2 SHA
# AMD Zen2 - 3000 & 4000 series
cpuminer-zen2

# Compiled as AMD Zen3 AVX2 SHA VAES
# AMD Zen3 - 5000 series
cpuminer-zen3

# Compiled as Icelake AVX512 SHA VAES
# Ice Lake (10th gen, 10000 series Mobile)
cpuminer-avx512-sha-vaes

# Compiled as Rocket Lake AVX512 SHA AES
# Rocket Lake (11th gen, 11000 series)
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



