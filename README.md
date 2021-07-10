cpuminer-gr is a fork of cpuminer-opt by Jay D Dee which is a fork of cpuminer-multi with optimizations
imported from other miners developped by lucas Jones, djm34, Wolf0, pooler,
Jeff garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional
optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a
claim to any of it post your case in the cpuminer-gr by email.

Miner programs are often flagged as malware by antivirus programs. This is
a false positive, they are flagged simply because they are cryptocurrency 
miners. The source code is open for anyone to inspect. If you don't trust 
the software, don't use it.

There is NO official bitcointalk thread about this miner. It is due to
unjust ban after posting about first release about this miner.

See file RELEASE_NOTES for change log and INSTALL_LINUX or INSTALL_WINDOWS
for compile instructions.

Requirements
------------

1. A x86-64 architecture CPU with a minimum of SSE2 support. This includes
Intel Core2 and newer and AMD equivalents. Further optimizations are available
on some algoritms for CPUs with AES, AVX, AVX2, SHA, AVX512 and VAES.

ARM and Aarch64 CPUs are not supported, yet.

2. 64 bit Linux or Windows OS. Ubuntu and Fedora based distributions,
including Mint and Centos, are known to work and have all dependencies
in their repositories. Others may work but may require more effort. Older
versions such as Centos 6 don't work due to missing features. 
64 bit Windows OS is supported with mingw-w64 and msys or pre-built binaries.

MacOS, OSx and Android are not supported.

3. Stratum pool supporting stratum+tcp:// or stratum+ssl:// protocols or
RPC getwork using http:// or https://.
GBT is YMMV.

Supported Algorithms
--------------------


                          gr            Ghost Rider (RTM)
                           

Quick Setup
-----------

    ./cpiminer-INSTRUCTIONS -a gr -o stratum+tcp://r-pool.net:3008 -u RQKcAZBtsSacMUiGNnbk3h3KJAN94tstvt -p x

    -h                         -> Display full help and all available options.
    Useful options:
    -a gr                      -> Use GR algorithm.
    -o stratum+tcp://URL:PORT  -> Your stratum URL. stratum+tcp://r-pool.net:3008
    -u WALLET_ADDR.WORKER_NAME -> Your wallet address. You can add "." and some text to differentiate between different workers.
    -p PASSWORD                -> Password to your user/worker on the pool. Most of the time "x" or not used is enough.
    -t VAL                     -> Use VAL number of threads. If not set, miner defaults to all threads.
    -d VAL                     -> Change dev fee percentage. Defaults to 1%.
    -y                         -> Disable MSR mod. Defaults to enabled and can improve performance. Only supported on builds with AES instructions. Requires root privileges
    --benchmark                -> 300s benchmark that measures average performance of the GR algorithm. Uses blocktimes from 16 days to determine rotation time ratio.
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

Bugs
----

Users are encouraged to post their bug reports using git issues or on official
RTM Discord or opening an issue in git:

https://discord.gg/2T8xG7e

https://github.com/WyvernTKC/cpuminer-gr-avx2/issues

All problem reports must be accompanied by a proper problem definition.
This should include how the problem occurred, the command line and
output from the miner showing the startup messages and any errors.
A history is also useful, ie did it work before.

Donations
---------

Any kind but donations are accepted.
Jay D Dee's BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT


This fork introduces 1% donation on added Ghost Rider (GR) algorithm only.

If you wanna support us, any donations are welcome:
Ausminer
RTM: RXq9v8WbMLZaGH79GmK2oEdc33CTYkvyoZ

Delgon
RTM: RQKcAZBtsSacMUiGNnbk3h3KJAN94tstvt
ETH: 0x6C1273b5f4D583bA00aeB2cE68f54825411D6E8c


Happy mining!
