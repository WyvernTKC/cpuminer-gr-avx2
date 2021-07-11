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
    -d VAL                     -> Change dev fee percentage. Defaults to 1.75%.
    -y                         -> Disable MSR mod. Defaults to enabled and can improve performance. Only supported on builds with AES instructions. Requires root privileges
    --benchmark                -> 450s benchmark that measures average performance of the GR algorithm. Uses blocktimes from 16 days to determine rotation time ratio.
    --no-tune                  -> Disable tuning of the miner.
    --force-tune               -> Force tuning of the miner regardless if tune_config file is present.
    --tune-config=FILE         -> Use already generated tuning configure file or point to where config file should be saved.

    AVX2+:
    --tune-simple              -> Decrease complexity of the tuning process. It should take 54 minutes.
    --tune-full                -> Increase complexity of the tuning process. It should take 115 minutes.


Tuning
------
Tuning starts automaticaly with the start of the miner. If previous tuning file `tune_config`
exists (or `--tune-config=FILE` flag is used), it is used instead. This behavior
can be overridden by `--no-tune` or `--force-tune`.
On non-AVX2 CPUs default tuning process takes 35 minutes to finish.
On AVX2 CPUs default tuning process takes 80 minutes to finish.


--tune-config:
There is a folder tune_presets where community members contributed their tuning configs
so users can start with something reasonable instead of tining it yourself.
Tuning yourself is recommended for the most accurate and best performance!


A small explanation of what tuning does. The traditional way of hashing would be,
take some input, hash it to generate output hash. That is what would be called
normal hashing (aka 1way) as we are doing 1 hash at a time. What we can do is
to hash 2 or 4 hashes at the same time! Due to different variants used in each
block etc, the memory requirement changes and we would like to have as much of
it in the cache as possible as RAM is SLOW! So 1way would require 128KiB, 256KiB,
256KiB, 512KiB, 1MiB or 2MiB to be stored somewhere if we wanna solve it. 2way
would need 2x of that amount and 4way 4x. In some cases, like in 256KiB variants,
that would increase the requirements to something like 1MiB or up to 2MiB for the
512KiB variants. In most cases, this amount of data can fit in the cache which
can bring additional performance. Putting too much can decrease it imagine 8MiB
for 4way Fast (2MiB variant) (in some cases it is still fastest if your CPU
lacks cache, like i3 or some mobile CPUs). OK, so there are 6 variants, that
make 20 possible "rotations". And we check all those 20 rotations to see if we
use 1way, 2way, or 4way on each of them brings improvement or not. We cannot
check it individually as to when they are hashing using all of them, it might 
not be accurate anymore so we have 8 scenarios per rotation for AVX
(only 1way or 2way, 2^3, 2 ways of solving for 3 variants) and 27 for AVX2
(1way, 2way, 4way, 3^3, 3 ways of solving for 3 variants) -> this is --tune-full
that checks everything. --tune-simple only checks 4way on Turtle and Turtlelite
variants and default also check Dark and Darklite ones as those are the most
likely to be used or benefit CPUs from all our testing. That way we can use the
most amount of cache and use it as efficiently as possible. The question you
might ask, how is doing 2way faster than doing just 1way 2 times? That is coz
we can use some more parallelization and other tricks to notify the CPU of
what is coming so it can prepare data faster.


Ghost Rider (GR)
---------------

Ghost Rider (GR) algorithm that is used to mine RTM consists of 15 "core" 
algorithms (same as in X16 without SHA) and 6 different variants of Cryptonight
which only 3 are used for hashing. Each block (in part of the previous block in
reality) dictates what should be the order those algorithms are calculated in
and which of the Cryptonight variants should be used. It goes like this:
5 core algorithms, 1 Cryptonight, 5 core, 1 Cryptonight, 5 core, 1 Cryptonight.
As you can see all core algorithms are always used but only 3 out of 6 variants
of Cryptonight. Those Cryptonight parts are the slowest/"hardest" part of the
whole hashing process. Core algorithms perform very well on pretty much every
CPU but Cryptonight requires a specific amount of memory, if that memory can be
fully or mostly stored in a cache, that will increase the performance
significantly (the main reason why AMD Ryzens are so much faster than Intels as
they have so much more L3 Cache). The variants of CN use 128KiB, 256KiB,
256KiB, 512KiB, 1MiB, or 2MiB or memory. In addition, the larger the memory
needed, the more iterations through it (making it even slower :P). The
performance of those algorithms can vary A LOT. You might be getting like
1500H/s if the blocks want the 3 slowest variants (The ones using most memory)
and 10000+H/s if the blocks use the fastest ones (Using my 2x2698v3 as an example).
This means 2 things. First, the hash rate like you notice is very volatile and
changes almost always with each block. The miner should show you Cryptonight
variants used in the current block, Turtlelite, Turtle, Darklite, Dark, Lite, Fast - 
those are variants in the same order as I mentioned memory, irony is that the 
Fast variant is the slowest one and Turtlelite is the fastest :). Second, some
blocks (in most parts the ones using easier variants) are found faster and not
in a very consistent manner. All should average to around 120s per block tho
in the long term.


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


This fork introduces 1.75% donation on added Ghost Rider (GR) algorithm only.

If you wanna support us, any donations are welcome:


Ausminers:

RTM: RXq9v8WbMLZaGH79GmK2oEdc33CTYkvyoZ

Delgon:

RTM: RQKcAZBtsSacMUiGNnbk3h3KJAN94tstvt
ETH: 0x6C1273b5f4D583bA00aeB2cE68f54825411D6E8c


Happy mining!
