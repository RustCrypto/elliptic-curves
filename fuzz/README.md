# Fuzzing harnesses for the `elliptic-curve` crate

This directory is under development; the coverage stats are from relatively brief runs.
Ultimately, the goal is to join Google's OSS-Fuzz: Continuous Fuzzing for Open Source Software, see https://google.github.io/oss-fuzz/ 


## Scalars

The `scalars.rs` harness has fairly complete coverage of deserializors and arithmetic operations.

~~~
$ cargo +nightly fuzz run scalars -j 4


#16419246: cov: 2038 ft: 3305 corp: 292 exec/s: 1763 oom/timeout/crash: 0/0/0 time: 2350s job: 134 dft_time: 0
#16650547: cov: 2038 ft: 3305 corp: 292 exec/s: 1700 oom/timeout/crash: 0/0/0 time: 2384s job: 135 dft_time: 0
~~~


## Points

The `points.rs` harness is currently being built. Some of the coverage is inherently duplicative of the scalars.

~~~
$ cargo +nightly fuzz run points -j 4


#2068356: cov: 3130 ft: 6073 corp: 359 exec/s: 93 oom/timeout/crash: 0/0/0 time: 4906s job: 195 dft_time: 0
#2086824: cov: 3130 ft: 6073 corp: 359 exec/s: 93 oom/timeout/crash: 0/0/0 time: 4955s job: 196 dft_time: 0
~~~

