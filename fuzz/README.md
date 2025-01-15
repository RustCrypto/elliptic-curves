# Fuzzing harnesses for the `elliptic-curve` crate

This directory is under development; the coverage stats are from relatively brief runs.
Ultimately, the goal is to join Google's OSS-Fuzz: Continuous Fuzzing for Open Source Software, see https://google.github.io/oss-fuzz/ 


## Scalars

The `scalars.rs` harness has fairly complete coverage of deserializors and arithmetic operations.

~~~
$ cargo +nightly fuzz run scalars -j 4


#722833: cov: 2025 ft: 3282 corp: 309 exec/s: 1941 oom/timeout/crash: 0/0/0 time: 106s job: 26 dft_time: 0
#775578: cov: 2025 ft: 3282 corp: 309 exec/s: 1883 oom/timeout/crash: 0/0/0 time: 113s job: 27 dft_time: 0
~~~


## Points

The `points.rs` harness is currently being built. Some of the coverage is inherently duplicative of the scalars.

~~~
$ cargo +nightly fuzz run points -j 4


#2068356: cov: 3130 ft: 6073 corp: 359 exec/s: 93 oom/timeout/crash: 0/0/0 time: 4906s job: 195 dft_time: 0
#2086824: cov: 3130 ft: 6073 corp: 359 exec/s: 93 oom/timeout/crash: 0/0/0 time: 4955s job: 196 dft_time: 0
~~~

