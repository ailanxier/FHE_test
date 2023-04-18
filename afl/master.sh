#!/usr/bin/env sh

AFL_DISABLE_TRIM=1 \
AFL_CUSTOM_MUTATOR_ONLY=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=lib/libopenfhe_bgv_protobuf_mutator.so \
AFL_SKIP_CPUFREQ=1 \
AFL_FAST_CAL=1 \
afl-fuzz -t 60000 -i bin -o /root/FHE_test/afl/out ./openfhe_bgv_test  @@