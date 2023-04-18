#!/usr/bin/env sh

AFL_DISABLE_TRIM=1 \
AFL_CUSTOM_MUTATOR_ONLY=1 \
AFL_CUSTOM_MUTATOR_LIBRARY=$HOME/Refine_Protobuf_Mutator/build/lib/libcustom_protobuf_mutator.so \
AFL_SKIP_CPUFREQ=1 \
afl-fuzz -t 45000 -i /root/Refine_Protobuf_Mutator/proto_seed/bin -o ./out ./openfhe_test  @@