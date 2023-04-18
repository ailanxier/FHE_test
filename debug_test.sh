#!/bin/bash
for file in /root/Refine_Protobuf_Mutator/proto_seed/bin/*.txt; do
    echo "Processing file: $file"
  ./openfhe_ckks_debug "$file"
done
