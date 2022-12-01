#!/bin/bash

time (tamarin-prover -m=deepsec -D=EquivLemmas lake-edhoc-KEM.spthy -D=CredCheck > lake-edhoc-KEM.spthy.CC.dps; deepsec lake-edhoc-KEM.spthy.CC.dps) | grep Result > res-anom.csv;
# 2 secs, attack

time (tamarin-prover -m=deepsec -D=EquivLemmas lake-edhoc-KEM.spthy > lake-edhoc-KEM.spthy.dps; deepsec lake-edhoc-KEM.spthy.dps) | grep Result > res-anom.csv;
# 2 secs, ok

time (tamarin-prover -m=proverifequiv -D=diffEquiv lake-edhoc-KEM.spthy > lake-edhoc-KEM.spthy.pv; proverif lake-edhoc-KEM.spthy.pv) | grep RESULT > res-anom.csv;
# 10 minutes, ok

time (tamarin-prover -m=proverifequiv -D=diffEquiv -D=MethodZero lake-edhoc.spthy > lake-edhoc.spthy.pv; proverif lake-edhoc.spthy.pv) | grep RESULT > res-anom.csv;
# 267 minutes, ok

