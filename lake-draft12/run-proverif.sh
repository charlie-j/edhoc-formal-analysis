#!/bin/bash

# Number of different commands that will be executd in parallel
# Each Proverif calls takes one core

N=30

files=(
    "lake-edhoc.spthy"
    "lake-edhoc-KEM.spthy"
    )

lemmas=(
    " --lemma=secretI"
    " --lemma=secretR"
    " --lemma=authRI_unique"
    " --lemma=authIR_unique"    
    " --lemma=honestauthRI_non_inj"
    " --lemma=no_reflection_attacks_RI"
    " --lemma=data_authentication_R_to_I"
    " --lemma=data_authentication_I_to_R"
    )
threats=(
    ""
    " -D=NeutralCheck"
    " -D=NeutralCheck -D=WeakestSignature"
    " -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey"
    " -D=LeakShare -D=WeakestSignature -D=LeakSessionKey"
    " -D=CredCheck"
    " -D=XorPrecise"
    " -D=WeakAEAD"
    " -D=LeakShare -D=WeakestSignature -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD"    
)

IFS='' # required to keep the tabs and spaces

TIMEOUT='30m'

exec_runner(){
    START=$(date +%s)
    filename=$(echo "$file$lemma$threat" | sed "s/[^[:alnum:]-]//g")
    echo $filename
    echo "tamarin-prover $threat -m=proverif $lemma $file > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
    res=$(eval "timeout $TIMEOUT tamarin-prover $threat -m=proverif $lemma $file > $filename.pv; timeout $TIMEOUT proverif $filename.pv")
    END=$(date +%s)
    DIFF=$(echo "$END - $START" | bc)
    res2=$(echo -n $res | grep "RESULT" | tr '\n' ' ')
    echo "$file; $lemma; $threat; $res2; $DIFF;"  >> "$outfilename"
    rm -f $filename.pv
}


outfilename="res-pro.csv"
echo "filename; lemma; threat; res; time"  >> "$outfilename"


# for file in $files; do
# find . -name "*.spthy"  | while read line; do
for file in  "${files[@]}"; do
for lemma in "${lemmas[@]}"; do
    for threat in "${threats[@]}"; do
        ((i=i%N)); ((i++==0)) && wait	
	exec_runner &
    done
done
done
echo "WARNING: some verification may still be running in the background"
