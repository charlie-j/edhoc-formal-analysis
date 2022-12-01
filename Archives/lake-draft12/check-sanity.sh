#!/bin/bash

IFS='' # required to keep the tabs and spaces

TIMEOUT='30m'

files=(
    "lake-edhoc-KEM.spthy"    
    "lake-edhoc-KEM-Sig.spthy"
    
    "lake-edhoc.spthy"    
    "lake-edhoc-Sig-DDH.spthy"    

#    "lake-edhoc-Hash-Sig-DDH.spthy" # proverif cannot model hash events
#    "lake-edhoc-KEM-Hash-Sig.spthy" # proverif cannot model hash events
    )

exec_runner(){
    START=$(date +%s)
    echo $filename
    echo "tamarin-prover -m=proverif -D=SanityChecks --lemma=executable* $filename > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
    res=$(eval "timeout $TIMEOUT tamarin-prover -m=proverif -D=SanityChecks --lemma=executable* $filename > $filename.pv; timeout $TIMEOUT proverif $filename.pv")
    END=$(date +%s)
    DIFF=$(echo "$END - $START" | bc)
    res2=$(echo -n $res | grep "RESULT" | tr '\n' ' ')
    echo "$filename; $res2; $DIFF;"  >> "$outfilename"
    rm -f $filename.pv
}


outfilename="sanity-checks.csv"
echo "filename; cmd; time"  >> "$outfilename"


# for file in $files; do
# find . -name "*.spthy"  | while read line; do
for filename in "${files[@]}"; do
    exec_runner
done


