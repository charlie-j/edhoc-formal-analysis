#!/bin/bash

#Number of different commands that will be executd in parallel
# TO set for each different server
# If we use proverif, it uses only one core
# the command for tamarin takes 8 core (but it is also parametrable)

N=$1

files=(
	"lake-edhoc-KEM.spthy	  --lemma=authIR_unique" # ok	 
	"lake-edhoc-KEM-Sig.spthy	  --lemma=authRI_unique	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok
	

	"lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=LeakShare -D=WeakestSignature " # ok
	"lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
	"lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_I_to_R  -D=LeakSessionKey -D=WeakAEAD" #ok


	"lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " # attack
	"lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" # ok
	"lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=LeakSessionKey" # ok
	"lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=XorPrecise" # ok


	"lake-edhoc-KEM-Sig.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok

	
	"lake-edhoc-KEM.spthy  --lemma=no_reflection_attacks_RI" #attack			
	"lake-edhoc-KEM-Sig.spthy	  --lemma=no_reflection_attacks_RI  -D=CredCheck   -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" #ok		
	
	"lake-edhoc-KEM-Sig.spthy	  --lemma=secretI	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok
	"lake-edhoc-KEM-Sig.spthy	  --lemma=secretR	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok	
    "lake-edhoc-KEM.spthy -D=NonRepudiationSoundness --lemma=none" #ok	
    )

exec_runner(){
    file=$@
    IFS='' # required to keep the tabs and spaces
    outfilename="res-pro-compressed-KEM.csv"
    TIMEOUT='30m'
    START=$(date +%s)
    filename=$(echo "$file" | sed "s/[^[:alnum:]-]//g")
    echo $filename
    echo "tamarin-prover -m=proverif $file  > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
    res=$(eval "timeout $TIMEOUT tamarin-prover  -m=proverif  $file > $filename.pv; timeout $TIMEOUT proverif $filename.pv")
    END=$(date +%s)
    DIFF=$(echo "$END - $START" | bc)
    res2=$(echo -n $res | grep "RESULT" | tr '\n' ' ')
    echo "$file; $res2; $DIFF;"  >> "$outfilename"
    rm -f $filename.pv
}


outfilename="res-pro-compressed-KEM.csv"
echo "filename; res; time"  >> "$outfilename"


# for file in $files; do
# find . -name "*.spthy"  | while read line; do
export -f exec_runner
for file in  "${files[@]}"; do
        sem -j $N exec_runner $file

done
sem --wait
