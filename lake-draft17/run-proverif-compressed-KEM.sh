#!/bin/bash

#Number of different commands that will be executd in parallel
# TO set for each different server
# If we use proverif, it uses only one core
# the command for tamarin takes 8 core (but it is also parametrable)

N=30

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

IFS='' # required to keep the tabs and spaces

TIMEOUT='30m'AD; RESULT event(AcceptR(cid_2,m,pkI_2,pkR_2,k4,ko,y,gx))@i && event(Honest(pkI_2))@k ==> (i > t && event(AcceptI(cid2,m,pkI_2,pkR_2,k3,k4,ko,x,gy))@t && cid_2 ≠ cid2) || event(Compromise(pkI_2))@t || (eve

exec_runner(){
    START=$(date +%s)
    filename=$(echo "$file" | sed "s/[^[:alnum:]-]//g")
    echo $filename
    echo "tamarin-prover -m=proverilake-edhoc-KEM.spthy -D=NonRepudiationSoundness ;-lemma=nonef $lemma  > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
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
for file in  "${files[@]}"; do
        ((i=i%N)); ((i++==0)) && wait	
	exec_runner &

done
echo "WARNING: some verification may still be running in the background"
