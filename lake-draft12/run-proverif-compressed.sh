#!/bin/bash

# Number of different commands that will be executd in parallel
# Each proverif call takes one core

N=$1

files=(
	"lake-edhoc.spthy --lemma=authIR_unique" # attack    
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok	
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok	

    "lake-edhoc.spthy  --lemma=authRI_unique" # attack    
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok


    "lake-edhoc.spthy  --lemma=data_authentication_I_to_R	 -D=LeakShare -D=WeakestSignature" # attack
	"lake-edhoc.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" # ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R   -D=WeakAEAD" #ok
	

	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" # attack
	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " # attack
	"lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" # attack    	
	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=XorPrecise" # ok 

	"lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # Mac attack
	"lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" # Ok 
	"lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj -D=WeakAEAD" # Ok 			
	"lake-edhoc.spthy	  --lemma=honestauthRI_non_inj -D=XorPrecise" # Ok 		   		
			
    "lake-edhoc.spthy  --lemma=no_reflection_attacks_RI" #attack			
	"lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	  -D=CredCheck" #ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	-D=WeakAEAD  -D=CredCheck" #ok	
	"lake-edhoc.spthy	  --lemma=no_reflection_attacks_RI	-D=XorPrecise  -D=CredCheck" #ok		
	
    "lake-edhoc.spthy	  --lemma=secretI	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-edhoc.spthy	  --lemma=secretI	  -D=XorPrecise" #ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=WeakAEAD" #ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=LeakSessionKey" #ok
	
	
    "lake-edhoc.spthy	  --lemma=secretR	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-edhoc.spthy	  --lemma=secretR	  -D=XorPrecise" #ok 
	"lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=WeakAEAD" #ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=LeakSessionKey" #ok

    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none" #attack
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakestSignature" # attack
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck" # attack
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakAEAD" # attack
  

    )



exec_runner(){
    IFS='' # required to keep the tabs and spaces
    TIMEOUT='30m'
    file=$@
    outfilename="res-pro-compressed.csv"
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


outfilename="res-pro-compressed.csv"
echo "filename; res; time"  >> "$outfilename"


# for file in $files; do
# find . -name "*.spthy"  | while read line; do
export -f exec_runner
for file in  "${files[@]}"; do
        sem -j $N exec_runner $file
done
sem --wait
