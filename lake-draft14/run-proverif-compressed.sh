#!/bin/bash

#Number of different commands that will be executd in parallel
# TO set for each different server
# If we use proverif, it uses only one core
# the command for tamarin takes 8 core (but it is also parametrable)

N=$1

files=(
	"lake-edhoc.spthy --lemma=authIR_unique" # ok  , 51s   
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok, 67s
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok	, 52s
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok, 107s	

    "lake-edhoc.spthy  --lemma=authRI_unique" #      ok, 54s
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok, 
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok


    "lake-edhoc.spthy  --lemma=data_authentication_I_to_R	 -D=LeakShare -D=WeakestSignature" #  attack, 125s
	"lake-edhoc.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" # ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R   -D=WeakAEAD" #ok
	

	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" #  ok
	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " #  attack, 892s
	"lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" #      	ok
	"lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=XorPrecise" # ok 

	"lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # ok
	"lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" # Ok 
	"lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj -D=WeakAEAD" # Ok 			
	"lake-edhoc.spthy	  --lemma=honestauthRI_non_inj -D=XorPrecise" # Ok 		   		
			
    "lake-edhoc.spthy  --lemma=no_reflection_attacks_RI" # attack, 55s 			
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

    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none" # ok
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakestSignature" # , attack, 36s 
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck" #  ok
    "lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakAEAD" #  ok
  

    )

exec_runner(){
    IFS='' # required to keep the tabs and spaces
    outfilename="res-pro-compressed.csv"
    file=$@
    TIMEOUT='30m'
    START=$(date +%s)
    filename=$(echo "$file" | sed "s/[^[:alnum:]-]//g")
    echo $filename
    echo "tamarin-prover -m=proverif $lemma  > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
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
