#!/bin/bash

# Number of different commands that will be executd in parallel
# Each proverif call takes one core

# Runs in 31 minutes on 60 threads at 2.6Ghz

N=$1

files=(
    # DRAFT 12
    
     	"lake-draft12/lake-edhoc.spthy --lemma=authIR_unique" # attack    
    "lake-draft12/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok
    "lake-draft12/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok	
    "lake-draft12/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok	

    "lake-draft12/lake-edhoc.spthy  --lemma=authRI_unique" # attack    
    "lake-draft12/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok
    "lake-draft12/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok
    "lake-draft12/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok


    "lake-draft12/lake-edhoc.spthy  --lemma=data_authentication_I_to_R	 -D=LeakShare -D=WeakestSignature" # attack
    	"lake-draft12/lake-edhoc.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" # ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R   -D=WeakAEAD" #ok
	

    	"lake-draft12/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" # attack
    	"lake-draft12/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " # attack
    	"lake-draft12/lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" # attack    	
    	"lake-draft12/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=XorPrecise" # ok 

    	"lake-draft12/lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # Mac attack
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" # Ok 
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj -D=WeakAEAD" # Ok 			
    	"lake-draft12/lake-edhoc.spthy	  --lemma=honestauthRI_non_inj -D=XorPrecise" # Ok 		   		
			
    "lake-draft12/lake-edhoc.spthy  --lemma=no_reflection_attacks_RI" #attack			
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	  -D=CredCheck" #ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	-D=WeakAEAD  -D=CredCheck" #ok	
    	"lake-draft12/lake-edhoc.spthy	  --lemma=no_reflection_attacks_RI	-D=XorPrecise  -D=CredCheck" #ok		
	
    "lake-draft12/lake-edhoc.spthy	  --lemma=secretI	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-draft12/lake-edhoc.spthy	  --lemma=secretI	  -D=XorPrecise" #ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=WeakAEAD" #ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=LeakSessionKey" #ok
	
	
    "lake-draft12/lake-edhoc.spthy	  --lemma=secretR	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-draft12/lake-edhoc.spthy	  --lemma=secretR	  -D=XorPrecise" #ok 
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=WeakAEAD" #ok
    	"lake-draft12/lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=LeakSessionKey" #ok

    "lake-draft12/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none" #attack
    "lake-draft12/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakestSignature" # attack
    "lake-draft12/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck" # attack
    "lake-draft12/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakAEAD" # attack
  
    	"lake-draft12/lake-edhoc-KEM.spthy	  --lemma=authIR_unique" # attack	 
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=authRI_unique	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok
	

    	"lake-draft12/lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=LeakShare -D=WeakestSignature " # ok
    	"lake-draft12/lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_I_to_R  -D=LeakSessionKey -D=WeakAEAD" #ok


    	"lake-draft12/lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " # attack
    	"lake-draft12/lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" # attack
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=LeakSessionKey" # atttack
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=XorPrecise" # ok, 17s


    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok, 504s

	
    "lake-draft12/lake-edhoc-KEM.spthy  --lemma=no_reflection_attacks_RI" #attack			, 12s
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=no_reflection_attacks_RI  -D=CredCheck   -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" #ok		, 565s
	
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=secretI	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok, 316s
    	"lake-draft12/lake-edhoc-KEM-Sig.spthy	  --lemma=secretR	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok, 755s	
    	"lake-draft12/lake-edhoc-KEM.spthy -D=NonRepudiationSoundness --lemma=none" #attack	, 103s
    	# DRAFT 14

    	"lake-draft14/lake-edhoc.spthy --lemma=authIR_unique" # ok  , 51s   
    "lake-draft14/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok, 67s
    "lake-draft14/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok	, 52s
    "lake-draft14/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok, 107s	

    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique" #      ok, 54s
    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ok, 
    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # ok
    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=XorPrecise -D=LeakSessionKey" # ok


    "lake-draft14/lake-edhoc.spthy  --lemma=data_authentication_I_to_R	 -D=LeakShare -D=WeakestSignature" #  attack, 125s
    	"lake-draft14/lake-edhoc.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" # ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R   -D=WeakAEAD" #ok
	

    	"lake-draft14/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" #  ok
    	"lake-draft14/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " #  attack, 892s
    	"lake-draft14/lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" #      	ok
    	"lake-draft14/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=XorPrecise" # ok 

    	"lake-draft14/lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" # Ok 
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj -D=WeakAEAD" # Ok 			
    	"lake-draft14/lake-edhoc.spthy	  --lemma=honestauthRI_non_inj -D=XorPrecise" # Ok 		   		
			
    "lake-draft14/lake-edhoc.spthy  --lemma=no_reflection_attacks_RI" # attack, 55s 			
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	  -D=CredCheck" #ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	-D=WeakAEAD  -D=CredCheck" #ok	
    	"lake-draft14/lake-edhoc.spthy	  --lemma=no_reflection_attacks_RI	-D=XorPrecise  -D=CredCheck" #ok		
	
    "lake-draft14/lake-edhoc.spthy	  --lemma=secretI	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-draft14/lake-edhoc.spthy	  --lemma=secretI	  -D=XorPrecise" #ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=WeakAEAD" #ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=secretI	  -D=LeakSessionKey" #ok
	
	
    "lake-draft14/lake-edhoc.spthy	  --lemma=secretR	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" #ok
    "lake-draft14/lake-edhoc.spthy	  --lemma=secretR	  -D=XorPrecise" #ok 
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=WeakAEAD" #ok
    	"lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=secretR	  -D=LeakSessionKey" #ok

    "lake-draft14/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none" # ok
    "lake-draft14/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakestSignature" # , attack, 36s 
    "lake-draft14/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck" #  ok
    "lake-draft14/lake-edhoc.spthy -D=NonRepudiationSoundness --lemma=none -D=NeutralCheck -D=WeakAEAD" #  ok

    	"lake-draft14/lake-edhoc-KEM.spthy	  --lemma=authIR_unique" # ok	 
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=authRI_unique	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok
	

    	"lake-draft14/lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=LeakShare -D=WeakestSignature " # ok
    	"lake-draft14/lake-edhoc-KEM.spthy	  --lemma=data_authentication_I_to_R	  -D=XorPrecise" # ok
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_I_to_R  -D=LeakSessionKey -D=WeakAEAD" #ok


    	"lake-draft14/lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=LeakShare -D=WeakestSignature " # attack
    	"lake-draft14/lake-edhoc-KEM.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" # ok
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=LeakSessionKey" # ok
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=data_authentication_R_to_I   -D=XorPrecise" # ok


    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok

	
    	"lake-draft14/lake-edhoc-KEM.spthy  --lemma=no_reflection_attacks_RI" #attack			 
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=no_reflection_attacks_RI  -D=CredCheck   -D=LeakShare -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" #ok		
	
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=secretI	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok
    	"lake-draft14/lake-edhoc-KEM-Sig.spthy	  --lemma=secretR	  -D=LeakShare  -D=LeakSessionKey -D=XorPrecise -D=WeakAEAD" # ok	
    "lake-draft14/lake-edhoc-KEM.spthy -D=NonRepudiationSoundness --lemma=none" #ok	
	
    )



exec_runner(){
    IFS='' # required to keep the tabs and spaces
    TIMEOUT='30m'
    file=$@
    outfilename="res-proverif.csv"
    START=$(date +%s)
    filename=$(echo "$file" | sed "s/[^[:alnum:]-]//g")
    echo $filename
    echo "tamarin-prover -m=proverif $file > $filename.pv; timeout $TIMEOUT proverif $filename.pv"
    res=$(eval "tamarin-prover +RTS -N1 -RTS -m=proverif $file > $filename.pv; timeout $TIMEOUT proverif $filename.pv")
    END=$(date +%s)
    DIFF=$(echo "$END - $START" | bc)
    res2=$(echo -n $res | grep "RESULT" | tr '\n' ' ')
    echo "$file; $res2; $DIFF;"  >> "$outfilename"
    rm -f $filename.pv
}

outfilename="res-proverif.csv"
echo "filename; res; time"  >> "$outfilename"

# for file in $files; do
# find . -name "*.spthy"  | while read line; do
export -f exec_runner
for file in  "${files[@]}"; do
    sem -j $N exec_runner $file
    # exec_runner $file
done
sem --wait
