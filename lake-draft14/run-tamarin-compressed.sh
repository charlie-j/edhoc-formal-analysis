#!/bin/bash

#Number of different commands that will be executd in parallel
# TO set for each different server
# the command for tamarin takes 4 core (but it is also parametrable)
# So, 4xN should be smaller than the number of cores
# The script execute 13 commands in total, so a 4*13 cores ensure that everything will run under 24 hour. All commands should terminate before that, as the longest takes 18 hours.
N=13

# Timeout for each command
TIMEOUT='24h'

# list of files and lemmas in cmds, each of them being verified with each method in methods and with each flag in flags.
methods=(
	"tamarin-prover"
)

cmds=(
    "lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" #    

    "lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" #  
    "lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" #      	


    
    "lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # 
    "lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" #  
    
    "lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	  -D=CredCheck" #

    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # 
    "lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # 

    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ,
    "lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # 


    "lake-edhoc.spthy	  --lemma=secretI	  -D=LeakSessionKey" #
    
    
    "lake-edhoc.spthy	  --lemma=secretR	 -D=LeakSessionKey" #

    "lake-edhoc-KEM-Hash.spthy -D=FreshDomain -D=CPcol -D=LEcol --lemma=secretI -D=weakKEM -D=SingleHash"
 
    
)
     


IFS='' # required to keep the tabs and spaces

exec_runner(){
    START=$(date +%s)
    filename=$(echo "$cmd $method" | sed "s/[^[:alnum:]-]//g")
    #echo $filename
    echo "START : timeout $TIMEOUT $method $cmd --prove +RTS -N4 -RTS"
    res=$(eval "timeout $TIMEOUT $method $cmd --prove +RTS -N4 -RTS")
    END=$(date +%s)
    DIFF=$(echo "$END - $START")
    res2=$(echo -n $res | grep "verified\|falsified"  | tr '\n' ' ') 
    echo "$filename; $method; $res2; $DIFF;"  >> "$outfilename"
    echo "$method $flag $cmd : END"
}

outfilename="res-tam-compressed.csv"

# Print headers
echo "filename; method; result; time" >> "$outfilename"

for method in "${methods[@]}"; do
        for cmd in "${cmds[@]}"; do
        	((i=i%N)); ((i++==0)) && wait	
		exec_runner &
        done
done
echo "WARNING: some verification may still be running in the background"
