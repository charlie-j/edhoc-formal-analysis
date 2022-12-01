#!/bin/bash

#Number of different commands that will be executd in parallel
# TO set for each different server
# the command for tamarin takes 4 core (but it is also parametrable)
# So, 4xN should be smaller than the number of cores
# The script execute 13 commands in total, so a 4*13 cores ensure that everything will run under 24 hour. All commands should terminate before that, as the longest takes 18 hours.
N=$1

# Timeout for each command

# list of files and lemmas in cmds, each of them being verified with each method in methods and with each flag in flags.

cmds=(
    "lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=data_authentication_I_to_R	 -D=LeakSessionKey" #    

    "lake-draft14/lake-edhoc.spthy	  --lemma=data_authentication_R_to_I	  -D=WeakAEAD" #  
    "lake-draft14/lake-edhoc.spthy  --lemma=data_authentication_R_to_I	 -D=LeakSessionKey -D=WeakestSignature" #      	


    
    "lake-draft14/lake-edhoc.spthy	  --lemma=honestauthRI_non_inj	  -D=LeakShare -D=WeakestSignature -D=LeakSessionKey" # 
    "lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=honestauthRI_non_inj  -D=LeakSessionKey" #  
    
    "lake-draft14/lake-edhoc-Sig-DDH.spthy	  --lemma=no_reflection_attacks_RI	  -D=CredCheck" #

    "lake-draft14/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # 
    "lake-draft14/lake-edhoc.spthy --lemma=authIR_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # 

    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey" # ,
    "lake-draft14/lake-edhoc.spthy  --lemma=authRI_unique -D=NeutralCheck -D=WeakAEAD -D=LeakSessionKey" # 


    "lake-draft14/lake-edhoc.spthy	  --lemma=secretI	  -D=LeakSessionKey" #
    
    
    "lake-draft14/lake-edhoc.spthy	  --lemma=secretR	 -D=LeakSessionKey" #

    
)
     



exec_runner(){
    cmd=$@
    TIMEOUT='24h'
    START=$(date +%s)
    outfilename="res-tamarin.csv"
    IFS='' # required to keep the tabs and spaces
    filename=$(echo "$cmd $method" | sed "s/[^[:alnum:]-]//g")
    #echo $filename
    echo "START: timeout $TIMEOUT tamarin-prover $cmd --prove +RTS -N4 -RTS"
    res=$(eval "timeout $TIMEOUT tamarin-prover $cmd --prove +RTS -N4 -RTS 2> /dev/null")
    END=$(date +%s)
    DIFF=$(echo "$END - $START" | bc)
    res2=$(echo -n $res | grep "verified\|falsified"  | tr '\n' ' ') 
    echo "$filename; $method; $res2; $DIFF;"  >> "$outfilename"
    echo "END: $method $flag $cmd"
}

outfilename="res-tamarin.csv"

# Print headers
echo "filename; method; result; time" >> "$outfilename"


export -f exec_runner
for cmd in  "${cmds[@]}"; do
        sem -j $N exec_runner $cmd
done
sem --wait
