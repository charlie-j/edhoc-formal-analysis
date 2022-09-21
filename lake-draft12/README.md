In this README, we provide individual commands needed to reproduce some of our attacks.

# Results on lake-edhoc.spthy

A call to tamarin with the argument `-m=proverif` translates the input file to a proverif file, that can be redirected to a file and verified with proverif.

## Proverif results

### Session key uniqueness


* tamarin-prover --lemma=authRI_unique -m=proverif lake-edhoc.spthy  > t.pv; proverif t.pv
 
Attack found, in 21 seconds, with the Neutral DH element sent by some compromised session.
 
 
* tamarin-prover --lemma=authRI_unique -m=proverif lake-edhoc.spthy  -D=NeutralCheck -D=WeakestSignature -D=LeakSessionKey > t.pv; proverif t.pv

Verified. The neutral check element forbids the previous attack.


### Session key and ephemeral share leaks

 * tamarin-prover --lemma=honestauthRI_non_inj -m=proverif lake-edhoc.spthy -D=LeakShare > t.pv; proverif t.pv

Attack found:

  * attacker initiates session with R, claiming to be I, and receive share from some R
  * attacker initiate session with I, forward the share of R, and use the epheremal key leak to complete the exchange
  * the session key of (I with attacker) is also the mac key, that can also be used to confirm the session (R with I) where the attacker impersonate I, so leaking the session key leaks the mac key, and attacker complete session with R.


### Reflection attacks

 * tamarin-prover --lemma=no_reflection_attacks_RI -m=proverif lake-edhoc.spthy > t.pv; proverif t.pv

Attack found (of course).

 tamarin-prover -m=proverif lake-edhoc.spthy  -D=CredCheck -D=SanityChecks > t.pv; proverif t.pv

Verified.



### Data auth

 * tamarin-prover -m=proverif lake-edhoc.spthy --lemma=data_authentication_R_to_I -D=LeakSessionKey > t.pv; proverif t.pv

Verified.
 
  
 * tamarin-prover -m=proverif lake-edhoc.spthy -D=XorPrecise --lemma=data_authentication_R_to_I -D=LeakSessionKey > t.pv; proverif t.pv

Verified.


 * tamarin-prover -m=proverif lake-edhoc.spthy -D=XorPrecise --lemma=data_authentication_I_to_R > t.pv; proverif t.pv
Attack found: m2 auth is borken If a signature is xor malleable, I can receive a valid signature different than the one sent by R.

Warning: XorPrecise is not yet implemented in Tamarin :/

 * tamarin-prover -m=proverif lake-edhoc.spthy -D=WeakAEAD --lemma=data_authentication_R_to_I > t.pv; proverif t.pv
Attack found: TH_4 as the cyphertext_3 is malleable

 * tamarin-prover -m=proverif lake-edhoc.spthy -D=LeakSessionKey --lemma=data_authentication_R_to_I_wleaks > t.pv; proverif t.pv
 
Attack found: TH_4 can be broken with
  - the attacker uses the leaked session key to renencrypt cyphertext_3 with a new random;
  - alternative are that with in addition a malleable signature (-D=WeakestSignature or -D=XorPrecise), it can also alter the sign2 under the aead.
  


### Non Repudiation Soundness 

Injective queries, exported by hand in the export field.

* tamarin-prover -D=NonRepudiationSoundness -m=proverif lake-edhoc.spthy -m=proverif --lemma=none > t.pv; proverif t.pv

Attack found: the attacker can send to an agent grpid, and then prove that the agent participated in many sessions.

* tamarin-prover -D=NonRepudiationSoundness -m=proverif lake-edhoc.spthy -m=proverif --lemma=none -D=NeutralCheck > t.pv; proverif t.pv

Attack found:
if the attacker can intercept a proof for g^x,y, it could then make a proof for g^y, x.

* tamarin-prover -D=NonRepudiation -m=proverif lake-edhoc.spthy -m=proverif --lemma=none -D=NeutralCheck -D=WeakestSignature > t.pv; proverif t.pv

Attack found: the attacker can use the malleability of the signature to produce multiple proofs

--> always true in the non injective setting.

--> does this mean only method 0, or also 1 and 2 but in a single direction?
We verify this for all methods where the responder is using a signature key, which are method 0 and 2.
For the initiator, it can only be done in method 0, as otherwise the responder must leak its own long term DH key.


## Tamarin results

We report here only on the  Chosen prefix collision attack. It can be obtained with

### Chosen prefix collision attack

The attacker can break the secrecy and authentication, if small subgroups are available.

The following command, using 4 cores, allows to find the attack in the KEM version but takes about 16 hours to terminate:

* tamarin-prover lake-edhoc-KEM-Hash.spthy -D=FreshDomain -D=CPcol -D=LEcol --prove=secretI +RTS -N4 -RTS -D=weakKEM -D=SingleHash


Alternatively, one can use the interactive mode of tamarin to explore the possible attacks, either on lake-edhoc-KEM-Hash.spthy or lake-edhoc-Hash.spthy :
 *  tamarin-prover  interactive .  -D=FreshDomain -D=CPcol -D=LEcol --prove=secretI +RTS -N4 -RTS -D=weakKEM -D=SingleHash


Basic attack on secrecy, abusing EAD_1 and C_R
```
Trans   := Method      || suitesI || G_X   || C_I   ||  EAD_1  ||   G_Y   || C_R 

Trans_I := method_zero || suitesI || G_X   || 'C_I' || 'EAD_1' || GrpID   || CPcol2 ||   G_Y || C_R 
Trans_R := method_zero || suitesI || grpid || 'C_I' || CPcol1  ||  G_Y    || 'C_R'
```

Attacks on suite auth:
```
Trans   := Method      || suitesI   || G_X || C_I   || EAD_1 ||   G_Y   || C_R 
Trans_I := method_zero || suitesI   || G_X || C_I   || EAD_1 || grpid   || CPcol2 || grpid || C_I || EAD_1 || G_Y     || C_R
Trans_R := method_zero ||  CPcol1   || grpid || C_I || EAD_1 || G_Y     || C_R
```

