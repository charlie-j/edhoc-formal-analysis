
# Description

This repository contains the models for the formal analysis of the Lake EDHOC protocol.
The version under verification is draft 18 (https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/18/).

In this reposity, you will find
 * the `Archives` subfolder containing the previous models for draft 12 and draft 14 corresponding to the results reported in the paper `A comprehensive, formal and automated analysis of the EDHOC protocol`- Charlie Jacomme, Elise Klein, Steve Kremer, Maïwenn Racouchot, to appear at USENIX'23.
 * the `models` subfolder contains the actual model, see details bellow.
 * the `SecurityClaims.md` file, which contains the extracted security related mentions inside the draft. In this file, the text between `quotes` is the one explicitely reused inside the specification of the security properties in `models/LakeProperties.splib`.
 * the `auto_checker.py` script along with additional scripts in `utilities`, that allow to run the full analaysis (see prerequisite). `res.pdf` is the automated results produced by the script, after following the steps described in `run.sh`.
 

# Prerequisite

The case-studies are based on the Sapic+ protocol platform, which allows from a single input file to export to Tamarin, Proverif and Deepsec.

We provide a Docker Image with all required tools preinstalled and the case studies folder on DockerHub. It can be obtained with:

 $ docker pull protocolanalysis/lake-edhoc:draft-14

Alternatively, one may install the Sapic+ version neeeded for our case studies from the dedicated git repository (https://github.com/charlie-j/tamarin-prover/tree/feature-proverif-output-with-assoc) and the DeepSec (https://deepsec-prover.github.io/) webpages. 

# High Level Description


In `model`, you may find several `.spthy` files, the tamarin and Sapic+ input format, that correspond to variants of the protocol:
 * `lake-edhoc.spthy` -> the classical model (with 4 authentication methods) of the protocol
 * `lake-edhoc-KEM.spthy`  -> the KEM based variant
 * `lake-edhoc-Sig-DDH.spthy` -> EDHOC with a more precise model of Signatures and DDH which is event based
 * `lake-edhoc-KEM-Sig.spthy`  -> EDHOC KEM based with a more precise model of Signatures
 * `lake-edhoc-KEM-Hash.spthy`  -> EDHOCs with a more precise model of hash
 
 Each of those files shares some common headers, in `Headers.splib`, and the security lemmas, in `LakeProperties.splib`. Moreover, each of those files contains multiple options for advanced threat models that can be enabled or disabled with flags, specified to tamarin on the command line using the "-D" option. 
 
 The `.spthy` files share most of their code as they were actually generated using the Jinja2 templating engine using the template in the `model/templates/` subfolder. For simplicity, we however provide them pre-generated.
 
# Auto_checker usage
 
TODO
