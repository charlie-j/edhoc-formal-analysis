<!> if you tried to enter the Docker and see this message, run 
```
docker run -it protocolanalysis/lake-edhoc:draft-14 bash
```
to actually enter the image. <!>

# Prerequisite

The case-studies are based on the Sapic+ protocol platform, which allows from a single input file to export to Tamarin, Proverif and Deepsec.

We provide a Docker Image with all required tools preinstalled and the case studies folder on DockerHub. It can be obtained with:

 $ docker pull protocolanalysis/lake-edhoc:draft-14

Alternatively, one may install the Sapic+ version neeeded for our case studies through the provided archive (with corresponding README), and then follow the installations instructions from the Proverif (https://proverif.inria.fr/) and DeepSec (https://deepsec-prover.github.io/) webpages. 

# High Level Description

This is the lake-edhoc case study main readme. In the same directory, you will find folders `lake-draftX`, where X is the corresponding version of the draft. Each subfolder contains the full case-study for version X.

In `lake-draftX`, you may find several `.spthy` files, the tamarin and Sapic+ input format, that correspond to variants of the protocol:
 * `lake-edhoc.spthy` -> the classical model (with 4 authentication methods) of the protocol
 * `lake-edhoc-KEM.spthy`  -> the KEM based variant
 * `lake-edhoc-Sig-DDH.spthy` -> EDHOC with a more precise model of Signatures and DDH which is event based
 * `lake-edhoc-KEM-Sig.spthy`  -> EDHOC KEM based with a more precise model of Signatures
 * `lake-edhoc-KEM-Hash.spthy`  -> EDHOCs with a more precise model of hash
 
 
 Each of those files shares some common headers, in `Headers.splib`, and the security lemmas, in `LakeProperties.splib`. Moreover, each of those files contains multiple options for advanced threat models that can be enabled or disabled with flags, specified to tamarin on the command line using the "-D" option. 
 
 The `.spthy` files share most of their code as they were actually generated using the Jinja2 templating engine using the template in the `lake-draftX/templates/` subfolder. For simplicity, we however provide them pre-generated.
 
Each `lake-draftX` folder contains a set of `.sh` scripts that can be used to reproduce our results and will output the accumulated results of many verifications inside `.csv` files. Note that those scripts may require a lot of time to run, and most of them heavily rely on parallelization. We will describe those in the next section.

As an alternative, `lake-draft12/README.md` contains a set of individual commands that illustrate how to use the platform, and allow to reproduce some of our main attacks. We also stored the output file we obtained when runnning the scripts in `lake-draft12/csv-results/`.  `lake-draft12/csv-results/res-pro.ods` is a libreoffice calc sheet that agregates some of those results and formats them in a more readable way.
 
 
# Lake-draft12 
 
This folder contains the following scripts:
 * `check-sanity.sh` -> verify sanity checks of the model on each file to ensure that the protocol models are actually running.  
 * `run-proverif.sh` and `run-proverif-EB.sh` -> explore all possible scenarios and threat models over all the files.
  * `run-proverif-compressed.sh` and `run-proverif-compressed-KEM.sh` -> verify the most significant scenarios, extracted thanks to the two previous scripts. They can be used to efficiently reproduce our result without having to re-explore redundant scenarios.
 * `run-anonimity.sh` -> verifies anonymity properties.
 
# Lake-draft14
 

This folder contains similar `check-sanity.sh`, `run-proverif-compressed-KEM.sh`, `run-anonimity.sh` and `run-proverif-compressed.sh` scripts, which can be used to verify that the weaknesses obtain in draft12 are not present anymore. Note that we can focus on the significant scenarios identified on draft 12, and do not have to re-run everything.

In addition, it contains a script `run-tamarin-compressed.sh`, that contains all tamarin commands that produce verification in under 20 hours, and that provide stronger guarantees than proverif on the verified models. It notably contains the command showing that the transcript collision attack is not possible anymore.


# Lake-draftX

For future updates, one should:
 * copy-paste the latest `lake-draftY` folder version to the new version name;
 * propagate the changelog of the standard in the main model file `lake-draftX/templates/lake-edhoc.jinja.spthy`;
 * execute `lake-draftX/templates/generate-models.sh` to overwrite the old spthy file;
 * first verify that the new model runs with `check-sanity.sh`;
 * then run all other scripts, starting with the faster proverif scripts and moving to the tamarin scripts at the end, inspecting the results.
 

