#!/bin/bash
jinja lake-edhoc.jinja.spthy -o ../lake-edhoc.spthy
jinja lake-edhoc.jinja.spthy -D SignatureEvent t -D DDHEvent t -o ../lake-edhoc-Sig-DDH.spthy
jinja lake-edhoc.jinja.spthy -D SignatureEvent t -o ../lake-edhoc-Sig.spthy
jinja lake-edhoc.jinja.spthy -D DDHEvent t -o ../lake-edhoc-DDH.spthy
jinja lake-edhoc.jinja.spthy -D HashEvent t -o ../lake-edhoc-Hash.spthy

jinja lake-edhoc.jinja.spthy -D KEM t -o ../lake-edhoc-KEM.spthy
jinja lake-edhoc.jinja.spthy -D KEM t -D SignatureEvent t -o ../lake-edhoc-KEM-Sig.spthy
jinja lake-edhoc.jinja.spthy -D KEM t -D HashEvent t -o ../lake-edhoc-KEM-Hash.spthy
