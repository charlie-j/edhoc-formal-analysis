#!/bin/bash

sort res-proverif.csv > res-proverif-sorted.csv
git diff --color-words expected-results/res-proverif.csv res-proverif-sorted.csv
