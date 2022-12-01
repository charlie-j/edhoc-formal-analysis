#!/bin/bash

sort res-tamarin.csv > res-tamarin-sorted.csv
git diff --color-words expected-results/res-tamarin.csv res-tamarin-sorted.csv
