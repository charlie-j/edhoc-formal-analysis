time python3 auto_checker.py -j 60 -fs res_12_14_no_comp
# 23m40s

python3 auto_checker.py -fl res_12_14_no_comp -c res_12_14_comp

python3 auto_checker.py -fl res_12_14_comp -rt -t 3600 -j 60 -fs res_12_14_no_comp_long
# 1100m

python3 auto_checker.py -fl res_12_14_no_comp_long -c -fs res_12_14_comp_long


python3 auto_checker.py -fl res_12_14_comp_long -lt -olt res_12_14.tex
