time python3 auto_checker.py -j 60 -fs res_12_14_no_comp
# 23m40s

time python3 auto_checker.py -fl res_12_14_no_comp -c res_12_14_comp

time python3 auto_checker.py -fl res_12_14_comp -rt -t 3600 -j 60 -fs res_12_14_no_comp_long
# 1100m

time python3 auto_checker.py -fl res_12_14_no_comp_long -c -fs res_12_14_comp_long

time python3 auto_checker.py -j 15 -fl res_12_14_comp_long -fst res_12_14_tamarin -tam -t 7200
# 2980m

python3 auto_checker.py -fl res_12_14_comp_long -flt res_12_14_tamarin -lt -olt res_12_14.tex
