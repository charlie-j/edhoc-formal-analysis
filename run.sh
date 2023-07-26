time python3 auto_checker.py -j 60 -fs res_no_comp
# 9m54s

python3 auto_checker.py -fl res_no_comp -c -fs res_comp


time python3 auto_checker.py -fl res_comp -rt -t 3600 -j 20 -fs res_no_comp_long
# 1480m

python3 auto_checker.py -fl res_no_comp_long -c -fs res_comp_long

time python3 auto_checker.py -j 15 -fl res_comp_long -fst res_tamarin -tam -t 7200
# 733m

python3 auto_checker.py -fl res_comp_long -flt res_tamarin -lt -olt res.tex
