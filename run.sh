python3 auto_checker.py -j 60 -fs re_no_comp
# 10 minutes

python3 auto_checker.py -fl res_no_comp -c -fs res_comp


time python3 auto_checker.py -fl res_comp -rt -t 3600 -j 60 -fs res_long
# 661 minutes

python3 auto_checker.py -fl res_long -c -fs res_proverif_final

