#!/usr/bin/env python3

"""
This script allows to run proverif on a list of protocols specified 
in proverif, with some c preprocessor to specify different scenarios.

The results are computed using parallelization, and are then post 
processed for a nice display, with finally a rendering using a tex
template.

"""

import os
import sys
import signal
import subprocess
import argparse
import smtplib
import json
import time

from email.header import Header
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from multiprocessing import Pool
import multiprocessing.pool
from functools import partial
from multiprocessing.managers import BaseManager
from multiprocessing import Manager

FOLDER = ""

###############
## UTILITIES ##
###############

def set_result(results,scen,res):
    try:
        previous_res = results[scen.prot][scen.lemma]["*".join(scen.threats)]
        if not(previous_res == res):
            print("Updating result for %s %s from %s to %s " % (scen.prot, scen.lemma, previous_res,res))
        results[scen.prot][scen.lemma]["*".join(scen.threats)] = res
            
    except:
        results[scen.prot][scen.lemma]["*".join(scen.threats)] = res
        
def get_result(results,scen):
    return results[scen.prot][scen.lemma]["*".join(scen.threats)]

        
# BaseManager.register("myresult",Data)


manager = Manager()




def powerset(s):
    x = len(s)
    masks = [1 << i for i in range(x)]
    for i in range(1 << x):
        yield [ss for mask, ss in zip(masks, s) if i & mask]

# We define the main parameters of the case study, first as full list, where we will intuitively want to consider all possible protocol and lemma under all subsets of attacker capabitlies and features

Protocols = ["models/lake-edhoc", "models/lake-edhoc-KEM"]

# Our list of target lemmas
Lemmas = [ "authIR_unique", "authRI_unique", "data_authentication_I_to_R", "data_authentication_R_to_I", "honestauthRI_non_inj", , "honestauthRI_unique", "secretI", "secretR", "honestauthIR_non_inj", "honestauthIR_unique" ]

# The list of Attacker Capabilities or Features we are going to look at.
AtomThreatModel= ["PreciseSignature", "PreciseSignatureProof", "LeakSessionKey", "WeakAEAD", "XorPrecise", "LeakShare", "PreciseDH"]
ThreatModels=list(powerset(AtomThreatModel))

Features = []

    

# Order in threat models, list of which capability is stronger than which other one.
# It will thus filter some threat models that are redundant.    
OrderedCapabilities = [["PreciseSignature", "PreciseSignatureProof"] ]

class Scenario:
  def __init__(self, prot, lemma, threats):
    self.prot=prot
    self.lemma=lemma
    self.threats=threats

  # We define the subset of interesting scenarios with a set of sometimes hardcoded constraints    
  def valid(self):
     threats = self.threats
     # for each dimension
     for dimension in OrderedCapabilities:
         # if there are two points of the dimension at in the threats, it is a redudant scenario
         if any( a!=b and a in threats and b in threats for a in dimension for b in dimension):
             return False
         elif "CredCheck" in threats and not self.lemma=="no_reflection_attacks_RI":
              return False
         elif "KEM" in self.prot and "PreciseDH" in threats:
             return False
         elif "KEM" in self.prot and "NeutralCheck" in threats:
             return False       
     return True


  def filename(self):
    name = self.prot
    if "PreciseSignatureProof" in self.threats:
        name += "-Sig"
    if "PreciseDH" in self.threats:
        name += "-DDH"
    name += ".spthy"
    return name

    
  def __repr__(self):
       threats = [i for i in self.threats if i not in ["PreciseSignatureProof", "PreciseDH"] ]
       header="%s --lemma=%s" % (self.filename(), self.lemma)
       if threats == []:
           return header
       else:
           threats= " -D=".join(threats)           
           return header + " -D=" + threats

  def tamarin_args(self):
      return self.__repr__()

def is_weaker_scenario(scen1,scen2):
    if not(scen1.lemma == scen2.lemma and scen1.prot == scen2.prot):
        return None # incomparable
    for feature in Features:
        # adding a feature weaken the attacker
        if (feature in scen2.threats and not feature in scen1.threats):
            return "false" 
    orderedthreatmodels = [i for dim in OrderedCapabilities for i in dim]
    nonorderedthreatmodels = [i for i in AtomThreatModel if i not in orderedthreatmodels]
    for atom in nonorderedthreatmodels:
        if atom in scen1.threats and not atom in scen2.threats:
            return "false"
    for dim in OrderedCapabilities:
        dimsc1 = [dim.index(x) for x in dim if x in scen1.threats]
        dimsc2 = [dim.index(x) for x in dim if x in scen2.threats]
        if len(dimsc2) == 0 and len(dimsc1) != 0:
            return "false"
        if (len(dimsc2) != 0 and len(dimsc1) != 0  and dimsc1[0] > dimsc2[0]):
            return "false"
    return "true"


def print_res(data,data_tam,prot,lemma,res_for_prot,index):
    try:
        scenario=res_for_prot[prot][index]
        res=data[prot][lemma][scenario]
        if "true" in res and res[1]=="implied":
            string_res= "\\okp{implied}"            
        elif "true" in res:    
            string_res= "\\okp{%s}" % int(res[1])
        elif "false" in res and res[1]=="implied":
            string_res= "\\attp{implied}"
        elif "false" in res:
            string_res= "\\attp{%s}" % int(res[1])            
        scenarios = scenario.split("*")
        return u""" &  \\begin{tabular}{c} 
        \\small \\"""+  ', \\'.join(scenarios) + """ \\\\ """ +  string_res + """\\end{tabular}"""   
    except IndexError:
        return u""" & """


def print_res_simpl(data,data_tam,prot,lemma,scenario):
    try:
        res=data[prot][lemma][scenario]
        if "true" in res and res[1]=="implied":
            string_res= "\\okp{\\implied}"            
        elif "true" in res:    
            string_res= "\\okp{%s}" % int(res[1])
        elif "false" in res and res[1]=="implied":
            string_res= "\\attp{\\implied}"
        elif "false" in res:
            string_res= "\\attp{%s}" % int(res[1])
        elif "timeout" in res:
            string_res = "\\timeoutp"
        elif "invalid" in res:
            string_res = "\\invalid"            
        else:
            string_res = str(res)
        if scenario in data_tam[prot][lemma].keys():
            res_tam=data_tam[prot][lemma][scenario]
            if "true" in res_tam and res_tam[1]=="implied":
                string_res_tam= "\\okt{\\implied}"            
            elif "true" in res_tam:    
                string_res_tam= "\\okt{%s}" % int(res_tam[1])
            elif "false" in res_tam and res_tam[1]=="implied":
                string_res_tam= "\\attt{\\implied}"
            elif "false" in res_tam:
                string_res_tam= "\\attt{%s}" % int(res_tam[1])
            elif "timeout" in res_tam:
                string_res_tam = "\\timeoutt"
            elif "invalid" in res_tam:
                string_res_tam = "\\invalid"                
            else:
                string_res_tam = str(res_tam)
        else:
            string_res_tam = ""
            
        scenarios = scenario.split("*")
        # return u""" &  \\begin{tabular}{c} 
        # \\small \\"""+  ', \\'.join(scenarios) + """ \\\\ """ +  string_res + " " + string_res_tam + """\\end{tabular}"""
        return u""" & """ +  string_res + " " + string_res_tam
    except KeyError:
        return u""" & """
    
lemmas_to_tex = {
    "no_reflection_attacks_RI":"noReflexionAttackRI",
    "authIR_unique":"authIRunique",
    "data_authentication_I_to_R":"dataAuthIR",
    "data_authentication_R_to_I":"dataAuthRI",
    "honestauthRI_non_inj":"honnestAuthRInonInj",
    "secretI":"secretI",
    "secretR":"secretR"
    }


def completion(data):
    for prot in Protocols:
        for lemma in Lemmas:
            for key in data[prot][lemma].keys():
                    for prot2 in Protocols:
                        if not key in data[prot2][lemma].keys():
                            target_scenario = Scenario(prot2,lemma,key.split("*"))
                            if target_scenario.valid():                                
                                data[prot2][lemma][key] = ("failed","failed")
                                for implier in data[prot2][lemma].keys():
                                    impl_scenario = Scenario(prot2,lemma,implier.split("*"))                                    
                                    if is_weaker_scenario(impl_scenario,target_scenario)=="true" and "false" in data[prot2][lemma][implier]:
                                        data[prot2][lemma][key] = ("false", "implied")
                                    elif is_weaker_scenario(target_scenario,impl_scenario)=="true" and "true" in data[prot2][lemma][implier]:
                                        data[prot2][lemma][key] = ("true", "implied")
                            else:
                                data[prot2][lemma][key] = "invalid"                                
    return data
        
def gen_tex(data1, data_tam, filename):
    """Generates the tex array for the given list of protocols"""
    # need to escape \t, \n, \b \a
    data = completion(data1)
#    print(json.dumps(data, indent=4))    
    
    tex_template =  u"""\documentclass[letterpaper, 10pt, table]{standalone}

\\usepackage[svgnames,dvipsnames]{xcolor}
\\usepackage{pifont}
\\usepackage{fontawesome5}
\\usepackage{multicol}
\\usepackage{nicematrix}
\\usepackage{marvosym}

\\definecolor{darkgreen}{rgb}{0.0, 0.2, 0.13}
\\definecolor{darkred}{rgb}{0.55, 0.0, 0.0}
\\definecolor{cadmiumgreen}{rgb}{0.0, 0.42, 0.24}
\\definecolor{darkblue}{rgb}{0.0, 0.0, 0.55}


\\newcommand{\\attack}{\\textcolor{FireBrick}{\\ding{55}}}
\\newcommand{\\ok}{\\textcolor{Green}{\\ding{51}}}



\\newcommand{\\attp}[1]{\\attack$^P$~(#1)}
\\newcommand{\\attpnt}{\\attack}
\\newcommand{\\attt}[1]{\\attack$^T$~(#1)}
\\newcommand{\\attd}[1]{\\attack$^D$~(#1)}
\\newcommand{\\attdnt}{\\attack$^D$}

\\newcommand{\\implied}{$\Rightarrow$}

\\newcommand{\\okp}[1]{\\ok$^P$~(#1)}
\\newcommand{\\okpnt}{\\ok$^P$}
\\newcommand{\\okt}[1]{\\ok$^T$~(#1)}
\\newcommand{\\oktnt}{\\ok$^T$}
\\newcommand{\\okd}[1]{\\ok$^D$~(#1)}
\\newcommand{\\okdnt}{\\ok$^D$}

\\newcommand{\\timeoutp}{\\faClock[regular]$^P$}
\\newcommand{\\timeoutt}{\\faClock[regular]$^T$}
\\newcommand{\\invalid}{$\emptyset$}


\\newcommand{\\authIRunique}{auth-IR-unique}
\\newcommand{\\authRIunique}{auth-RI-unique}
\\newcommand{\\dataAuthIR}{data-authentication-IR}
\\newcommand{\\dataAuthRI}{data-authentication-RI}
\\newcommand{\\honnestAuthRInonInj}{honest-auth-RI-non-inj}
\\newcommand{\\noReflexionAttackRI}{no-reflection-attacks-RI}
\\newcommand{\\secretI}{secretI}
\\newcommand{\\secretR}{secretR}
\\newcommand{\\repudiationSoundness}{repudiation-soundness}

\\newcommand{\\weak}[1]{#1\\ensuremath{^{\\text{\\Lightning}}}}

\\newcommand{\\PreciseSignature}{{\\sf \\weak{Sig}}}
\\newcommand{\\WeakAEAD}{{\\sf \\weak{AEAD}}}
\\newcommand{\\WeakHash}{{\\sf \\weak{Hash}}}
\\newcommand{\\XorPrecise}{{\\sf \\weak{$\\oplus$}}}



\\newcommand{\\PreciseSignatureProof}{{\\sf \\weak{Sig}-proof}}
\\newcommand{\\PreciseDH}{{\\sf \\weak{DH}}}

\\newcommand{\\LeakSessionKey}{{\\sf \\weak{SessKey}}}
\\newcommand{\\LeakShare}{{\\sf \\weak{DHShare}}}


\\newcommand{\\NeutralCheck}{{\\sf DH-Check}}
\\newcommand{\\CredCheck}{\\sf Cred-Check}



\\begin{document}

\\begin{tabular}{c}

 \\begin{NiceTabular} {c c """ + " ".join([ "c" for p in Protocols]) + """ }
   \\CodeBefore
    \\rowlistcolors{2}{Gray!15,White}[restart,cols={1-""" + str(2+len(Protocols)) + """}]
    \\Body
    \\bf Lemma & Scenario  """ + "".join([ (" & \\bf %s " % prot) for prot in Protocols])  + """  \\\\ \\hline

  

"""

    for lemma in Lemmas:
        tex_template += """
\\""" + lemmas_to_tex[lemma]
        # res_for_prot = {}
        # for prot in Protocols:
        #     res_for_prot[prot] = [scen for scen in data[prot][lemma].keys() if data[prot][lemma][scen][0] in ["true","false"]]
        # maxrange=max([len(res_for_prot[prot]) for prot in Protocols])
        # for i in range(0,maxrange):
            # for prot in Protocols:                      
            #     tex_template +=  print_res(data,prot,lemma,res_for_prot,i)
        threats=list(set([threat for prot in Protocols  for threat in data[prot][lemma].keys() ]))
        threats.sort(reverse=False,key=lambda x: len(x))
        for threat in threats :
            if any([data[prot][lemma][threat][0]  in ["true","false"] and not data[prot][lemma][threat][1]=="implied" for prot in Protocols]):
                threat_display = threat.split("*")                
                tex_template += """ & \\""" +  ', \\'.join(threat_display)  
                for prot in Protocols:
                    tex_template +=  print_res_simpl(data,data_tam,prot,lemma,threat) 
                tex_template += """  \\\\ """
        tex_template += """  \\hline """                      
            

    tex_template += """\\end{NiceTabular} 
\\\\ 
\\\\
\\textbf{Automated aggregation of results}
\\\\
\\\\
For each lemma and each scenario, we display the result of the automated analysis based on Proverif and Tamarin. \\\\
 We display all scenarios for which at least one of the protocol has a non trivial and non timeout result.
\\\\
\\\\
\\begin{tabular}{rl}
\\attt{x},\\attp{x}:& attack found with Tamarin (T) or Proverif (P) in x seconds \\\\
\\okt{x},\\okp{x}:& proof found with Tamarin (T) or Proverif (P) in x seconds \\\\
 (\\implied):& means the result is implied by another displayed result \\\\
\\timeoutt,\\timeoutp: & timeout for Tamarin (T) or Proverif (P) \\\\
\\invalid: & the scenario is irrelevant for this protocol (e.g., DH weakness in KEM setting)

\\end{tabular}

\\end{tabular}

 \\end{document} """
    with open(filename, 'w') as res_file:
        res_file.write(tex_template)


# utility functions to merge dictionnaries
def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

# base function which calls the subscript computing the results
def call_prover(scen,prover):
    if prover=="proverif":
        cmd = "./utilities/proverif-tamarin %s" % (FOLDER + scen.tamarin_args())
    elif prover=="tamarin":
        cmd = "tamarin-prover %s --prove +RTS -N4 -RTS" % (FOLDER + scen.tamarin_args())        
    print(cmd)
    inittime = time.time()    
    process = subprocess.Popen(cmd.split(),cwd=os.path.dirname(os.path.realpath(__file__)),stderr=subprocess.STDOUT,stdout=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        output, errors = process.communicate(timeout=TIMEOUT)
        if prover=="proverif":
            proof_results = [line for line in str(output).split('\\n') if "RESULT" in line]
            if len(proof_results) != 1:
                print(output)
                return (cmd+"test"+" ".join(proof_results))
            res = proof_results[0]
            runtime = time.time() - inittime    
            if "true" in res:
                return ("true", runtime)
            elif "false" in res:
                return ("false", runtime)
            elif "cannot" in res:
                return ("cannot", runtime)
            return ("unrecognized result", runtime)
        elif prover=="tamarin":
            if "Maude returned warning" in str(output):
                return "AssociativeFailure"
            elif "CallStack" in str(output) or "internal error" in str(output):
                return "TamarinError"
            proof_results = [line for line in str(output).split('\\n') if (" "+scen.lemma+" " in line and "steps" in line)]
            if len(proof_results) == 1:
                line = proof_results[0]
                runtime = time.time() - inittime                    
                if "verified" in line:
                    return ("true", runtime)
                elif "falsified" in line:
                    return ("false", runtime)
                else:
                    return ("unrecognized result", runtime)
            else:
                return ("unrecognized result", runtime)        
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM) 
        return ("timeout", TIMEOUT)
    except OSError:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM) 
        return ("oom", TIMEOUT)        

# function which checks if the protocols are running
def check_sanity(prot):
    proof_results = call_check(prot, "SANITY", "")
    print(proof_results)
    for res in proof_results:
        if "true" in res or "failure" in res:
            raise "Not running protocols"                
        
def load_result_scenario(results,prover,scenario):
    try:
        get_result(results,scenario)
    except: # when the result does not exists
        res =  call_prover(scenario,prover)
        print("Protocol %s is %s for lemma %s in threat model %s" % (scenario.prot, res, scenario.lemma, " ".join(scenario.threats)))
        set_result(results,scenario,res)
        if res[0] == "true":
            for scen in scenarios:
                if str(scen) != str(scenario) and is_weaker_scenario(scen,scenario)=="true":
                    print("Protocol %s is %s for lemma %s in threat model %s ==> also for %s " % (scenario.prot, res, scenario.lemma, " ".join(scenario.threats),  " ".join(scen.threats)))                                
                    set_result(results,scen,("true","implied"))
        if res[0] == "false":
            for scen in scenarios:
                if str(scen) != str(scenario) and is_weaker_scenario(scenario,scen)=="true":
                    print("Protocol %s is %s for lemma %s in threat model %s ==> also for %s " % (scenario.prot, res, scenario.lemma, " ".join(scenario.threats),  " ".join(scen.threats)))                                
                    set_result(results, scen,("false","implied"))
        if prover=="tamarin":
            bck_results(results)

def load_results(results, prover):    
    pool = Pool(processes=JOBS)
    res = pool.map(partial(load_result_scenario,results,prover), scenarios, chunksize=1)
    pool.close()
    # for scen in scenarios:   # for debug
    #     load_result_scenario(results,prover,scen)
    

def bck_results(results):    
    res = {}
    for prot in Protocols:
        res[prot]={}
        for lemma in Lemmas:
            res[prot][lemma]={}
            for key in results[prot][lemma].keys():
                res[prot][lemma][key]=results[prot][lemma][key]    
    f = open("tamarin.bck", "w")
    f.write(json.dumps(res, indent=4))
    f.close()            
    
def init_result():
    results = manager.dict()
    for prot in Protocols:
        sub = manager.dict()
        results[prot] = sub
    for prot in Protocols:    
        for lemma in Lemmas:
            sub = manager.dict()            
            results[prot][lemma] = sub
    return results

parser = argparse.ArgumentParser()
parser.add_argument('-c','--compress', help='Compress the results, based on threqt models implications',  action='store_true')
parser.add_argument('-rt','--retry', action="store_true",  help='For timeout jobs, retry to prove them')
parser.add_argument('-lt','--latex', action="store_true", help='Save results into a latex file')
parser.add_argument('-olt','--outputlatex', help='Latex file name')
parser.add_argument('-fs','--filesave', nargs='+', help='Save proverif results into file')
parser.add_argument('-fl','--fileload', nargs='+', help='Load proverif results from file')
parser.add_argument('-fst','--filesavetamarin', nargs='+', help='Save tamarin results into file')
parser.add_argument('-flt','--fileloadtamarin', nargs='+', help='Load tamarin results from file')
parser.add_argument('-t','--timeout', type=int, help='Timeout for execution')
parser.add_argument('-tam','--tamarin', help='Double check true results with Tamarin. each job taks 4 cores',  action='store_true')
parser.add_argument('-j','--proverifjobs', type=int, help='Number of parallel proverif jobs, default = total cores')
args = parser.parse_args()

if not args.retry:
    scenarios=[]         
    for prot in Protocols:
        for lemma in Lemmas:
            for threat in ThreatModels:
                scen=Scenario(prot,lemma,threat)
                if scen.valid():
                    scenarios += [scen]
    scenarios.sort(reverse=False,key=lambda x: len(x.threats))
    print("Checking %i scenarios" % (len(list(scenarios))))

# fixed scenarios for test    
#scenarios=[Scenario("lake-draft14/lake-edhoc-KEM","authIR_unique" ,["PreciseSignature"])]
#
# TODO
# for prot in Protocols:
#     check_sanity(prot)

if args.proverifjobs:
    JOBS = args.proverifjobs
else:
    JOBS = int(os.cpu_count())

if args.timeout:
    TIMEOUT = args.timeout
else:
    TIMEOUT = 30

if args.fileload:
    with open(args.fileload[0]) as user_file:
        file_contents = user_file.read()
    res = json.loads(file_contents)
    results=res
else:
    results = init_result()
    load_results(results, "proverif")

if args.retry:
    scenarios=[]
    proved_scenarios=[]
    for prot in Protocols:
        for lemma in Lemmas:
            for threat in ThreatModels:
                scen=Scenario(prot,lemma,threat)
                try:
                    if scen.valid() and get_result(results,scen)[0]!="true" and get_result(results,scen)[0] != "false":
                        scenarios += [scen]
                    elif scen.valid() and (get_result(results,scen)[0]=="true" or get_result(results,scen)[0] == "false"):
                        proved_scenarios += [scen]
                except: None
    scenarios.sort(reverse=False,key=lambda x: len(x.threats))
    print("ReChecking %i scenarios" % (len(list(scenarios))))
    new_results = init_result()
    for scen in proved_scenarios:
        set_result(new_results,scen,get_result(results,scen))
    results=new_results
    load_results(results, "proverif")

if args.fileloadtamarin:
    with open(args.fileloadtamarin[0]) as user_file:
        file_contents = user_file.read()
    res = json.loads(file_contents)
    tam_res = res
else:
    tam_res = {}
    for prot in Protocols:
        tam_res[prot]={}
        for lemma in Lemmas:
            tam_res[prot][lemma]={}
                
    
if args.tamarin:
    results=completion(results)
    scenarios=[]
    for prot in Protocols:
        for lemma in Lemmas:
            for threat in ThreatModels:
                scen=Scenario(prot,lemma,threat)
                try:
                    if scen.valid() and get_result(results,scen)[0]=="true": 
                        scenarios += [scen]
                except: None
    scenarios.sort(reverse=False,key=lambda x: len(x.threats))
    # scenarios=[Scenario("lake-draft14/lake-edhoc-KEM","authIR_unique" ,[])] # for debug
    print("ReChecking %i scenarios with Tamarin" % (len(list(scenarios))))
    tamarin_results = init_result()
    load_results(tamarin_results, "tamarin")
    for prot in Protocols:
        for lemma in Lemmas:
            for key in tamarin_results[prot][lemma].keys():
                tam_res[prot][lemma][key]=tamarin_results[prot][lemma][key]


res = {}
for prot in Protocols:
    res[prot]={}
    for lemma in Lemmas:
        res[prot][lemma]={}
        for key in results[prot][lemma].keys():
            res[prot][lemma][key]=results[prot][lemma][key]

if args.compress:
    scenarios=[]         
    for prot in Protocols:
        for lemma in Lemmas:
            for threat in ThreatModels:
                scen=Scenario(prot,lemma,threat)
                try:
                    if scen.valid() and get_result(results,scen):
                        scenarios += [scen]
                except: None    
    comp = {}
    for prot in Protocols:
        comp[prot]={}
        for lemma in Lemmas:
            comp[prot][lemma]={}
    for scen in scenarios:
        if get_result(res,scen)[0]=="true" and not any([scen2 for scen2 in scenarios if get_result(res,scen2)[0]=="true" and is_weaker_scenario(scen,scen2)=="true" and str(scen)!=str(scen2)]):
            set_result(comp,scen, get_result(res,scen))
        if get_result(res,scen)[0]=="false" and all([get_result(res,scen2)[0]!="false" or is_weaker_scenario(scen2,scen)!="true" or str(scen)==str(scen2) for scen2 in scenarios]):
            set_result(comp,scen, get_result(res,scen))
        if get_result(res,scen)[0]!="true" and all([get_result(res,scen2)[0]!="true" or is_weaker_scenario(scen,scen2)!="true" or str(scen)==str(scen2) for scen2 in scenarios]) and get_result(res,scen)[0]!="false" and all([get_result(res,scen2)[0]!="false" or is_weaker_scenario(scen2,scen)!="true" or str(scen)==str(scen2) for scen2 in scenarios]):
            set_result(comp,scen,get_result(res,scen))
else:
    comp = res

                
if args.filesave:
    f = open(args.filesave[0], "w")
    f.write(json.dumps(comp, indent=4))
    f.close()            
else:
    print(json.dumps(comp, indent=4))    

                
if args.filesavetamarin:
    f = open(args.filesavetamarin[0], "w")
    f.write(json.dumps(tam_res, indent=4))
    f.close()              
    
if args.outputlatex:
    filename = args.outputlatex
else:
    filename = "-".join(Protocols) + "-".join(Lemmas)+".tex"

if args.latex:
    gen_tex(comp, tam_res, filename)


# TEsts

# scen1=Scenario("lake-draft14/lake-edhoc-KEM","data_authentication_R_to_I" ,"WeakAEAD".split("*"))
# scen2=Scenario("lake-draft14/lake-edhoc-KEM","data_authentication_R_to_I" ,"XorPrecise*LeakShare".split("*"))
# print(is_weaker_scenario(scen1,scen2))
