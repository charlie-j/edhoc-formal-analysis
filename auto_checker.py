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

Protocols = ["lake-draft12/lake-edhoc", "lake-draft12/lake-edhoc-KEM", "lake-draft14/lake-edhoc", "lake-draft14/lake-edhoc-KEM"]

# Our list of target lemmas
Lemmas = [ "no_reflection_attacks_RI", "authIR_unique", "data_authentication_I_to_R", "data_authentication_R_to_I", "honestauthRI_non_inj", "secretI", "secretR"]

# The list of Attacker Capabilities or Features we are going to look at.
AtomThreatModel= ["PreciseSignature", "PreciseSignatureProof", "LeakSessionKey", "WeakAEAD", "XorPrecise", "LeakShare", "PreciseDH", "CredCheck", "NeutralCheck"]
ThreatModels=list(powerset(AtomThreatModel))

Features = ["CredCheck", "NeutralCheck"]

    

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


def print_res(data,prot,lemma,res_for_prot,index):
    try:
        scenario=res_for_prot[prot][index]
        res=data[prot][lemma][scenario]
        if "true" in res: 
            string_res= "\\okp{%s}" % int(res[1])
        elif "false" in res:
            string_res= "\\attp{%s}" % int(res[1])
        scenarios = scenario.split("*")
        return u""" &  \\begin{tabular}{c} 
        \\small \\"""+  ', \\'.join(scenarios) + """ \\\\ """ +  string_res + """\\end{tabular}"""   
    except IndexError:
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
    

def gen_tex(data, filename):
    """Generates the tex array for the given list of protocols"""
    # need to escape \t, \n, \b \a
    tex_template =  u"""\documentclass[compsoc, conference, letterpaper, 10pt, times, table]{standalone}

\\usepackage[svgnames,dvipsnames]{xcolor}
\\usepackage{pifont}
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
\\newcommand{\\attd}[1]{\\attack$^D$~(#1)}
\\newcommand{\\attdnt}{\\attack$^D$}

\\newcommand{\\okp}[1]{\\ok$^P$~(#1)}
\\newcommand{\\okpnt}{\\ok$^P$}
\\newcommand{\\okt}[1]{\\ok$^T$~(#1)}
\\newcommand{\\oktnt}{\\ok$^T$}
\\newcommand{\\okd}[1]{\\ok$^D$~(#1)}
\\newcommand{\\okdnt}{\\ok$^D$}

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

 \\begin{NiceTabular} {c """ + " ".join([ "c" for p in Protocols]) + """ }
   \\CodeBefore
    \\rowlistcolors{2}{Gray!15,White}[restart,cols={2-""" + str(1+len(Protocols)) + """}]
    \\Body
    \\bf Lemma  """ + "".join([ (" & \\bf %s " % prot) for prot in Protocols])  + """  \\\\ \\hline

  

"""

    for lemma in Lemmas:
        tex_template += """
\\""" + lemmas_to_tex[lemma]
        res_for_prot = {}
        for prot in Protocols:
            res_for_prot[prot] = [scen for scen in data[prot][lemma].keys() if data[prot][lemma][scen][0] in ["true","false"]]
        maxrange=max([len(res_for_prot[prot]) for prot in Protocols])
        for i in range(0,maxrange):
            for prot in Protocols:                      
                tex_template +=  print_res(data,prot,lemma,res_for_prot,i)
            tex_template += """  \\\\ """
        tex_template += """  \\hline """                      
            

    tex_template += """\\end{NiceTabular} \\end{document} """
    with open(filename, 'w') as res_file:
        res_file.write(tex_template)


# utility functions to merge dictionnaries
def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

# base function which calls the subscript computing the results
def call_proverif(scen):
    cmd = "./utilities/proverif-tamarin %s" % (FOLDER + scen.tamarin_args())
    print(cmd)
    inittime = time.time()    
    process = subprocess.Popen(cmd.split(),cwd=os.path.dirname(os.path.realpath(__file__)),stderr=subprocess.STDOUT,stdout=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        output, errors = process.communicate(timeout=TIMEOUT)

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
        
def load_result_scenario(results,scenario):
    try:
        get_result(results,scenario)
    except: # when the result does not exists
        res =  call_proverif(scenario)
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

def load_results(results):    
    pool = Pool(processes=JOBS)
    res = pool.map(partial(load_result_scenario,results), scenarios, chunksize=1)
    pool.close()


    
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
parser.add_argument('-c','--compress', help='Compress the results',  action='store_true')
parser.add_argument('-rt','--retry', action="store_true",  help='For timeout jobs, retry to prove them')
parser.add_argument('-lt','--latex', action="store_true", help='Save results into a latex file')
parser.add_argument('-olt','--outputlatex', help='Latex file name')
parser.add_argument('-fs','--filesave', nargs='+', help='Save results into file')
parser.add_argument('-fl','--fileload', nargs='+', help='Load results from file')
parser.add_argument('-t','--timeout', type=int, help='Timeout for proverif execution')
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
    load_results(results)

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
    load_results(results)
    
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

    
if args.outputlatex:
    filename = args.outputlatex
else:
    filename = "-".join(Protocols) + "-".join(Lemmas)+".tex"

if args.latex:
    gen_tex(comp, filename)
