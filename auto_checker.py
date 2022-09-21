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

FOLDER = "lake-draft15/"

###############
## UTILITIES ##
###############


# def getManager():
#     m = BaseManager()
#     m.start()
#     return m

# class Data:
#     def __init__(self,data=None, length=0):
#         self.data = data
#         self.length = length

#     def get(self):
#         return self.data

#     def set(self,data):
#         self.data = data

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

Protocols = ["DH", "KEM"]

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
         elif self.prot=="KEM" and "PreciseDH" in threats:
             return False
     return True


  def filename(self):
    name = "lake-edhoc"
    if self.prot == "KEM":
        name += "-KEM"
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
        if (feature in scen1.threats and not feature in scen2.threats):
            return None
        if (feature in scen2.threats and not feature in scen1.threats):
            return None # incomparable 
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
    
# # We define a pretty printer for the scenarios, with tex templates
# scen_pprinter = {
# #    "AP_TLS_RO AP_TLS_RW" : "\maliom{u-tls}{\\rw}",

#     }

# list_scen_pprinter = list(scen_pprinter.keys())
# list_scen_pprinter.sort(key=lambda item: len(item))
# list_scen_pprinter.reverse()

# def gen_tex(dprots):
#     """Generates the tex array for the given list of protocols"""

#     tex_template = u"""\documentclass[compsoc, conference, letterpaper, 10pt, times, table, svgnames]{article}

# \\usepackage{xcolor}
# \\usepackage{pifont}
# \\usepackage{multicol}
# \\usepackage[paperwidth=20in, paperheight=40in]{geometry}
# \\newcommand{\cmark}{\\textcolor{Lime}{\ding{51}}}
# \\newcommand{\cannot}{?}
# \\newcommand{\\bigcmark}{\\textcolor{Lime}{\ding{52}}}
# \\newcommand{\\bluecmark}{\\textcolor{Blue}{\ding{51}}}
# \\newcommand{\\bigbluecmark}{\\textcolor{Blue}{\ding{52}}}
# \\newcommand{\greycmark}{\\textcolor{Grey}{\ding{51}}}
# \\newcommand{\\biggreycmark}{\\textcolor{Grey}{\ding{52}}}
# \\newcommand{\qmark}{\\textcolor{Grey}{\ding{51}}}
# \\newcommand{\\xmark}{\\textcolor{Red}{\ding{55}}}
# \\newcommand{\\bigxmark}{\\textcolor{Red}{\ding{54}}}
# \\newcommand{\greyxmark}{\\textcolor{Grey}{\ding{55}}}
# \\newcommand{\\biggreyxmark}{\\textcolor{Grey}{\ding{54}}}

# \\newcommand{\mal}{\mathcal{M}}
# \\newcommand{\\ro}{\mathcal{RO}}
# \\newcommand{\\rw}{\mathcal{RW}}
# \\newcommand{\chan}[1]{#1}
# \\newcommand{\mali}[2]{$\mal^{\chan{#1}}_{in:#2}$}
# \\newcommand{\malo}[2]{$\mal^{\chan{#1}}_{out:#2}$}
# \\newcommand{\malio}[3]{$\mal^{\chan{#1}}_{in:#2,out:#3}$}
# \\newcommand{\maliom}[2]{$\mal^{\chan{#1}}_{#2}$}

# \\begin{document}
# \\begin{figure}
# \\vspace{-2.5cm}
# \\begin{itemize}
# \item green tick = injectivity proven,  red cross = attack found, grey cross = cannot prove, \_ = scenario not pertinent
# \item First mark : No unwanted login with 2 Factor and 'I trust' unchecked
# \item Second mark : No unwanted login with 2 Factor and 'I trust' checked
# \item Third mark : No unwanted login through cookie
# \end{itemize}
# \\rowcolors{1}{LightSteelBlue!60}{}
# \\begin{tabular}{p{0.25cm}p{0.25cm}p{0.3cm}cc""" + "".join([ "c" for p in dprots]) + """}
# """

#     end_tex_template="""\end{tabular}
# \\begin{footnotesize}
# Protocols
# \\vspace{-.4cm}
# \\begin{multicols}{2}
# \\begin{itemize}
# \item g2V - Google 2 Step with Verification code
# \item g2VL - G2 V with code Linked to the TLS session
# \item g2VLD - G2 V with code Linked to the TLS session and display
# \item g2ST - Google 2 Step Single Tap
# \item g2STD - G2 ST with Fingerprint display
# \item g2STRD - G2 STD with a Random to compare
# \item FIDO - FIDO Yubikey protocol
# \item g2DTDE - g2DTD extension
# \end{itemize}
# \end{multicols}
# \\vspace{-.4cm}
# Scenarios:
# \\vspace{-.4cm}
# \\begin{multicols}{2}
# \\begin{itemize}
# \item NC - No Compare, the human does not compare values
# \item FS - Fingerprint spoof, the attacker can copy the user IP address
# \item WPH - The user might be victim of phishing only on trusted everyday connections
# \item SPH - The user might be victim of phishing even when doing an untrusted connection
# \item D\_I\_RO/D\_O\_RW/... - The phone inputs and inputs are controlled in Read Only or Read Write
# \item P\_... - Attacker control over the user PC, where the user wants to stay logged in.
# \item AP\_... - Attacker control over some untrusted device, where the user only want to login once.
# \item TLS\_RO\_RW... - The attacker controls the TLS connections, inputs or outputs
# \item USBI\_RO/USBO\_RW - Attacker control of the USB devices, inputs or outputs

# \end{itemize}
# \end{multicols}
# \end{footnotesize}


# \end{figure}
# \end{document}
# """

#     tex_template += """\multicolumn{4}{c}{Threat Scenarios} """
#     # we compute the set of pertinent scenarios and display the protocols
#     scens = set([])
#     for prot in dprots:
#         tex_template += """ & %s """ % prot
#         scens = scens | set(results[prot].keys())
#     tex_template += """\\\\
# """
#     scens = list(scens)
#     scens.sort(key=lambda item: (item != '', len(item)>=5, 'AP' in item, not('PH' in item), 'FS' in item, len(item)))
#     print(scens)
#     for scen in scens:
#         pp_scen = scen
#         for rw in (list_scen_pprinter):
#             pp_scen = pp_scen.replace(rw,scen_pprinter[rw])
#         pp_scen =  pp_scen.replace("_","\_").split(" ")
#         print(pp_scen)
#         if 'PH' in pp_scen:
#             tex_template += """ PH & """
#             pp_scen.remove("PH")
#         else:  
#             tex_template += """& """
#         if 'FS' in pp_scen:
#             tex_template += """ FS & """
#             pp_scen.remove("FS")
#         else:  
#             tex_template += """& """
#         if 'NC' in pp_scen:
#             tex_template += """ NC & """
#             pp_scen.remove("NC")
#         else:  
#             tex_template += """& """
#         print(pp_scen)
#         tex_template += " ".join(pp_scen)


#         for prot in dprots:
#             result = results[prot][scen]
#             tex_template += """& """
#             if result == "big_true_implied":
#                 tex_template += """\\biggreycmark """
#             elif result == "big_true":
#                 tex_template += """\\bigcmark """
#             elif result == "big_true_diff":
#                 tex_template += """\\bigbluecmark """
#             elif result == "big_false_implied":
#                 tex_template += """\\biggreyxmark """
#             elif result == "big_false":
#                 tex_template += """\\bigxmark """
#             else:
#                 for res in result:
#                     if "true_implied" in res:
#                         tex_template += """\greycmark """
#                     elif "true_diff" in res:
#                         tex_template += """\\bluecmark """
#                     elif "false_implied" in res:
#                         tex_template += """\greyxmark """
#                     elif "true" in res:
#                         tex_template += """\cmark """
#                     elif "false" in res:
#                         tex_template += """\\xmark """
#                     elif "cannot" in res:
#                         tex_template += """\cannot """
#                     elif "failure" in res:
#                         tex_template += """- """
#                     elif "noinjvalid" in res:
#                         tex_template += """\qmark """
#         tex_template += """\\\\
# """
#     tex_template += end_tex_template
#     filename = "-".join(dprots)+".tex"
#     with open(filename, 'w') as res_file:
#         res_file.write(tex_template)
#     subprocess.call(["pdflatex", filename],stdout=subprocess.PIPE)

# utility functions to merge dictionnaries
def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z

# base function which calls the subscript computing the results
def call_proverif(scen):
    cmd = "./utilities/proverif-tamarin %s" % (FOLDER + scen.tamarin_args())
    print(cmd)
    process = subprocess.Popen(cmd.split(),cwd=os.path.dirname(os.path.realpath(__file__)),stderr=subprocess.STDOUT,stdout=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        output, errors = process.communicate(timeout=TIMEOUT)

        proof_results = [line for line in str(output).split('\\n') if "RESULT" in line]
        if len(proof_results) != 1:
            print(output)
            return (cmd+"test"+" ".join(proof_results))
        res = proof_results[0]
        if "true" in res:
            return "true"
        elif "false" in res:
            return "false"
        elif "cannot" in res:
            return "cannot"
        return "unrecognized result"
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM) 
        return "timeout"
    
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
        if res == "true":
            for scen in scenarios:
                if scen != scenario and is_weaker_scenario(scen,scenario)=="true":
                    print("Protocol %s is %s for lemma %s in threat model %s ==> also for %s " % (scenario.prot, res, scenario.lemma, " ".join(scenario.threats),  " ".join(scen.threats)))                                
                    set_result(results,scen,"true")
        if res == "false":
            for scen in scenarios:
                if scen != scenario and is_weaker_scenario(scenario,scen)=="true":
                    print("Protocol %s is %s for lemma %s in threat model %s ==> also for %s " % (scenario.prot, res, scenario.lemma, " ".join(scenario.threats),  " ".join(scen.threats)))                                
                    set_result(results, scenario,"false")

def load_results(results):
    
    pool = Pool(processes=JOBS)
    res = pool.map(partial(load_result_scenario,results), scenarios, chunksize=1)
    pool.close()
    # for scen in scenarios:
    #     load_result_scenario(results,scen)

    
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
# parser.add_argument('-p','--prots', nargs='+', help='List of prots to test, all by default')
# parser.add_argument('-s','--scen', nargs='+', help='List of scenarios to test, all by default')
# parser.add_argument('-d','--disp', nargs='+', help='List of prots to display together')
parser.add_argument('-c','--compress', help='Compress the results',  action='store_true')
# parser.add_argument('-co','--componly', help='Only displays the line with a diff', action='store_true')
parser.add_argument('-rt','--retry', action="store_true",  help='For timeout jobs, retry to prove them')
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
    for prot in Protocols:
        for lemma in Lemmas:
            for threat in ThreatModels:
                scen=Scenario(prot,lemma,threat)
                try:
                    if scen.valid() and get_result(results,scen)!="true" and get_result(results,scen):
                        scenarios += [scen]
                except: None
    scenarios.sort(reverse=False,key=lambda x: len(x.threats))
    print("ReChecking %i scenarios" % (len(list(scenarios))))
    results = init_result()
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
        if get_result(res,scen)=="true" and not any([scen2 for scen2 in scenarios if get_result(res,scen2)=="true" and is_weaker_scenario(scen,scen2)=="true" and scen!=scen2]):
            set_result(comp,scen,"true")
        if get_result(res,scen)=="false" and all([get_result(res,scen2)!="false" or is_weaker_scenario(scen2,scen)!="true" or scen==scen2 for scen2 in scenarios]):
            set_result(comp,scen,"false")
        if get_result(res,scen)!="true" and all([get_result(res,scen2)!="true" or is_weaker_scenario(scen,scen2)!="true" or scen==scen2 for scen2 in scenarios]) and get_result(res,scen)!="false" and all([get_result(res,scen2)!="false" or is_weaker_scenario(scen2,scen)!="true" or scen==scen2 for scen2 in scenarios]):
            set_result(comp,scen,get_result(res,scen))
else:
    comp = res

                
if args.filesave:
    f = open(args.filesave[0], "w")
    f.write(json.dumps(comp, indent=4))
    f.close()            
else:
    print(json.dumps(comp, indent=4))    
