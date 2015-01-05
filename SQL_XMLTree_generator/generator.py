#parser XML
import xml.etree.ElementTree as ET
import os
import sys
import time
import getopt
import collections
from packages.InitialSample import *
from packages.FinalSample import *
from packages.Manifest import * 

def f_construction(root,i):
    tree_construction = ET.parse('samples/construction.xml').getroot()
    for construct in tree_construction:
        params[i]=Construction(construct)
        generation(root,i+1)

def f_sanitize(root,i):
    tree_sanitize = ET.parse('samples/sanitize.xml').getroot()
    for sanitize in tree_sanitize:
        params[i]=Sanitize(sanitize)
        generation(root,i+1)

def f_input(root,i):
    tree_input = ET.parse('samples/input.xml').getroot()
    for inputt in tree_input:
        params[i]=InputSample(inputt)
        manifest.beginTestCase(params[i].inputType)
        generation(root,i+1)
        manifest.endTestCase()

options={
    "construction":f_construction,
    "sanitize":f_sanitize,
    "input":f_input,
}

def initialization(root,i):
    global manifest
    manifest = Manifest()
    global params
    params=[None]*len(root)
    generation(root,i)
    manifest.close()


def generation(root,i):
    if(i<len(root)):
        options[root[i].tag](root,i)
    else:
        sample = FinalSample(params)
        path = sample.generate(manifest) 

def main(argv) :
    #Constants
    safe = "safe"
    unsafe = "unsafe"
    needQuote = "needQuote"
    quote = "quote"
    noQuote = "noQuote"
    integer = "int"

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv,"r:o",["relevancy=", "order="])
    except getopt.GetoptError:
        print ('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"):
            setRelevancy(arg)
        elif opt in ("-o", "--order") :
            setOrder()

    root=ET.parse('output.xml').getroot()
    initialization(root,0)
    for idx in params:
        print(idx)

    safe = FinalSample.safe_Sample ;
    unsafe = FinalSample.unsafe_Sample
    print(str(safe) + " safe sample ( " + str(safe / (safe + unsafe)) + " )"  )
    print(str(unsafe) + " unsafe sample ( " + str(unsafe / (safe + unsafe)) + " )")
    print(str(unsafe + safe) + "total" )

if __name__ == "__main__":
   main(sys.argv[1:])
 
