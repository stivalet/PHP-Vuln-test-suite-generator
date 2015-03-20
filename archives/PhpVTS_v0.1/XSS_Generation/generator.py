#parser XML
import xml.etree.ElementTree as ET
import os
import sys
import time
import getopt
from packages.InitialSample import *
from packages.FinalSample import *
from packages.Manifest import * 

  
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
        opts, args = getopt.getopt(argv,"r:o",["relevancy=","order"])
    except getopt.GetoptError:
        print ('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"):
            setRelevancy(arg)
        elif opt in ("-o", "--order") :
            setOrder(arg)


    #Gets initialSample samples
    tree_file = ET.parse('samples/file.xml').getroot()
    tree_input = ET.parse('samples/input.xml').getroot()
    tree_sanitize = ET.parse('samples/sanitize.xml').getroot()


    #Table to store samples to combine
    tab_file = []
    tab_input = []
    tab_sanitize = []

    #Manifest initialization
    manifest = Manifest()

    for sanitize in tree_sanitize:
        tab_sanitize.append(Sanitize(sanitize))

    for file in tree_file:
        tab_file.append(File(file))

    for inputt in tree_input:
        tab_input.append(InputSample(inputt))


    #Exhaustive array-loop of the three tables
    for file in tab_file :
        for Input in tab_input :
            manifest.beginTestCase(Input.inputType)
            for sanitize in tab_sanitize :
                sample = FinalSample(file, Input, sanitize)
                path = sample.generate(manifest)            
            manifest.endTestCase()
    manifest.close()

    safe = FinalSample.safe_Sample 
    unsafe = FinalSample.unsafe_Sample
    print(str(safe) + " safe sample ( " + str(safe / (safe + unsafe)) + " )"  )
    print(str(unsafe) + " unsafe sample ( " + str(unsafe / (safe + unsafe)) + " )")
    print(str(unsafe + safe) + " total" )

if __name__ == "__main__":
   main(sys.argv[1:])
 
