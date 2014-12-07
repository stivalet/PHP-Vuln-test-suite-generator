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
    prepared = "prepared"
    noPrepared = "noPrepared"
    block = "block"
    noBlock = "noBlock"

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv,"r:o",["relevancy=", "order"])
    except getopt.GetoptError:
        print ('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"):
            setRelevancy(arg)
        elif opt in ("-o", "--order") :
            setOrder(1)

    #Gets initialSample samples
    tree_construction = ET.parse('samples/construction.xml').getroot()
    tree_input = ET.parse('samples/input.xml').getroot()
    tree_sanitize = ET.parse('samples/sanitize.xml').getroot()

    #Table to store samples to combine
    tab_construction = []
    tab_input = []
    tab_sanitize = []

    #Manifest initialization
    manifest = Manifest()

    for sanitize in tree_sanitize:
        tab_sanitize.append(Sanitize(sanitize))

    for construct in tree_construction:
        tab_construction.append(Construction(construct))

    for inputt in tree_input:
        tab_input.append(InputSample(inputt))


    #Exhaustive array-loop of the three tables
    for construct in tab_construction :
        for Input in tab_input :
            manifest.beginTestCase(Input.inputType)
            for sanitize in tab_sanitize :
                sample = FinalSample(construct, Input, sanitize)
                path = sample.generate(manifest)
            manifest.endTestCase()
    manifest.close()

    safe = FinalSample.safe_Sample ;
    unsafe = FinalSample.unsafe_Sample
    print(str(safe) + " safe sample ( " + str(safe / (safe + unsafe)) + " )"  )
    print(str(unsafe) + " unsafe sample ( " + str(unsafe / (safe + unsafe)) + " )")
    print(str(unsafe + safe) + "total" )

if __name__ == "__main__":
   main(sys.argv[1:])
