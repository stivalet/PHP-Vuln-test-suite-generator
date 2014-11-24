#parser XML
import xml.etree.ElementTree as ET
import os
import sys
import time
import getopt
from XSS_Generation.generatorXSS import *

def main(argv) :
    #List of flaws
    flaws = ["XSS","AC","IDOR","Injection","BASV"]
    global select = 1
    global ordered = False
    
    generation = []
    
    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv,"f:r:o",["flaws=","relevancy=","order"])
    except getopt.GetoptError:
        print ('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"): #Generate files only with a relevancy better than given
            select = int(arg)
        elif opt in ("-o", "--order") : #Option allowing separate safe and unsafe samples
            ordered = True
        elif opt in ("-f", "--flaws") : #Selecting flaws to create
            generation = arg.split(',')

    for flaw in generation :
        if flaw not in flaws :
            usage()
            return 1

    for flaw in generation :
        print("Generation of",flaw,"flaw")
        generateFlaw(flaw,select,ordered)

def generateFlaw(kind, relevancy, order) :
    #Constants
    safe = "safe"
    unsafe = "unsafe"
    needQuote = "needQuote"
    quote = "quote"
    noQuote = "noQuote"
    integer = "int"
    
    setRelevancy(relevancy)
    setOrder(order)


    #Gets initialSample samples
    tree_construction = ET.parse(str("kind")+'samples/construction.xml').getroot()
    tree_input = ET.parse(str("kind")+'samples/input.xml').getroot()
    tree_sanitize = ET.parse(str("kind")+'samples/sanitize.xml').getroot()


    #Table to store samples to combine
    tab_construction = []
    tab_input = []
    tab_sanitize = []

    #Manifest initialization
    manifest = Manifest(kind)

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

    safe = FinalSample.safe_Sample
    unsafe = FinalSample.unsafe_Sample
    print(str(safe) + " safe sample ( " + str(safe / (safe + unsafe)) + " )"  )
    print(str(unsafe) + " unsafe sample ( " + str(unsafe / (safe + unsafe)) + " )")
    print(str(unsafe + safe) + "total" )

def usage() :
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecur Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)"
    print("Wrong parameters : \n   ",order,"\n   ",relevancy,"\n   ",flaw)

if __name__ == "__main__":
   main(sys.argv[1:])
 
