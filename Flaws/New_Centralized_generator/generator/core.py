import os
import xml.etree.ElementTree as ET
import sys
import getopt
from Flaws_generators.InitializeSample import *
from Flaws_generators.Injection_Generator import *
from Flaws_generators.XSS_Generator import *
from Classes.File import *
from Classes.FileManager import *
from Classes.Manifest import *

def main(argv) :
    #List of flaws
    flaws = ["XSS","AC","IDOR","Injection","BASV"]
    #Generation of files with a relevancy greater or equals to select
    global select
    select=0
    global ordered
    ordered=False

    generation = []

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv,"f:r:o:h",["flaws=","relevancy=","order","help"])
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
        elif opt in ("-h", "--help") : #Show usage
            usage()
            return 0

    for flaw in generation :
        if flaw not in flaws :
            usage()
            return 1

    fileManager = FileManager()

    for flaw in generation:
        if flaw == "XSS" :
            manifest = Manifest(flaw)
            xssGen = GeneratorXSS(manifest,fileManager,select,ordered)
            xssGen.generate()
            safe=xssGen.safe_Sample
            unsafe=xssGen.unsafe_Sample
            print("XSS generation report:")
            print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe)) + " )"  )
            print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe)) + " )")
            print(str(unsafe + safe) + " total\n" )
        if flaw == "Injection" :
            manifest = Manifest(flaw)
            xssInj = GeneratorInjection(manifest,fileManager,select,ordered)
            xssInj.generate()
            safe=xssInj.safe_Sample
            unsafe=xssInj.unsafe_Sample
            print("Injection generation report:")
            print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe)) + " )"  )
            print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe)) + " )")
            print(str(unsafe + safe) + " total\n" )

    
def usage() :
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecur Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)"
    print("Wrong parameters : \n   ",order,"\n   ",relevancy,"\n   ",flaw)

if __name__ == "__main__":
   main(sys.argv[1:])
