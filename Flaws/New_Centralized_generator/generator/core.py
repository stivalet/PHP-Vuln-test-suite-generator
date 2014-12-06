import os
import xml.etree.ElementTree as ET
import sys
import getopt
import Flaws_generator

def main(argv) :
    #List of flaws
    flaws = ["XSS","AC","IDOR","Injection","BASV"]
    #Generation of files with a relevancy greater or equals to select
    global select = 0
    global ordered = False

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

    manifest = Manifest()
    fileManager = FileManager()

    for flaw in generation
        if flaw == "XSS" :
            xssGen = GeneratorXSS(manifest,fileManager,select,ordered)
            xssGen.generate()
        if flaw == "Injection" :
            xssInj = GeneratorInjection(manifest,fileManager,select,ordered)
            xssInj.generate()

    
def usage() :
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecur Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)"
    print("Wrong parameters : \n   ",order,"\n   ",relevancy,"\n   ",flaw)
