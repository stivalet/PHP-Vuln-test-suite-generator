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
    
    generation = []

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv,"f:r:o",["flaws=","relevancy=","order"])
    except getopt.GetoptError:
        print ('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"): #Generate files only with a relevancy better than given
            setRelevancy(arg)
        elif opt in ("-o", "--order") : #Option allowing separate safe and unsafe samples
            setOrder(arg)
        elif opt in ("-f", "--flaws") : #Selecting flaws to create
            generation = arg.split(',')

    for flaw in generation :
        if flaw not in flaws :
            usage()
            return 1

    for flaw in generation :
        if flaw == "XSS" :
            print("Generation of XSS")
        elif flaw == "AC" :
            print("Generation of AC")
        elif flaw == "IDOR" :
            print("Generation of IDOR")
        elif flaw == "Injection" :
            print("Generation of Injection")
        elif flaw == "BASV" :
            print("Generation of BASV")
        else :
            usage()
            return 1
                    
def usage() :
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecur Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)"
    print("Wrong parameters : \n   ",order,"\n   ",relevancy,"\n   ",flaw)

if __name__ == "__main__":
   main(sys.argv[1:])
 
