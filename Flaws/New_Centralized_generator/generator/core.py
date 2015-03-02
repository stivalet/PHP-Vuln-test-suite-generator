from Flaws_generators.Injection_Generator import *
from Flaws_generators.XSS_Generator import *
import time
from Classes.FileManager import *
from Classes.Manifest import *
from Flaws_generators.Generator_factory import *
from Flaws_generators.Generation_functions import *


def main(argv):
    # List of flaws
    flaws = ["XSS", "AC", "IDOR", "Injection", "BASV", "URF", "SM", "SDE"]
    cwe = {"XSS":"",
           }
    #Generation of files with a relevancy greater or equals to select
    select = 0
    ordered = False

    generation = []
    CWElist = []
    rang = 0
    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv, "c:f:r:h", ["cwe=", "flaws=", "relevancy=", "help"])
    except getopt.GetoptError:
        print('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"):  #Generate files only with a relevancy better than given
            select = int(arg)
        elif opt in ("-f", "--flaws"):  #Selecting flaws to create
            generation = arg.split(',')
        elif opt in ("-c", "--cwe"):
            CWElist = arg.split(',')
        elif opt in ("-h", "--help"):  #Show usage
            usage()
            return 0

    for flaw in generation:
        if flaw not in flaws:
            usage()
            return 1

    date=time.strftime("%m-%d-%Y_%Hh%Mm%S")
    root=ET.parse('output.xml').getroot()

    if len(generation)>0 is not None or len(CWElist)>0 :
        if len(CWElist)>0: generation=flaws
        elif len(CWElist)>0: CWElist=['']
        for flaw in generation:
            if flaw == "XSS":
                print("XSS generation report:")
                manifest = Manifest(date,flaw)
                safe, unsafe = initialization(Generator_factory.makeXSS_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "Injection":
                print("Injection generation report:")
                manifest = Manifest(date,flaw)
                safe, unsafe = initialization(Generator_factory.makeInjection_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "IDOR":
                print("IDOR generation report:")
                manifest = Manifest(date,flaw)
                safe, unsafe = initialization(Generator_factory.makeIDOR_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )"  )
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "URF":
                print("URF generation report:")
                manifest = Manifest(date,flaw)
                safe, unsafe = initialization(Generator_factory.makeURF_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )"  )
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "SM":
                print("SM generation report:")
                manifest = Manifest(date,flaw)
                for input in root.findall('input'):
                    root.remove(input)
                safe, unsafe = initialization(Generator_factory.makeSM_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )"  )
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "SDE":
                print("SDE generation report:")
                manifest = Manifest(date,flaw)
                for input in root.findall('input'):
                    root.remove(input)
                safe, unsafe = initialization(Generator_factory.makeSDE_Generator(date, manifest, select, CWElist), root)
                manifest.close()
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )"  )
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe) if (safe + unsafe)>0 else 1) + " )")
                print(str(unsafe + safe) + " total\n")

def usage():
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecure Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)\n      URF : URL Redirects and Forwards\n      SM : Security Misconfiguration\n      SDE : Sensitive Data Exposure"
    print("Wrong parameters : \n   ", order, "\n   ", relevancy, "\n   ", flaw)


if __name__ == "__main__":
    main(sys.argv[1:])
