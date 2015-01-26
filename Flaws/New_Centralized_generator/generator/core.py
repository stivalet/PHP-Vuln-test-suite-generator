from Flaws_generators.Injection_Generator import *
from Flaws_generators.XSS_Generator import *
from Classes.FileManager import *
from Classes.Manifest import *
from Flaws_generators.Generator_factory import *
from Flaws_generators.Generation_functions import *


def main(argv):
    # List of flaws
    flaws = ["XSS", "AC", "IDOR", "Injection", "BASV"]
    cwe = {"XSS":"",
           }
    #Generation of files with a relevancy greater or equals to select
    global select
    select = 0
    global ordered
    ordered = False

    generation = []
    CWElist = []
    rang = 0
    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv, "f:r:o:h:cwe", ["flaws=", "relevancy=", "order", "help","commonweaknessenumeration="])
    except getopt.GetoptError:
        print('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-r", "--relevancy"):  #Generate files only with a relevancy better than given
            select = int(arg)
        elif opt in ("-o", "--order"):  #Option allowing separate safe and unsafe samples
            ordered = True
        elif (rang == 0 and (opt in ("-f", "--flaws"))):  #Selecting flaws to create
            rang = 1
            generation = arg.split(',')
        elif (rang == 0 and (opt in ("-cwe","--commonweaknessenumeration"))):
            rang = 1
            CWElist = arg.split(",")
        elif opt in ("-h", "--help"):  #Show usage
            usage()
            return 0

    for flaw in generation:
        if flaw not in flaws:
            usage()
            return 1

    fileManager = FileManager()
    generator = Generator_factory()
    root=ET.parse('output.xml').getroot()

    if generation != None :
        for flaw in generation:
            if flaw == "XSS":
                manifest = Manifest(flaw)
                [safe, unsafe] = initialization(generator.makeXSS_Generator(manifest, fileManager, select, ordered), root)
                manifest.close()
                print("XSS generation report:")
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe)) + " )")
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe)) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "Injection":
                manifest = Manifest(flaw)
                [safe, unsafe] = initialization(generator.makeInjection_Generator(manifest, fileManager, select, ordered), root)
                manifest.close()
                print("Injection generation report:")
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe)) + " )")
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe)) + " )")
                print(str(unsafe + safe) + " total\n")
            if flaw == "IDOR":
                manifest = Manifest(flaw)
                [safe, unsafe] = initialization(generator.makeIDOR_Generator(manifest, fileManager, select, ordered), root)
                manifest.close()
                print("IDOR generation report:")
                print(str(safe) + " safe samples ( " + str(safe / (safe + unsafe)) + " )"  )
                print(str(unsafe) + " unsafe samples ( " + str(unsafe / (safe + unsafe)) + " )")
                print(str(unsafe + safe) + " total\n")
    elif CWElist != None :
        pass



def usage():
    order = "-o for classifying vulnerable and non vulnerable programs in different folders"
    relevancy = "-r generate only files with upper or equal relevancy than the parameter"
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      AC        : Wrong access control\n      IDOR      : Insecur Direct Object Reference\n      BASV      : Broken Authentication and Session Violation\n      Injection : Injection (SQL,LDAP,XPATH)"
    print("Wrong parameters : \n   ", order, "\n   ", relevancy, "\n   ", flaw)


if __name__ == "__main__":
    main(sys.argv[1:])
