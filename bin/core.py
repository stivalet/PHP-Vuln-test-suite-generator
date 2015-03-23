from Classes.Manifest import *
from Flaws_generators.Generator_factory import *
from Flaws_generators.Generation_functions import *
import global_variables as g


def main(argv):
    # List of flaws
    flaws = ["XSS", "AC", "IDOR", "Injection", "BASV", "URF", "SM", "SDE"]

    #Generation of files with a relevancy greater or equals to select
    select = 0

    generation = []
    rang = 0

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv, "c:f:r:h", ["cwe=", "flaws=", "relevancy=", "help"])
    except getopt.GetoptError:
        print('Invalid argument')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-f", "--flaws") and rang == 0:  #Selecting flaws to create
            generation = arg.split(',')
            rang = 1
        elif opt in ("-c", "--cwe") and rang == 0:
            g.cwe_list = arg.split(',')
            rang = 1
        elif opt in ("-h", "--help"):  #Show usage
            usage()
            return 0

    for flaw in generation:
        if flaw not in flaws:
            usage()
            return 1

    date = time.strftime("%m-%d-%Y_%Hh%Mm%S")
    root = ET.parse('output.xml').getroot()

    if len(generation) == 0 or len(g.cwe_list) > 0:
        generation=flaws
    for flaw in generation:
        if flaw == "XSS":
            initialization(Generator_factory.makeXSS_Generator(date, select), root)
        if flaw == "Injection":
            initialization(Generator_factory.makeInjection_Generator(date, select), root)
        if flaw == "IDOR":
            initialization(Generator_factory.makeIDOR_Generator(date, select), root)
        if flaw == "URF":
            initialization(Generator_factory.makeURF_Generator(date, select), root)
        if flaw == "SM":
            for input in root.findall('input'):
                root.remove(input)
            initialization(Generator_factory.makeSM_Generator(date, select), root)
        if flaw == "SDE":
            for input in root.findall('input'):
                root.remove(input)
            initialization(Generator_factory.makeSDE_Generator(date, select), root)

def usage():
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n      XSS       : Cross-site Scripting\n      IDOR      : Insecure Direct Object Reference\n      Injection : Injection (SQL,LDAP,XPATH)\n      URF : URL Redirects and Forwards\n      SM : Security Misconfiguration\n      SDE : Sensitive Data Exposure"
    cweparam = "-c generate particular CWE"
    print("Wrong parameters :\n   ", flaw, "\n   ", cweparam)


if __name__ == "__main__":
    main(sys.argv[1:])
