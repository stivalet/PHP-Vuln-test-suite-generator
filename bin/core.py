from Classes.Manifest import *
from Flaws_generators.Generator_factory import *
from Flaws_generators.Generation_functions import *
import global_variables as g


def main(argv):
    # List of flaws
    flaws = ["XSS", "IDOR", "Injection", "URF", "SM", "SDE"]

    generation = []
    rang = 0

    #Gets options & arguments
    try:
        opts, args = getopt.getopt(argv, "c:f:h", ["cwe=", "flaws=", "help"])
    except getopt.GetoptError:
        print('Invalid argument')
        usage()
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
            initialization(Generator_factory.makeXSS_Generator(date), root)
        if flaw == "Injection":
            initialization(Generator_factory.makeInjection_Generator(date), root)
        if flaw == "IDOR":
            initialization(Generator_factory.makeIDOR_Generator(date), root)
        if flaw == "URF":
            initialization(Generator_factory.makeURF_Generator(date), root)
        if flaw == "SM":
            for input in root.findall('input'):
                root.remove(input)
            initialization(Generator_factory.makeSM_Generator(date), root)
        if flaw == "SDE":
            for input in root.findall('input'):
                root.remove(input)
            initialization(Generator_factory.makeSDE_Generator(date), root)

def usage():
    flaw = "-f flaws to generate (flaw1,flaw2,flaw3,...):\n\tIDOR :\tInsecure Direct Object Reference\n\tInjection :\tInjection (SQL,LDAP,XPATH)\n\tSDE :\tSensitive Data Exposure\n\tSM :\tSecurity Misconfiguration\n\tURF :\tURL Redirects and Forwards\n\tXSS :\tCross-site Scripting"
    cweparam = "-c generate particular CWE:\n\t78 :\tCommand OS Injection\n\t79 :\tXSS\n\t89 :\tSQL Injection\n\t90 :\tLDAP Injection\n\t91 :\tXPath Injection\n\t95 :\tCode Injection\n\t98 :\tFile Injection\n\t209 :\tInformation Exposure Through an Error Message\n\t311 :\tMissing Encryption of Sensitive Data\n\t327 :\tUse of a Broken or Risky Cryptographic Algorithm\n\t601 :\tURL Redirection to Untrusted Site\n\t862 :\tInsecure Direct Object References"
    example = "$py core.py -f Injection \t// generate test cases with Injection flaws\n $py core.py -c 79 \t\t// generate test cases with cross site scripting." 
    print("usage: [-f flaw | -c cwe ] [arg]\nOptions and arguments:\n", flaw, "\n", cweparam,"\n",example )


if __name__ == "__main__":
    main(sys.argv[1:])
