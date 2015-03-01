import xml.etree.ElementTree as ET
from .Generator_Abstract_Class import *
from Classes.FileManager import *
from .InitializeSample import *
from Classes.File import *


header = open("./rights.txt", "r")
copyright = header.readlines()


class GeneratorXSS(Generator):
    def __init__(self, date, manifest, select, ordered):
        Generator.__init__(self, date, manifest, select, ordered)
        self.z = 0

    def getType(self):
        return ["XSS"]

    def testSafety(self, construction, sanitize, flaw):
        # TO improve

        #########################################################################
        # Special case (Order mater !!!!)
        # Universal safe sanitizing (Cast & co)
        # Ok in every case
        if sanitize.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1

        # TODO : replace by test on the format
        # 3 :Escaping (" -> \" ) with rule 3 can lead to XSS (HTML parser first... blablabla... Read the OWASP doc thx)
        if construction.safeties[flaw]["rule"] == 3 and sanitize.safeties[flaw]["escape"] == 1:
            self.unsafe_Sample += 1
            return 0

        # 3 :Escape </script> tag needed (Rule 3)
        if construction.safeties[flaw]["scriptBlock"] == 1 and sanitize.safeties[flaw]["scriptBlock"] != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 :Escape </style> tag needed (Rule 4)
        if construction.safeties[flaw]["styleBlock"] == 1 and sanitize.safeties[flaw]["styleBlock"] != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 : URL must NOT start with "javascript" (but with http) (in CSS)
        if construction.safeties[flaw]["URL_CSS_context"] == 1 and sanitize.safeties[flaw]["URL_CSS_context"] != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 : property must NOT start with "expression" (in CSS)
        if construction.safeties[flaw]["property_CSS_context"] == 1 and sanitize.safeties[flaw]["property_CSS_context"] != 1:
            self.unsafe_Sample += 1
            return 0

        # Universal unsafe file (Unsafe function & co)
        if construction.safeties[flaw]["unsafe"] == 1:
            self.unsafe_Sample += 1
            return 0

        # Simple quote escape is enough (Rule 2,3,4)
        if construction.safeties[flaw]["simpleQuote"] == 1 and sanitize.safeties[flaw]["simpleQuote"] == 1:
            self.safe_Sample += 1
            return 1

        # Double quote escape is enough (Rule 2,3,4)
        if construction.safeties[flaw]["doubleQuote"] == 1 and sanitize.safeties[flaw]["doubleQuote"] == 1:
            self.safe_Sample += 1
            return 1

        #########################################################################
        # General Case
        # Rule 1 : escape & < > " '     (and / ideally)
        if construction.safeties[flaw]["rule"] == 1 and sanitize.safeties[flaw]["rule1"] == 1:
            self.safe_Sample += 1
            return 1

        # Rule 2 : escape ASCII < 256 (format : &#xHH ) ideally
        # properly quoted attribute only need corresponding quote
        if construction.safeties[flaw]["rule"] == 2 and sanitize.safeties[flaw]["rule2"] == 1:
            self.safe_Sample += 1
            return 1

        #Rule 3 : escape ASCII < 256 (format : \xHH)
        #properly quoted attribute only need corresponding quote
        #</script> can still close a script block
        if construction.safeties[flaw]["rule"] == 3 and sanitize.safeties[flaw]["rule3"] == 1:
            self.safe_Sample += 1
            return 1

        #Rule 4 : escape ASCII < 256 (format : \HH)
        #properly quoted attribute only need corresponding quote
        # + escape </style>
        if construction.safeties[flaw]["rule"] == 4 and sanitize.safeties[flaw]["rule4"] == 1:
            self.safe_Sample += 1
            return 1

        #Rule 5 : escape ASCII < 256 (format : %HH)
        #TO double checked, and improve...
        if construction.safeties[flaw]["rule"] == 5 and sanitize.safeties[flaw]["rule5"] == 1:
            self.safe_Sample += 1
            return 1
        self.unsafe_Sample += 1
        return 0

    # Generates final sample
    def generate(self, params):

        file = File()

        # test if the samples need to be generated
        relevancy = 1
        for param in params:
            relevancy *= param.relevancy
            if (relevancy < self.select):
                return 0

        # retrieve parameters for safety test
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2, "XSS")

        # Creates folder tree and sample files if they don't exists
        file.addPath("generation_"+self.date)
        file.addPath("XSS")
        file.addPath("CWE_79")

        # sort by safe/unsafe
        if self.ordered:
            file.addPath("safe" if safe else "unsafe")

        for param in params:
            for dir in param.path:
                if dir != params[-1].path[-1]:
                    file.addPath(dir)
                else:
                    file.setName(dir)

        # Adds comments
        file.addContent("<!-- \n" + ("Safe sample\n" if safe else "Unsafe sample\n"))

        for param in params:
            file.addContent(param.comment + "\n")
        file.addContent("-->\n\n")

        # Writes copyright statement in the sample file
        for line in copyright:
            file.addContent(line)

        # Writes the code in the sample file
        file.addContent("\n\n")

        out = ""
        tmp = ""
        for param in params:
            if isinstance(param, Construction):
                for line in open(param.code[0], "r").readlines():
                    tmp += line
                out = tmp + out
                tmp = ""
                for line in open(param.code[1], "r").readlines():
                    tmp += line
            else:
                for line in param.code:
                    out += line
        file.addContent(out + tmp)
        FileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        for param in params:
            if isinstance(param, InputSample):
                self.manifest.beginTestCase(param.inputType)
                break

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
        return file
