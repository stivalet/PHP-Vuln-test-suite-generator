import xml.etree.ElementTree as ET
from .Generator_Abstract_Class import *

from .InitializeSample import *
from Classes.File import *


header = open("./rights.txt", "r")
copyright = header.readlines()


class GeneratorXSS(Generator):
    def __init__(self, manifest, fileManager, select, ordered):
        Generator.__init__(self, manifest, fileManager, select, ordered)

    def getType(self):
        return ["XSS"]

    def testSafety(self, flaw, sanitize):
        # TO improve

        #########################################################################
        # Special case (Order mater !!!!)
        #Universal safe sanitizing (Cast & co)
        #Ok in every case
        if sanitize.safe == 1:
            self.safe_Sample += 1
            return 1

        #TODO : replace by test on the format
        # 3 :Escaping (" -> \" ) with rule 3 can lead to XSS (HTML parser first... blablabla... Read the OWASP doc thx)
        if flaw.rule == 3 and sanitize.escape == 1:
            self.unsafe_Sample += 1
            return 0

        # 3 :Escape </script> tag needed (Rule 3)
        if flaw.scriptBlock == 1 and sanitize.scriptBlock != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 :Escape </style> tag needed (Rule 4)
        if flaw.styleBlock == 1 and sanitize.styleBlock != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 : URL must NOT start with "javascript" (but with http) (in CSS)
        if flaw.URL_CSS_context == 1 and sanitize.URL_CSS_context != 1:
            self.unsafe_Sample += 1
            return 0

        # 4 : property must NOT start with "expression" (in CSS)
        if flaw.property_CSS_context == 1 and sanitize.property_CSS_context != 1:
            self.unsafe_Sample += 1
            return 0

        #Universal unsafe file (Unsafe function & co)
        if flaw.unsafe == 1:
            self.unsafe_Sample += 1
            return 0

        #Simple quote escape is enough (Rule 2,3,4)
        if flaw.simpleQuote == 1 and sanitize.simpleQuote == 1:
            self.safe_Sample += 1
            return 1

        #Double quote escape is enough (Rule 2,3,4)
        if flaw.doubleQuote == 1 and sanitize.doubleQuote == 1:
            self.safe_Sample += 1
            return 1

        #########################################################################
        #General Case
        #Rule 1 : escape & < > " '     (and / ideally)
        if flaw.rule == 1 and sanitize.rule1 == 1:
            self.safe_Sample += 1
            return 1

        #Rule 2 : escape ASCII < 256 (format : &#xHH ) ideally
        #properly quoted attribute only need corresponding quote
        if flaw.rule == 2 and sanitize.rule2 == 1:
            self.safe_Sample += 1
            return 1

        #Rule 3 : escape ASCII < 256 (format : \xHH)
        #properly quoted attribute only need corresponding quote
        #</script> can still close a script block
        if flaw.rule == 3 and sanitize.rule3 == 1:
            self.safe_Sample += 1
            return 1

        #Rule 4 : escape ASCII < 256 (format : \HH)
        #properly quoted attribute only need corresponding quote
        # + escape </style>
        if flaw.rule == 4 and sanitize.rule4 == 1:
            self.safe_Sample += 1
            return 1

        #Rule 5 : escape ASCII < 256 (format : %HH)
        #TO double checked, and improve...
        if flaw.rule == 5 and sanitize.rule5 == 1:
            self.safe_Sample += 1
            return 1
        self.unsafe_Sample += 1
        return 0

    def findFlaw(self, fileName):  # Find if a line in the file start by //flaw
        sample = open(fileName, 'r')
        i = 0
        for line in sample.readlines():
            i += 1
            if line[:6] == "//flaw":
                break
        return i + 1

    # Generates final sample
    def generate(self, params):
        for param in params:
            if isinstance(param, InputSample):
                self.manifest.beginTestCase(param.inputType)
                break

        file = File()

        # test if the samples need to be generated
        relevancy=1
        for param in params:
            relevancy*=param.relevancy
            if(relevancy<self.select):
                return 0

        #retreve parameters for safety test
        safe=None
        for param in params:
            if isinstance(param, Flaws):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2)

        #Creates folder tree and sample files if they don't exists
        file.addPath("generation")
        file.addPath("XSS")

        #sort by safe/unsafe
        if self.ordered:
            file.addPath("safe" if safe else "unsafe")

        for param in params:
            for dir in param.path:
                if dir != params[-1].path[-1]:
                    file.addPath(dir)
                else:
                    file.setName(dir)

        #Adds comments
        file.addContent("<!-- \n"+("Safe sample\n" if safe else "Unsafe sample\n"))

        for param in params:
            file.addContent(param.comment+"\n")
        file.addContent("-->\n\n")

        #Writes copyright statement in the sample file
        for line in copyright:
            file.addContent(line)

        #Writes the code in the sample file
        file.addContent("\n\n")

        out=""
        tmp=""
        for param in params:
            if isinstance(param, Flaws):
                for line in open(param.code[0], "r").readlines():
                    tmp+=line
                out=tmp+out
                tmp=""
                for line in open(param.code[1], "r").readlines():
                    tmp+=line
            else:
                for line in param.code:
                    out+=line
        file.addContent(out+tmp)
        self.fileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
