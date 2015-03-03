import re
import xml.etree.ElementTree as ET
import sys
from Classes.FileManager import *
from .Generator_Abstract_Class import *
from .InitializeSample import *
from Classes.File import *

# Constants
safe = "safe"
unsafe = "unsafe"
needQuote = "needQuote"
quote = "quote"
noQuote = "noQuote"
integer = "int"
safety = "safety"


# Manages final samples, by a combination of 3 initialSample
class GeneratorSDE(Generator):
    # Initializes counters
    safe_Sample = 0
    unsafe_Sample = 0

    def getType(self):
        return ['CWE_311_SDE', 'CWE_327_SDE']

    def __init__(self, date, manifest, select, cwe):
        Generator.__init__(self, date, manifest, select, cwe)

    def testSafety(self, construction, sanitize, flaw):
        if sanitize.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1
        if construction.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1

        self.unsafe_Sample += 1
        return 0


    def generate(self, params):
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        for value in set(param.flaws).intersection(param2.flaws):
                            if value == "CWE_311_SDE":
                                return self.generateWithType("CWE_311", params)
                            if value == "CWE_327_SDE":
                                return self.generateWithType("CWE_327", params)

    # Generates final sample
    def generateWithType(self, sde, params):
        ok=0 if len(self.cwe)>0 else 1
        for c in self.cwe:
            var = re.findall("CWE_("+c+")$", sde, re.I)
            if len(var)>0:
                ok=1
        if ok==0:return None
        file = File()

        # test if the samples need to be generated
        relevancy = 1
        for param in params:
            relevancy *= param.relevancy
            if (relevancy < self.select):
                return

        # Coherence test
        #for param in params:
        #    if (isinstance(param, Sanitize) and param.constraintType != ""):
        #        for param2 in params:
        #            if (isinstance(param2, Construction) and (param.constraintType != param2.constraintType)):
        #                return
        #    if (isinstance(param, Sanitize) and param.constraintField != ""):
        #        for param2 in params:
        #            if (isinstance(param2, Construction) and (param.constraintField != param2.constraintField)):
        #                return

        # retreve parameters for safety test
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2, sde + "_SDE")

        flawCwe = {"CWE_311": "MESD",
                   "CWE_327": "UBRCA"
        }

        # Creates folder tree and sample files if they don't exists
        file.addPath("generation_"+self.date)
        file.addPath("SDE")
        file.addPath(sde)

        # sort by safe/unsafe
        file.addPath("safe" if safe else "unsafe")

        name=sde
        for param in params:
            name+="["
            for dir in param.path:
                name+="("+dir+")"
            name+="]"
        file.setName(name)

        file.addContent("<?php\n")
        #file.addContent("/*\n")

        # Adds comments
        file.addContent("/* \n" + ("Safe sample\n" if safe else "Unsafe sample\n"))

        for param in params:
            file.addContent(param.comment + "\n")
        file.addContent("*/\n\n")

        # Gets copyright header from file
        header = open("./rights_PHP.txt", "r")
        copyright = header.readlines()
        header.close()

        # Writes copyright statement in the sample file
        file.addContent("\n\n")
        for line in copyright:
            file.addContent(line)

        # Writes the code in the sample file
        file.addContent("\n\n")
        for param in params:
            for line in param.code:
                file.addContent(line)
            file.addContent("\n\n")

        #if injection != "eval" and injection != "include_require":
        #    #Gets query execution code
        #    footer = open("./execQuery_" + injection + ".txt", "r")
        #    execQuery = footer.readlines()
        #    footer.close()

        #    #Adds the code for query execution
        #    for line in execQuery:
        #        file.addContent(line)

        file.addContent("\n\n?>")

        FileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        #for param in params:
        #    if isinstance(param, InputSample):
        #        self.manifest.beginTestCase(param.inputType)
        #        break
        self.manifest.beginTestCase("Sensitive_data")

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
        return file

