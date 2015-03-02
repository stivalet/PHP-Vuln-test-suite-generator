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
class GeneratorInjection(Generator):
    # Initializes counters
    safe_Sample = 0
    unsafe_Sample = 0

    def getType(self):
        return ['CWE_89_Injection', 'CWE_91_Injection', 'CWE_90_Injection', 'CWE_78_Injection', 'CWE_95_Injection', 'CWE_98_Injection']

    def __init__(self, date, manifest, select, cwe):
        Generator.__init__(self, date, manifest, select, cwe)

    def testSafety(self, construction, sanitize, flaw):
        if sanitize.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1
        if construction.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1
        if sanitize.safeties[flaw]["needQuote"] == 1 and construction.safeties[flaw]["quote"] == 1:
            self.safe_Sample += 1
            return 1
        # case of pg_escape_literal
        if sanitize.safeties[flaw]["needQuote"] == -1 and construction.safeties[flaw]["safe"] == 0:
            self.safe_Sample += 1
            return 1

        self.unsafe_Sample += 1
        #print(sanitize.safe)
        #print(sanitize.comment)
        #print("\n")
        return 0


    def generate(self, params):
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        for value in set(param.flaws).intersection(param2.flaws):
                            if value == "CWE_91_Injection":
                                return self.generateWithType("CWE_91", params)
                            elif value == "CWE_90_Injection":
                                return self.generateWithType("CWE_90", params)
                            elif value == "CWE_89_Injection":
                                return self.generateWithType("CWE_89", params)
                            elif value == "CWE_78_Injection":
                                return self.generateWithType("CWE_78", params)
                            elif value == "CWE_95_Injection":
                                return self.generateWithType("CWE_95", params)
                            elif value == "CWE_98_Injection":
                                return self.generateWithType("CWE_98", params)

    # Generates final sample
    def generateWithType(self, injection, params):
        ok=0 if len(self.cwe)>0 else 1
        for c in self.cwe:
            var = re.findall("CWE_("+c+")$", injection, re.I)
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
        for param in params:
            if (isinstance(param, Sanitize) and param.constraintType != ""):
                for param2 in params:
                    if (isinstance(param2, Construction) and (param.constraintType != param2.constraintType)):
                        return
            if (isinstance(param, Sanitize) and param.constraintField != ""):
                for param2 in params:
                    if (isinstance(param2, Construction) and (param.constraintField != param2.constraintField)):
                        return

        # retreve parameters for safety test
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2, injection + "_Injection")

        flawCwe = {"CWE_78": "OSCommand",
                   "CWE_91": "XPath",
                   "CWE_90": "LDAP",
                   "CWE_89": "SQL",
                   "CWE_95": "eval",
                   "CWE_98": "include_require"
        }

        # Creates folder tree and sample files if they don't exists
        file.addPath("generation_"+self.date)
        file.addPath("Injection")
        file.addPath(injection)

        # sort by safe/unsafe
        file.addPath("safe" if safe else "unsafe")

        name=injection
        for param in params:
            for dir in param.path:
                if dir != params[-1].path[-1]:
                    name+="["+dir+"]"
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

        if injection != "CWE_98":
            #Gets query execution code
            footer = open("./execQuery_" + flawCwe[injection] + ".txt", "r")
            execQuery = footer.readlines()
            footer.close()

            #Adds the code for query execution
            for line in execQuery:
                file.addContent(line)

        file.addContent("\n\n?>")

        FileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        #if safe:
        #    self.safe_Sample += 1
        #else:
        #    self.unsafe_Sample += 1

        for param in params:
            if isinstance(param, InputSample):
                self.manifest.beginTestCase(param.inputType)
                break

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
        return file
