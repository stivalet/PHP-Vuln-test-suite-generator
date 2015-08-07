import re
import shutil
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
needUrlSafe = "needUrlSafe"
urlSafe = "urlSafe"


# Manages final samples, by a combination of 3 initialSample
class GeneratorURF(Generator):
    def __init__(self, date, select):
        super(GeneratorURF, self).__init__(date, select, "URF")

    def getType(self):
        return ['CWE_601_URF']

    def testSafety(self, construction, sanitize, flaw):
        if construction.safeties[flaw]["needUrlSafe"] == 1:
            if sanitize.safeties[flaw]["urlSafe"] == 1:
                self.safe_Sample += 1
                return 1

        else :
            if sanitize.safeties[flaw]["urlSafe"] == 1:
                self.safe_Sample += 1
                return 1
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
        return 0


    def generate(self, params):
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        for value in set(param.flaws).intersection(param2.flaws):
                            if value == "CWE_601_URF":
                                return self.generateWithType("CWE_601", params)

    # Generates final sample
    def generateWithType(self, urf, params):
        file = File()

        # test if the samples need to be generated
        if self.revelancyTest(params) == 0:
            return None

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
                        safe = self.testSafety(param, param2, urf + "_URF")

        flawCwe = {"CWE_601": "Open_Redirect"
        }

        # Creates folder tree and sample files if they don't exists
        file.addPath("PHPTestSuite_"+self.date)
        file.addPath("URF")
        file.addPath(urf)

        # sort by safe/unsafe
        file.addPath("safe" if safe else "unsafe")

        file.setName(self.generateFileName(params, urf))

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
            if not safe and isinstance(param, Construction) :
                file.addContent("//flaw\n") #add this comment if not safe
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

        for param in params:
            if isinstance(param, InputSample):
                self.manifest.beginTestCase(param.inputType)
                break

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
        return file

    def __del__(self):
        self.onDestroy("URF")
