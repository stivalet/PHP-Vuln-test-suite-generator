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
needErrorSafe = "needErrorSafe"
errorSafe = "errorSafe"

# Manages final samples, by a combination of 3 initialSample
class GeneratorSM(Generator):
    def __init__(self, date):
        super(GeneratorSM, self).__init__(date, "SM")

    def getType(self):
        return ['CWE_209_SM']

    def testSafety(self, construction, sanitize, flaw):
        if construction.safeties[flaw]["needErrorSafe"] == 1:
            if sanitize.safeties[flaw]["errorSafe"] == 1:
                self.safe_Sample += 1
                return 1

        else :
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
                            if value == "CWE_209_SM":
                                return self.generateWithType("CWE_209", params)

    # Generates final sample
    def generateWithType(self, sm, params):
        file = File()

        # retrieve parameters for safety test
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2, sm + "_SM")

        # Creates folder tree and sample files if they don't exists
        file.addPath("PHPTestSuite_"+self.date)
        file.addPath("SM")
        file.addPath(sm)

        # sort by safe/unsafe
        file.addPath("safe" if safe else "unsafe")

        file.setName(self.generateFileName(params, sm))

        file.addContent("<?php\n")

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

        file.addContent("\n\n?>")

        FileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        self.manifest.beginTestCase("Error_message")

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()
        return file

    def __del__(self):
        self.onDestroy("SM")
