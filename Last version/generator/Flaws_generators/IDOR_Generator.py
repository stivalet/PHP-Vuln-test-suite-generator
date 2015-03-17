import re
import shutil

from .Generator_Abstract_Class import *
from .InitializeSample import *
from Classes.File import *
from Classes.FileManager import *

# Manages final samples, by a combination of 3 initialSample
class GeneratorIDOR(Generator):
    def __init__(self, date, select):
        super(GeneratorIDOR, self).__init__(date, select, "IDOR")

    def getType(self):
        return ["CWE_862_SQL_IDOR", "CWE_862_XPath_IDOR", "CWE_862_Fopen_IDOR"]

    def testSafety(self, construction, sanitize, flaw):
        if sanitize.safeties[flaw]["safe"] == 1 or construction.safeties[flaw]["safe"] == 1:
            self.safe_Sample += 1
            return 1
        self.unsafe_Sample += 1
        return 0

    # def testIsBlock(self) :
    # if self.sanitize.isBlock == block :
    # return 1
    # return 0

    def generate(self, params):
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        for value in set(param.flaws).intersection(param2.flaws):
                            if value == "CWE_862_SQL_IDOR":
                                return self.generateWithType("CWE_862_SQL", params)
                            elif value == "CWE_862_Fopen_IDOR":
                                return self.generateWithType("CWE_862_Fopen", params)
                            elif value == "CWE_862_XPath_IDOR":
                                return self.generateWithType("CWE_862_XPath", params)

    # Generates final sample
    def generateWithType(self, IDOR, params):
        file = File()

        # test if the samples need to be generated
        if self.revelancyTest(params) == 0:
            return None

        #Build constraints
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2, IDOR + "_IDOR")  # 1 : safe ,0 : unsafe

        flawCwe = {"CWE_862_SQL": "SQL",
                   "CWE_862_Fopen": "fopen",
                   "CWE_862_XPath": "XPath"
        }

        #Creates folder tree and sample files if they don't exists
        file.addPath("generation_"+self.date)
        file.addPath("IDOR")
        file.addPath(IDOR)

        #sort by safe/unsafe
        file.addPath("safe" if safe else "unsafe")

        file.setName(self.generateFileName(params, IDOR))

        file.addContent("<?php\n")
        file.addContent("/*\n")

        #Adds comments
        file.addContent("/* \n" + ("Safe sample\n" if safe else "Unsafe sample\n"))

        for param in params:
            file.addContent(param.comment + "\n")
        file.addContent("*/\n\n")

        # Gets copyright header from file
        header = open("./rights_PHP.txt", "r")
        copyright = header.readlines()
        header.close()

        #Writes copyright statement in the sample file
        file.addContent("\n\n")
        for line in copyright:
            file.addContent(line)

        #Writes the code in the sample file
        file.addContent("\n\n")
        for param in params:
            for line in param.code:
                file.addContent(line)
            file.addContent("\n\n")

        if flawCwe[IDOR] != "fopen":
            for param in params:
                if isinstance(param, Construction):
                    if param.prepared == 0 or flawCwe[IDOR] == "XPath":
                        fileQuery = open("./execQuery_" + flawCwe[IDOR] + ".txt", "r")
                        execQuery = fileQuery.readlines()
                        fileQuery.close()
                        for line in execQuery:
                            file.addContent(line)
                    else:
                        fileQuery = open("./execQuery_" + flawCwe[IDOR] + "_prepared.txt", "r")
                        execQueryPrepared = fileQuery.readlines()
                        fileQuery.close()
                        for line in execQueryPrepared:
                            file.addContent(line)

        file.addContent("\n ?>")
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
        self.onDestroy("IDOR")