import os

from .Generator_Abstract_Class import *
from .InitializeSample import *
from Classes.File import *

# Manages final samples, by a combination of 3 initialSample
class GeneratorIDOR(Generator):
    ##Initializes counters
    # safe_Sample = 0
    # unsafe_Sample = 0

    def __init__(self, manifest, fileManager, select, ordered):
        Generator.__init__(self, manifest, fileManager, select, ordered)

    # def __init__(self, manifest, fileManager, select, ordered):
    # self.select = select
    # self.ordered = ordered
    # self.manifest = manifest
    # self.fileManager = fileManager

    def getType(self):
        return ["SQL_IDOR", "XPath_IDOR", "Fopen_IDOR"]

    def testSafety(self, sanitize, construction):
        if sanitize.safe == safe or construction.safe == safe:
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
                            if value == "SQL_IDOR":
                                self.generateWithType("SQL", params)
                            elif value == "Fopen_IDOR":
                                self.generateWithType("fopen", params)
                            elif value == "XPath_IDOR":
                                self.generateWithType("XPath", params)

    # Generates final sample
    def generateWithType(self, IDOR, params):
        #Gets query execution code
        #2 types normal query and prepared query
        if IDOR != "fopen":
            fileQuery = open("./execQuery_" + IDOR + ".txt", "r")
            execQuery = fileQuery.readlines()
            fileQuery.close()

        execQueryPrepared = ""
        if IDOR == "SQL":
            fileQuery = open("./execQuery_" + IDOR + "_prepared.txt", "r")
            execQueryPrepared = fileQuery.readlines()
            fileQuery.close()

        for param in params:
            if isinstance(param, InputSample):
                self.manifest.beginTestCase(param.inputType)
                break

        file = File()

        # test if the samples need to be generated
        relevancy = 1
        for param in params:
            relevancy *= param.relevancy
            if (relevancy < self.select):
                return 0

        #Build constraints
        safe = None
        for param in params:
            if isinstance(param, Construction):
                for param2 in params:
                    if isinstance(param2, Sanitize):
                        safe = self.testSafety(param, param2)  # 1 : safe ,0 : unsafe


        #Creates folder tree and sample files if they don't exists
        file.addPath("generation")
        file.addPath("IDOR")
        file.addPath(IDOR)

        #sort by safe/unsafe
        if self.ordered:
            file.addPath("safe" if safe else "unsafe")

        for param in params:
            for dir in param.path:
                if dir != params[-1].path[-1]:
                    file.addPath(dir)
                else:
                    file.setName(dir)

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

        if IDOR in ["SQL", "XPath"]:
            for param in params:
                if (isinstance(param, Construction) and param.prepared == 0) or IDOR == "XPath":
                    for line in execQuery:
                        file.addContent(line)
                else:
                    fileQuery = open("./execQuery_" + IDOR + "_prepared.txt", "r")
                    execQueryPrepared = fileQuery.readlines()
                    fileQuery.close()
                    for line in execQueryPrepared:
                        file.addContent(line)

        file.addContent("\n ?>")
        self.fileManager.createFile(file)

        flawLine = 0 if safe else self.findFlaw(file.getPath() + "/" + file.getName())

        self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
        self.manifest.endTestCase()