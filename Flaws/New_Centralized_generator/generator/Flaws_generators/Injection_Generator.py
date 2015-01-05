import os
import xml.etree.ElementTree as ET
import sys
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

# Gets copyright header from file
header = open("./rights_PHP.txt", "r")
copyright = header.readlines()
header.close()

# Manages final samples, by a combination of 3 initialSample
class GeneratorInjection:
    # Initializes counters
    safe_Sample = 0
    unsafe_Sample = 0

    def __init__(self, manifest, fileManager, select, ordered):
        self.select = select
        self.ordered = ordered
        self.manifest = manifest
        self.fileManager = fileManager

    def testSafety(self, sanitize, flaw):
        if sanitize.isSafe == safe:
            self.safe_Sample += 1
            return 1
        if flaw.isSafe == safe:
            self.safe_Sample += 1
            return 1
        if sanitize.isSafe == needQuote and flaw.isSafe == quote:
            self.safe_Sample += 1
            return 1
        # case of pg_escape_literal
        if sanitize.isSafe == noQuote and flaw.isSafe == 0:
            self.safe_Sample += 1
            return 1

        self.unsafe_Sample += 1
        return 0

    def findFlaw(self, fileName):
        sample = open(fileName, 'r')
        i = 0
        for line in sample.readlines():
            i += 1
            if line[:6] == "//flaw":
                break
        return i + 1

    def generate(self):
        self.generateWithType("LDAP")
        self.generateWithType("SQL")
        self.generateWithType("XPath")
        self.manifest.close()

    # Generates final sample
    def generateWithType(self, injection):
        #Gets query execution code
        footer = open("./execQuery_" + injection + ".txt", "r")
        execQuery = footer.readlines()
        footer.close()
        for f in ET.parse(self.fileManager.getXML(injection + "_injection")).getroot():
            flaw = Injection(f)
            for i in ET.parse(self.fileManager.getXML("input_injection")).getroot():
                Input = InputSample(i)
                self.manifest.beginTestCase(Input.inputType)
                for s in ET.parse(self.fileManager.getXML("sanitize_injection")).getroot():
                    sanitize = Sanitize_injection(s)

                    file = File()

                    # test if the samples need to be generated
                    input_R = Input.relevancy
                    sanitize_R = sanitize.relevancy
                    file_R = flaw.relevancy

                    #Relevancy test
                    if (input_R * sanitize_R * file_R < self.select):
                        return 0

                    #Coherence test
                    if ( sanitize.constraintType != ""
                         and sanitize.constraintType != flaw.constraintType ):
                        return 0

                    if ( sanitize.constraintField != ""
                         and sanitize.constraintField != flaw.constraintField ):
                        return 0

                    safe = self.testSafety(sanitize, flaw)


                    #Creates folder tree and sample files if they don't exists
                    file.addPath("generation")
                    file.addPath("Injection")
                    file.addPath(injection)

                    #sort by safe/unsafe
                    if self.ordered == True:
                        if safe:
                            file.addPath("safe")
                        else:
                            file.addPath("unsafe")

                    for dir in flaw.path:
                        file.addPath(dir)

                    for dir in Input.path:
                        file.addPath(dir)

                    for i in range(len(sanitize.path) - 1):
                        dir = sanitize.path[i]
                        file.addPath(dir)

                    file.setName(sanitize.path[-1])
                    file.addContent("<?php\n")
                    file.addContent("/*\n")

                    #Adds comments
                    if safe:
                        file.addContent("Safe sample")
                    else:
                        file.addContent("Unsafe sample")

                    file.addContent(flaw.comment + "\n" + Input.comment + "\n" + sanitize.comment + "\n" + " */")


                    #Writes copyright statement in the sample file
                    file.addContent("\n\n")
                    for line in copyright:
                        file.addContent(line)

                    #Writes the code in the sample file
                    file.addContent("\n\n")
                    file.addContent(Input.code + "\n"
                                    + sanitize.code + "\n"
                                    + flaw.code + "\n\n")

                    #Adds the code for query execution
                    for line in execQuery:
                        file.addContent(line)

                    file.addContent("\n ?>")

                    self.fileManager.createFile(file)

                    if safe:
                        flawLine = 0
                    else:
                        flawLine = self.findFlaw(file.getPath() + "/" + file.getName())

                    self.manifest.addFileToTestCase(file.getPath() + "/" + file.getName(), flawLine)
                self.manifest.endTestCase()
