import os

from .Generator_Abstract_Class import *
from .InitializeSample import *
from Classes.File import *

select = 0
order = 0
safety = "safety"

#Constants
safe = "safe"
unsafe = "unsafe"

#Gets copyright header from file
header = open("./rights.txt", "r")
copyright = header.readlines()
header.close()

def setRelevancy(R) :
   global select
   select = int(R)

def setOrder(O) :
   if O==1 :
      global order
      order = safety


#Manages final samples, by a combination of 3 initialSample
class GeneratorIDOR(Generator) :

    ##Initializes counters
    #safe_Sample = 0
    #unsafe_Sample = 0

    def __init__(self, manifest, fileManager, select, ordered):
        Generator.__init__(self, manifest, fileManager, select, ordered)

    #def __init__(self, manifest, fileManager, select, ordered):
    #    self.select = select
    #    self.ordered = ordered
    #    self.manifest = manifest
    #    self.fileManager = fileManager

    def getType(self):
        return ['SQL_IDOR', 'XPath_IDOR', 'Fopen']

    def testSafety(self) :
        if self.sanitize.isSafe == safe or self.construct.isSafe == safe :
            self.safe_Sample +=1
            return 1

        self.unsafe_Sample +=1
        return 0

    def findFlaw(self, fileName) :
       sample = open(fileName, 'r')
       i = 0
       for line in sample.readlines() :
          i += 1
          if line[:6] == "//flaw" :
             break
       return i + 1
	   
	#def testIsBlock(self) :
    #    if self.sanitize.isBlock == block :
    #        return 1
    #    return 0

    def testIsPrepared(self) :
        if self.construct.isPrepared == prepared :
          return 1
        return 0

	def generate(self):
        self.generateWithType("fopen")
        self.generateWithType("SQL")
        self.generateWithType("XPath")
        self.manifest.close()   
	   
    #Generates final sample
    def generateWithType(self, IDOR) :
        #Gets query execution code
        #2 types normal query and prepared query
        fileQuery = open("./execQuery_"+IDOR+ ".txt", "r")
        execQuery = fileQuery.readlines()
        fileQuery.close()
        
		for f in ET.parse(self.fileManager.getXML(IDOR + "_IDOR")).getroot():
            flaw = IDOR(f)
            for i in ET.parse(self.fileManager.getXML("input_IDOR")).getroot():
                Input = InputSample(i)
                self.manifest.beginTestCase(Input.inputType)
                for s in ET.parse(self.fileManager.getXML("sanitize_IDOR")).getroot():
                    sanitize = Sanitize_IDOR(s)

                    file = File()
					#test if the samples need to be generated
					input_R = Input.relevancy
					sanitize_R = sanitize.relevancy
					construct_R = flaw.relevancy

					#Relevancy test
					if(input_R * sanitize_R * construct_R < select) :
						continue
						
					#Build constraints
					safe = self.testSafety() #1 : safe ,0 : unsafe
					if IDOR=="SQL":
					    block = self.testIsBlock() #1 : block, 0 : noBlock
                        prepared = self.testIsPrepared() #1 : prepared, 0 : noPrepared

					#Creates folder tree and sample files if they don't exists
					file.addPath(generation)
					file.addPath("IDOR")
					file.addPath(IDOR)
					
					#sort by safe/unsafe
					if order == safety :
					   if safe :
						  path = path + "/safe"
					   else :
						  path = path + "/unsafe"

					for dir in self.construct.path :
						file.addPath(dir)

					for dir in self.input.path:
						file.addPath(dir)

					for i in range(len(self.sanitize.path)-1) :
						dir = self.sanitize.path[i]
						file.addPath(file)

					file.setName(sanitize.path[-1])

					#Adds comments
					file.addContent("un" if !safe + "safe sample")  

					sample.write("<?php \n")
					comment = ( "/*"
								   + commentSafe + "\n"
								   + self.construct.comment + "\n"
								   + self.input.comment + "\n"
								   + self.sanitize.comment
								   + " */")
					sample.write(comment)

					#Writes copyright statement in the sample file
					sample.write("\n\n")
					for line in copyright :
						sample.write(line)

					#Writes the code in the sample file
					sample.write("\n\n")

					code  = (self.input.code + "\n"
								 + self.sanitize.code + "\n"
								 + self.construct.code + "\n\n")
					sample.write(code)

					if IDOR=="XPath":
						for line in execQuery :
							 sample.write(line)

					sample.write("\n?>")
					sample.close()

					if safe :
						flawLine = 0
					else :
						flawLine = self.findFlaw(name)

					manifest.addFileToTestCase(name, flawLine)
