import os

#select = 0
#order = 0
#order = "safety"

#Constants
safe = "safe"
unsafe = "unsafe"
block = "block"
noBlock = "noBlock"
prepared = "prepared"
noPrepared = "noPrepared"


#Gets copyright header from file
header = open("./rights.txt", "r")
copyright = header.readlines()
header.close()

#Gets query execution code
fileNormalQuery = open("./execNormalQuery.txt", "r")
execNormalQuery = fileNormalQuery.readlines()
fileNormalQuery.close()

filePreparedQuery = open("./execPreparedQuery.txt", "r")
execPreparedQuery = filePreparedQuery.readlines()
filePreparedQuery.close()

#def setRelevancy(R) :
#   global select
#   select = int(R)

#def setOrder(O) :
#   if O==1 :
#      global order
#      order = safety


#Manages final samples, by a combination of 3 initialSample
class FinalSample :

    #Initializes counters
    safe_Sample = 0
    unsafe_Sample = 0

    def __init__(self, construct, Input, sanitize) :
        self.construct = construct
        self.input = Input
        self.sanitize = sanitize

    def testSafety(self) :
        if self.sanitize.isSafe == safe or self.construct.isSafe == safe :
            FinalSample.safe_Sample +=1
            return 1

        FinalSample.unsafe_Sample +=1
        return 0

    #def findFlaw(self, fileName) :
    #   sample = open(fileName, 'r')
    #   i = 0
    #   for line in sample.readlines() :
    #      i += 1
    #      if line[:6] == "//flaw" :
    #         break
    #   return i + 1

    def testIsBlock(self) :
        if self.sanitize.isBlock == block :
            return 1
        return 0

    def testIsPrepared(self) :
        if self.construct.isPrepared == prepared :
          return 1
        return 0

    #Generates final sample
    def generate(self) :

        #test if the samples need to be generated
        #input_R = self.input.relevancy
        #sanitize_R = self.sanitize.relevancy
        #construct_R = self.construct.relevancy

        #Relevancy test
        #if(input_R * sanitize_R * construct_R < select) :
        #    return 0

        #Coherence test
        #if ( self.sanitize.constraintType != ""
        #     and self.sanitize.constraintType != self.construct.constraintType ) :
        #    return 0

        #if ( self.sanitize.constraintField != ""
        #     and self.sanitize.constraintField != self.construct.constraintField ) :
        #    return 0


        safe = self.testSafety(); #1 : safe ,0 : unsafe
        block = self.testIsBlock(); #1 : block, 0 : noBlock
        prepared = self.testIsPrepared(); #1 : prepared, 0 : noPrepared


        #Creates folder tree and sample files if they don't exists
        path = "./generation"
        if not os.path.exists(path):
            os.makedirs(path)

        #sort by safe/unsafe
        #if order == safety :
        #   if safe :
        #      path = path + "/safe"
        #   else :
        #      path = path + "/unsafe"

        if not os.path.exists(path):
           os.makedirs(path)


        for dir in self.construct.path :
            path = path + "/" + dir
            if not os.path.exists(path):
               os.makedirs(path)

        for dir in self.input.path:
            path = path + "/" + dir
            if not os.path.exists(path):
               os.makedirs(path)

        for i in range(len(self.sanitize.path)-1) :
            dir = self.sanitize.path[i]
            path = path + "/" + dir
            if not os.path.exists(path):
               os.makedirs(path)

        name = path + "/" + self.sanitize.path[-1] + ".php"
        sample = open(name, "w")

        #Adds comments
        if safe :
            commentSafe = "Safe sample"
        else :
            commentSafe = "Unsafe sample"


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

        if block and prepared :
            code  = (self.input.code + "\n"
                         + self.sanitize.code + "\n"
                         + self.construct.code + "\n\n")
            sample.write(code)

            for line in execPreparedQuery :
                sample.write(line)

            sample.write("}\n")

        elif block :
            code  = (self.input.code + "\n"
                         + self.sanitize.code + "\n"
                         + self.construct.code + "\n\n")
            sample.write(code)

            for line in execNormalQuery :
                sample.write(line)

            sample.write("}\n")

        elif prepared :
            code  = (self.input.code + "\n"
                         + self.sanitize.code + "\n"
                         + self.construct.code + "\n\n")
            sample.write(code)

            for line in execPreparedQuery :
                sample.write(line)

        else :
            code  = (self.input.code + "\n"
                         + self.sanitize.code + "\n"
                         + self.construct.code + "\n\n")
            sample.write(code)

            for line in execNormalQuery :
                sample.write(line)

        sample.write("\n ?>")
        sample.close()

        #if safe :
        #    flawLine = 0
        #else :
        #    flawLine = self.findFlaw(name)

        #manifest.addFileToTestCase(name, flawLine)
