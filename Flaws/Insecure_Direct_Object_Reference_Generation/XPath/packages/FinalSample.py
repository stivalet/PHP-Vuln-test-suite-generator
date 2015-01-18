import os

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

#No need in this version the part ExecQuery in concatenated with the construction samples
#Gets query execution code
#fileQuery = open("./execQuery.txt", "r")
#execQuery = fileQuery.readlines()
#fileQuery.close()

def setRelevancy(R) :
   global select
   select = int(R)

def setOrder(O) :
   if O==1 :
      global order
      order = safety


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

    def findFlaw(self, fileName) :
       sample = open(fileName, 'r')
       i = 0
       for line in sample.readlines() :
          i += 1
          if line[:6] == "//flaw" :
             break
       return i + 1

    #Generates final sample
    def generate(self, manifest) :

        #test if the samples need to be generated
        input_R = self.input.relevancy
        sanitize_R = self.sanitize.relevancy
        construct_R = self.construct.relevancy

        #Relevancy test
        if(input_R * sanitize_R * construct_R < select) :
            return 0

        #Coherence test
        #if ( self.sanitize.constraintType != ""
        #     and self.sanitize.constraintType != self.construct.constraintType ) :
        #    return 0

        #if ( self.sanitize.constraintField != ""
        #     and self.sanitize.constraintField != self.construct.constraintField ) :
        #    return 0

        #Build constraints
        safe = self.testSafety() #1 : safe ,0 : unsafe

        #Creates folder tree and sample files if they don't exists
        path = "./generation"
        if not os.path.exists(path):
            os.makedirs(path)

        #sort by safe/unsafe
        if order == safety :
           if safe :
              path = path + "/safe"
           else :
              path = path + "/unsafe"

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

        code  = (self.input.code + "\n"
                     + self.sanitize.code + "\n"
                     + self.construct.code + "\n\n")
        sample.write(code)

        #for line in execQuery :
        #    sample.write(line)

        sample.write("\n?>")
        sample.close()

        if safe :
            flawLine = 0
        else :
            flawLine = self.findFlaw(name)

        manifest.addFileToTestCase(name, flawLine)
