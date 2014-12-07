import os
from .InitialSample import *

select = 0
order = 0
#order = "safety"

#Constants
safe = "safe"
unsafe = "unsafe"
needQuote = "needQuote"
quote = "quote"
noQuote = "noQuote"
integer = "int"
safety = "safety"


#Gets copyright header from file
header = open("./rights.txt", "r")
copyright = header.readlines()
header.close()

#Gets query execution code
footer = open("./execQuery.txt", "r")
execQuery = footer.readlines()
footer.close()

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
    
    def __init__(self, params) :
        #self.construct = params["construction"]
        #self.input = params["input"]
        #self.sanitize = params["sanitize"]
        self.params=params

    def testSafety(self) :
       #if self.sanitize.isSafe == safe :
       #    FinalSample.safe_Sample +=1
       #    return 1
       #if self.construct.isSafe == safe :
       #    FinalSample.safe_Sample +=1
       #    return 1
       #if self.sanitize.isSafe == needQuote and self.construct.isSafe == quote :
       #    FinalSample.safe_Sample +=1
       #    return 1
       ##case of pg_escape_literal
       #if self.sanitize.isSafe == noQuote and self.construct.isSafe == 0 :
       #    FinalSample.safe_Sample +=1
       #    return 1
       for param in self.params:
          if(isinstance(self.params[param],Sanitize) and self.params[param].isSafe == safe):
              FinalSample.safe_Sample +=1
              #print("ok1\n")
              return 1
          if(isinstance(self.params[param],Construction) and self.params[param].isSafe == safe):
              FinalSample.safe_Sample +=1
              #print("ok2\n")
              return 1
          if(isinstance(self.params[param],Sanitize) and self.params[param].isSafe == needQuote):
              for param2 in self.params:
                 if(isinstance(self.params[param2],Construction) and self.params[param2].isSafe == quote):
                    FinalSample.safe_Sample +=1
                    #print("ok3\n")
                    return 1
          if(isinstance(self.params[param],Sanitize) and self.params[param].isSafe == noQuote):
              for param2 in self.params:
                 if(isinstance(self.params[param],Construction) and self.params[param] and self.params[param].isSafe == 0):
                    FinalSample.safe_Sample +=1
                    #print("ok4\n")
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

        ##test if the samples need to be generated
        #input_R = self.input.relevancy
        #sanitize_R = self.sanitize.relevancy
        #construct_R = self.construct.relevancy

        ##Relevancy test
        #if(input_R * sanitize_R * construct_R < select) :
        #    return 0
        relevancy=1
        for param in self.params:
            relevancy*=self.params[param].relevancy
            if(relevancy<select):
                return 0 

        ##Coherence test
        #if ( self.sanitize.constraintType != ""
        #     and self.sanitize.constraintType != self.construct.constraintType ) :
        #    return 0

        #if ( self.sanitize.constraintField != ""
        #     and self.sanitize.constraintField != self.construct.constraintField ) :
        #    return 0

        for param in self.params:
            if(isinstance(self.params[param],Sanitize) and self.params[param].constraintType != ""):
                for param2 in self.params:
                    if(isinstance(self.params[param2],Construction) and (self.params[param].constraintType != self.params[param2].constraintType)):
                        return 0
            if(isinstance(self.params[param],Sanitize) and self.params[param].constraintField != ""):
                for param2 in self.params:
                    if(isinstance(self.params[param2],Construction) and (self.params[param].constraintField != self.params[param2].constraintField)):
                        return 0

        safe = self.testSafety();

        
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

        
        #for dir in self.construct.path :
        #    path = path + "/" + dir
        #    if not os.path.exists(path):
        #       os.makedirs(path)

        #for dir in self.input.path:
        #    path = path + "/" + dir
        #    if not os.path.exists(path):
        #       os.makedirs(path)

        #for i in range(len(self.sanitize.path)-1) :
        #    dir = self.sanitize.path[i]
        #    path = path + "/" + dir
        #    if not os.path.exists(path):
        #       os.makedirs(path)
        
        file_name=""
        for param in self.params:
           if(isinstance(self.params[param],Sanitize)):
              if(len(self.params[param].path)>1):
                 for i in range(len(self.params[param].path)-1) :
                    dir = self.params[param].path[i]
                    path = path + "/" + dir
                    if not os.path.exists(path):
                       os.makedirs(path)
              file_name=self.params[param].path[-1]
           else:
              for dir in self.params[param].path :
                 path = path + "/" + dir
                 if not os.path.exists(path):
                    os.makedirs(path)

        name = path + "/" + file_name + ".php"
        sample = open(name, "w")

        #Adds comments
        if safe :
            commentSafe = "Safe sample"
        else :
            commentSafe = "Unsafe sample"
        

        sample.write("<?php \n")
        comment = "/*" + commentSafe + "\n"
        for param in self.params:
            comment+=self.params[param].comment+"\n"               
        comment += " */"
        sample.write(comment)

        #Writes copyright statement in the sample file
        sample.write("\n\n")
        for line in copyright :
            sample.write(line)

        #Writes the code in the sample file
        sample.write("\n\n")
        
        code=""
        for param in self.params:
               	code+=(self.params[param].code+"\n")
        sample.write(code)

        #Adds the code for query execution
        for line in execQuery :
            sample.write(line)

        sample.write("\n ?>")
        sample.close()

        if safe :
            flawLine = 0
        else :
            flawLine = self.findFlaw(name)
            
        manifest.addFileToTestCase(name, flawLine)
