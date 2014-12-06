import os

select = 0
order = 0
# order = "safety"

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

#Manages final samples, by a combination of 3 initialSample        
class FinalSample :
   
   #Initializes counters
   safe_Sample = 0
   unsafe_Sample = 0
    
   def __init__(self, file, Input, sanitize) :
       self.file = file
       self.input = Input
       self.sanitize = sanitize

   def testSafety(self) :
      if self.construct != None :
         if self.sanitize.isSafe == safe :
            FinalSample.safe_Sample +=1
            return 1
         if self.construct.isSafe == safe :
            FinalSample.safe_Sample +=1
            return 1
         if self.sanitize.isSafe == needQuote and self.construct.isSafe == quote :
            FinalSample.safe_Sample +=1
            return 1
         #case of pg_escape_literal
         if self.sanitize.isSafe == noQuote and self.construct.isSafe == 0 :
            FinalSample.safe_Sample +=1
            return 1
      
   def findFlaw(self, fileName) : #Find if a line in the file start by //flaw
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
      if self.file != None
         file_R = self.file.relevancy
      if self.construct != None
         construct_R = self.construct.relevancy

      #Relevancy test
      if(input_R * sanitize_R * file_R < select) :
         return 0

      #Coherence test
      if ( self.sanitize.constraintType != ""
            and self.sanitize.constraintType != self.construct.constraintType ) :
         return 0

      if ( self.sanitize.constraintField != ""
            and self.sanitize.constraintField != self.construct.constraintField ) :
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

      if self.file == "XSS"
         for dir in self.file.path :
            path = path + "/" + dir
            if not os.path.exists(path):
               os.makedirs(path)

      if self.kind == "Injection"
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

      if self.kind == "XSS" :
         self.writingXSS(sample,safe,manifest)
      
      if self.kind == "Injection" :
         self.writingInjection(sample,safe,manifest)

   def writingXSS(self, sample, safe, manifest) :
      sample.write("<!-- \n")
      comment = ( commentSafe + "\n"
                  + self.file.comment + "\n"
                  + self.input.comment + "\n"
                  + self.sanitize.comment 
                  + " -->")
      sample.write(comment)

      #Writes copyright statement in the sample file
      sample.write("\n\n")
      for line in copyright :
         sample.write(line)

      #Writes the code in the sample file
      sample.write("\n\n")

      if self.kind == "XSS" :
         for line in self.file.start :
            sample.write(line)
      
         code  = (self.input.code + "\n"
                  + self.sanitize.code + "\n")
         sample.write(code)
      
         for line in self.file.end :
            sample.write(line)
      
         sample.close()

         if safe :
            flawLine = 0
      else :
         flawLine = self.findFlaw(name)
            
      manifest.addFileToTestCase(name, flawLine)

   def writingInjection(self, sample, safe, manifest) :
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
