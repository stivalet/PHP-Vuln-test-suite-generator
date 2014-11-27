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

   
   def findFlaw(self, fileName) : #Find if a line in the file start by //flaw
      sample = open(fileName, 'r')
      i = 0
      for line in sample.readlines() :
         i += 1
         if line[:6] == "//flaw" :
            break
      return i + 1
