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
    
   def __init__(self, file, Input, sanitize) :
       self.file = file
       self.input = Input
       self.sanitize = sanitize

   def testSafety(self) :
      #TO improve
      
      #########################################################################      
      #Special case (Order mater !!!!)
      #Universal safe sanitizing (Cast & co)
      #Ok in every case
      if self.sanitize.safe == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #TODO : replace by test on the format
      # 3 :Escaping (" -> \" ) with rule 3 can lead to XSS (HTML parser first... blablabla... Read the OWASP doc thx)
      if self.file.rule == 3 and self.sanitize.escape == 1 :
         FinalSample.unsafe_Sample += 1
         return 0

      # 3 :Escape </script> tag needed (Rule 3)
      if self.file.scriptBlock == 1 and self.sanitize.scriptBlock != 1 :
         FinalSample.unsafe_Sample += 1
         return 0

      # 4 :Escape </style> tag needed (Rule 4)
      if self.file.styleBlock == 1 and self.sanitize.styleBlock != 1 :
         FinalSample.unsafe_Sample += 1
         return 0

      # 4 : URL must NOT start with "javascript" (but with http) (in CSS)
      if self.file.URL_CSS_context == 1 and self.sanitize.URL_CSS_context != 1 :
         FinalSample.unsafe_Sample += 1
         return 0

      # 4 : property must NOT start with "expression" (in CSS)
      if self.file.property_CSS_context == 1 and self.sanitize.property_CSS_context != 1 :
         FinalSample.unsafe_Sample += 1
         return 0

      #Universal unsafe file (Unsafe function & co)
      if self.file.unsafe == 1 :
         FinalSample.unsafe_Sample +=1
         return 0

      #Simple quote escape is enough (Rule 2,3,4)
      if self.file.simpleQuote == 1 and self.sanitize.simpleQuote == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #Double quote escape is enough (Rule 2,3,4)
      if self.file.doubleQuote == 1 and self.sanitize.doubleQuote == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #########################################################################
      #General Case
      #Rule 1 : escape & < > " '     (and / ideally)
      if self.file.rule == 1 and self.sanitize.rule1 == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #Rule 2 : escape ASCII < 256 (format : &#xHH ) ideally
      #properly quoted attribute only need corresponding quote
      if self.file.rule == 2 and self.sanitize.rule2 == 1 :         
         FinalSample.safe_Sample += 1
         return 1

      #Rule 3 : escape ASCII < 256 (format : \xHH)
      #properly quoted attribute only need corresponding quote
      #</script> can still close a script block
      if self.file.rule == 3 and self.sanitize.rule3 == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #Rule 4 : escape ASCII < 256 (format : \HH)
      #properly quoted attribute only need corresponding quote
      # + escape </style>
      if self.file.rule == 4 and self.sanitize.rule4 == 1 :
         FinalSample.safe_Sample += 1
         return 1

      #Rule 5 : escape ASCII < 256 (format : %HH)
      #TO double checked, and improve...
      if self.file.rule == 5 and self.sanitize.rule5 == 1 :
         FinalSample.safe_Sample += 1
         return 1


      
      FinalSample.unsafe_Sample +=1
      return 0
   
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
      file_R = self.file.relevancy

      #Relevancy test
      if(input_R * sanitize_R * file_R < select) :
         return 0

      safe = self.testSafety();

      
      #Creates folder tree and sample files if they don't exists
      path = "./generation"


      #sort by safe/unsafe
      if order == safety :
         if safe :
            path = path + "/safe"
         else :
            path = path + "/unsafe"
            
      if not os.path.exists(path):
         os.makedirs(path)
        
      for dir in self.file.path :
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
