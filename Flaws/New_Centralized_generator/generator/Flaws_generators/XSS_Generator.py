import os
import xml.etree.ElementTree as ET
import sys
from .InitializeSample import *

header = open("./rights.txt", "r")
copyright = header.readlines()

class GeneratorXSS :

    def __init__(self,manifest,fileManager,select,ordered):
        self.select = select
        self.ordered = ordered
        self.manifest = manifest
        self.fileManager = fileManager
        self.safe_Sample=0
        self.unsafe_Sample=0

    def testSafety(self,flaw,sanitize) :
        #TO improve

        #########################################################################
        #Special case (Order mater !!!!)
        #Universal safe sanitizing (Cast & co)
        #Ok in every case
        if sanitize.safe == 1 :
         self.safe_Sample += 1
         return 1

        #TODO : replace by test on the format
        # 3 :Escaping (" -> \" ) with rule 3 can lead to XSS (HTML parser first... blablabla... Read the OWASP doc thx)
        if flaw.rule == 3 and sanitize.escape == 1 :
         self.unsafe_Sample += 1
         return 0

        # 3 :Escape </script> tag needed (Rule 3)
        if flaw.scriptBlock == 1 and sanitize.scriptBlock != 1 :
         self.unsafe_Sample += 1
         return 0

        # 4 :Escape </style> tag needed (Rule 4)
        if flaw.styleBlock == 1 and sanitize.styleBlock != 1 :
         self.unsafe_Sample += 1
         return 0

        # 4 : URL must NOT start with "javascript" (but with http) (in CSS)
        if flaw.URL_CSS_context == 1 and sanitize.URL_CSS_context != 1 :
         self.unsafe_Sample += 1
         return 0

        # 4 : property must NOT start with "expression" (in CSS)
        if flaw.property_CSS_context == 1 and sanitize.property_CSS_context != 1 :
         self.unsafe_Sample += 1
         return 0

        #Universal unsafe file (Unsafe function & co)
        if flaw.unsafe == 1 :
         self.unsafe_Sample +=1
         return 0

        #Simple quote escape is enough (Rule 2,3,4)
        if flaw.simpleQuote == 1 and sanitize.simpleQuote == 1 :
         self.safe_Sample += 1
         return 1

        #Double quote escape is enough (Rule 2,3,4)
        if flaw.doubleQuote == 1 and sanitize.doubleQuote == 1 :
         self.safe_Sample += 1
         return 1

        #########################################################################
        #General Case
        #Rule 1 : escape & < > " '     (and / ideally)
        if flaw.rule == 1 and sanitize.rule1 == 1 :
         self.safe_Sample += 1
         return 1

        #Rule 2 : escape ASCII < 256 (format : &#xHH ) ideally
        #properly quoted attribute only need corresponding quote
        if flaw.rule == 2 and sanitize.rule2 == 1 :
         self.safe_Sample += 1
         return 1

        #Rule 3 : escape ASCII < 256 (format : \xHH)
        #properly quoted attribute only need corresponding quote
        #</script> can still close a script block
        if flaw.rule == 3 and sanitize.rule3 == 1 :
         self.safe_Sample += 1
         return 1

        #Rule 4 : escape ASCII < 256 (format : \HH)
        #properly quoted attribute only need corresponding quote
        # + escape </style>
        if flaw.rule == 4 and sanitize.rule4 == 1 :
         self.safe_Sample += 1
         return 1

        #Rule 5 : escape ASCII < 256 (format : %HH)
        #TO double checked, and improve...
        if flaw.rule == 5 and sanitize.rule5 == 1 :
         self.safe_Sample += 1
         return 1
        self.unsafe_Sample +=1
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
    def generate(self) :
        for f in ET.parse('./XML/file.xml').getroot():
            flaw=Flaws(f)
            for i in ET.parse('./XML/input.xml').getroot():
                Input=InputSample(i)
                self.manifest.beginTestCase(Input.inputType)
                for s in ET.parse('./XML/sanitize.xml').getroot():
                    sanitize=Sanitize(s)

                    #test if the samples need to be generated
                    input_R = Input.relevancy
                    sanitize_R = sanitize.relevancy
                    file_R = flaw.relevancy

                    #Relevancy test
                    if(input_R * sanitize_R * file_R < self.select) :
                     return 0

                    safe = self.testSafety(flaw,sanitize);

                    #Creates folder tree and sample files if they don't exists
                    path = "./generation"


                    #sort by safe/unsafe
                    if self.ordered == True :
                     if safe :
                        path = path + "/safe"
                     else :
                        path = path + "/unsafe"

                    if not os.path.exists(path):
                     os.makedirs(path)

                    for dir in flaw.path :
                     path = path + "/" + dir
                     if not os.path.exists(path):
                        os.makedirs(path)

                    for dir in Input.path:
                     path = path + "/" + dir
                     if not os.path.exists(path):
                        os.makedirs(path)

                    for i in range(len(sanitize.path)-1) :
                     dir = sanitize.path[i]
                     path = path + "/" + dir
                     if not os.path.exists(path):
                        os.makedirs(path)

                    name = path + "/" + sanitize.path[-1] + ".php"
                    sample = open(name, "w")

                    #Adds comments
                    if safe :
                     commentSafe = "Safe sample"
                    else :
                     commentSafe = "Unsafe sample"


                    sample.write("<!-- \n")
                    comment = ( commentSafe + "\n"
                              + flaw.comment + "\n"
                              + Input.comment + "\n"
                              + sanitize.comment
                              + " -->")
                    sample.write(comment)

                    #Writes copyright statement in the sample file
                    sample.write("\n\n")
                    for line in copyright :
                     sample.write(line)

                    #Writes the code in the sample file
                    sample.write("\n\n")

                    for line in flaw.start :
                     sample.write(line)

                    code  = (Input.code + "\n"
                           + sanitize.code + "\n")
                    sample.write(code)

                    for line in flaw.end :
                     sample.write(line)

                    sample.close()

                    if safe :
                     flawLine = 0
                    else :
                     flawLine = self.findFlaw(name)

                    self.manifest.addFileToTestCase(name, flawLine)
                self.manifest.endTestCase()
        self.manifest.close()