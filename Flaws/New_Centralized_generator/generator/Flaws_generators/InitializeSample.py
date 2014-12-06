import os
import sys
import time
import getopt

class InitialSample : #Initialize path,comment and relevancy parameters
    def __init__(self, initialSample) : #XML tree in parameter
        self.path = []
        tree_path = initialSample.find("path").findall("dir")
        for dir in tree_path :
            self.path.append(dir.text)
            
        self.comment = initialSample.find("comment").text
        self.relevancy = float(initialSample.find("relevancy").text)

    def addSafetyAttributes(self, initialSample) :
        #Classify XSS injection/sanitazition by rule of OWASP
        safety = initialSample.find("safety")

        #Rule of sanitizing needed   
        self.rule = 0
        if safety.get("rule") != None :
            self.rule = int(safety.get("rule"))

        #Escaping simple quoted is enough ?
        self.simpleQuote = 0
        if safety.get("simpleQuote") != None :
            self.simpleQuote = int(safety.get("simpleQuote"))

        #Escaping double quoted is enough ?
        self.doubleQuote = 0
        if safety.get("doubleQuote") != None :
            self.doubleQuote = int(safety.get("doubleQuote"))

        #Unsafe function & co
        self.unsafe = 0
        if safety.get("unsafe") != None :
            self.unsafe = int(safety.get("unsafe"))

        #Escape of type " -> \" needed ? (TODO : improve that)
        self.escape = 0
        if safety.get("escape") != None :
            self.escape = int(safety.get("escape"))

        #Escape of </script> needed ?
        self.scriptBlock = 0
        if safety.get("scriptBlock") != None :
            self.scriptBlock = int(safety.get("scriptBlock"))

        #Escape of </style> needed ?
        self.styleBlock = 0
        if safety.get("styleBlock") != None :
            self.styleBlock = int(safety.get("styleBlock"))

        #Prevent data from starting with "javascript" needed ?
        self.URL_CSS_context = 0
        if safety.get("URL_CSS_context") != None :
            self.URL_CSS_context = int(safety.get("URL_CSS_context"))

        #Prevent data from starting with "expression" needed ?
        self.property_CSS_context = 0
        if safety.get("property_CSS_context") != None :
            self.property_CSS_context = int(safety.get("property_CSS_context"))


class InputSample(InitialSample) : #Initialize the type of input and the code parameters of the class
    def __init__(self, initialSample) : #XML tree in parameter
        InitialSample.__init__(self,initialSample)
        self.inputType = initialSample.find("inputType").text
        self.code = initialSample.find("code").text   


class Sanitize(InitialSample) : #Initialize rules, safety, code and escape
    def __init__(self, initialSample) : #XML tree in parameter
        InitialSample.__init__(self,initialSample)
        self.code = initialSample.find("code").text

        safety = initialSample.find("safety")

        #Universal safe sanitizing (Cast & co)
        self.safe = 0
        if safety.get("safe") != None :
            self.safe = int(safety.get("safe"))

            
        #Rule that can be always sanitize (/!\ Format)
        self.rule1 = 0
        self.rule2 = 0
        self.rule3 = 0
        self.rule4 = 0
        self.rule5 = 0
        
        if safety.get("rule1") != None :
            self.rule1 = int(safety.get("rule1"))
        if safety.get("rule2") != None :
            self.rule2 = int(safety.get("rule2"))
        if safety.get("rule3") != None :
            self.rule3 = int(safety.get("rule3"))
        if safety.get("rule4") != None :
            self.rule4 = int(safety.get("rule4"))
        if safety.get("rule5") != None :
            self.rule5 = int(safety.get("rule5"))
            
        addSafetyAttributes(self,initialSample)


class Flaws(InitialSample): #Load parameters and code beginning and end
    def __init__(self, initialSample) : #Add parameters showing the beginning and the end of the sample
        InitialSample.__init__(self,initialSample)
        #print(os.getcwd())
        start = initialSample.find("start").text
        fileStart = open("samples/" + start, 'r')
        self.start = fileStart.readlines() #Add start of the sample
        fileStart.close()

        end = initialSample.find("end").text
        fileEnd = open("samples/" + end, 'r')
        self.end = fileEnd.readlines() #Add end of the sample
        fileEnd.close()

        addSafetyAttributes(self,initialSample)
        
        
