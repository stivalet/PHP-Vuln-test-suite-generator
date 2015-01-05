import os
import sys

class FileManager :

    def createFile(self,file) :
        if not os.path.exists(file.path):
            os.makedirs(file.path)

        createdFile = open(file.path+"/"+file.name,"w")
        createdFile.write(file.content)
        createdFile.close()

    xml={
        "input":"input.xml",
        "sanitize":"sanitize.xml",
        "flaw":"file.xml",
        "input_injection":"input_injection.xml",
        "sanitize_injection":"sanitize_injection.xml",
        "SQL_injection":"SQL_injection.xml",
        "LDAP_injection":"LDAP_injection.xml",
        "XPath_injection":"XPath_injection.xml",
    }
    def getXML(self,xmlfile):
        return "XML/"+self.xml[xmlfile]

    
