import os
import sys


class FileManager:
    def createFile(self, file):
        if not os.path.exists(file.path):
            os.makedirs(file.path)

        createdFile = open(file.path + "/" + file.name, "w")
        createdFile.write(file.content)
        createdFile.close()

    xml = {
        "input": "input.xml",
        "sanitize": "sanitize.xml",
        "construction": "construction.xml",
    }

    def getXML(self, xmlfile):
        return "XML/" + self.xml[xmlfile]