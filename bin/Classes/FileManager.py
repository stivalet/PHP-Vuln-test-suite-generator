import os


class FileManager:
    @staticmethod
    def createFile(file):
        if not os.path.exists(file.path):
            os.makedirs(file.path)

        createdFile = open(file.path + "/" + file.name, "w")
        createdFile.write(file.content)
        createdFile.close()

    _xml = {
        "input": "input.xml",
        "sanitize": "sanitize.xml",
        "construction": "construction.xml",
    }

    @classmethod
    def getXML(cls, xmlfile):
        return "XML/" + cls._xml[xmlfile]