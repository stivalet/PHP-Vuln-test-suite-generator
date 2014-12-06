import os
import sys

class FileManager :

    def createFile(file) :
        if not os.path.exists(file.path):
            os.makedirs(file.path)

        createdFile = open(path+"/"+name,"w")
        createdFile.write(file.content)
        createdFile.close()

    
