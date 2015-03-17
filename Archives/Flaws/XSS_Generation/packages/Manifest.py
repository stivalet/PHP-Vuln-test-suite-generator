import os
import time


#Constants
safe = "safe"
unsafe = "unsafe"
needQuote = "needQuote"
quote = "quote"

integer = "int"



class Manifest :
    def __init__(self) :

        path = "./generation"        
        if not os.path.exists(path):
            os.makedirs(path) #Create the folder if not exist
            
        self.manifest = open("./generation/manifest.xml","w")
        self.manifest.write("<container>\n")
        
    def beginTestCase(self,Input) :
        date = time.strftime('%d/%m/%y' ,time.localtime())
        metaData = ("\t<testcase> \n" +
                    "\t\t<meta-data> \n" +
                    "\t\t\t<author>H. Bühler, D. Lucas, F. Nollet, A. Reszetko</author> \n" +
                    "\t\t\t<date>" + date + "</date> \n" +
                    "\t\t\t<input>" + Input + "</input>\n" +
                    "\t\t</meta-data> \n \n")
        self.manifest.write(metaData) #Add metadata in the manifest

    def addFileToTestCase(self, path, flawLine) :
        if(flawLine == 0) :            
            file = "\t\t<file path=\""+ path +"\" language=\"PHP\"/> \n\n"
        else :
            flawLine = str(flawLine)
            file = ("\t\t<file path=\"" + path + "\" language=\"PHP\"> \n" +
                    "\t\t\t<flaw line=\""+flawLine+"\" name = \"XSS\"/> \n" +
                    "\t\t</file> \n\n" )

        self.manifest.write(file)


    def endTestCase(self) :
        self.manifest.write("\t</testcase> \n\n\n")

    def close(self) :
        self.manifest.write("</container>")
        self.manifest.close()
