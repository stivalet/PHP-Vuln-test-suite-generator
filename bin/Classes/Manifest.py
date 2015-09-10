import os
import time


# Constants
safe = "safe"
unsafe = "unsafe"
needQuote = "needQuote"
quote = "quote"

integer = "int"


class Manifest:
    def __init__(self, date, flaw="Not define"):
        self.date=date
        path = "../PHPTestSuite_"+self.date+"/" + flaw
        if not os.path.exists(path):
            os.makedirs(path)  # Create the folder if not exist

        self.flaw = flaw
        self.manifest = open(path + "/manifest.xml", "w")
        self.manifest.write("<container>\n")

    def beginTestCase(self, Input):
        date = time.strftime('%d/%m/%y', time.localtime())
        metaData = ("\t<testcase> \n" +
                    "\t\t<meta-data> \n" +
                    "\t\t\t<author>Bertrand STIVALET, Aurelien DELAITRE</author> \n" +
                    "\t\t\t<date>" + date + "</date> \n" +
                    "\t\t\t<input>" + Input + "</input>\n" +
                    "\t\t</meta-data> \n \n")
        self.manifest.write(metaData)  # Add metadata in the manifest

    def addFileToTestCase(self, path, flawLine):
        tmp = ""
        for s in path.split("/"):
            if s in ["..", "PHPTestSuite_"+self.date, "XSS", "Injection", "IDOR", "URF", "SM", "SDE"]:
                continue
            else:
                tmp += s + "/"
        tmp = tmp[:-1]
        # print(tmp)
        if (flawLine == 0):
            file = "\t\t<file path=\"" + tmp + "\" language=\"PHP\"/> \n\n"
        else:
            flawLine = str(flawLine)
            file = ("\t\t<file path=\"" + tmp + "\" language=\"PHP\"> \n" +
                    "\t\t\t<flaw line=\"" + flawLine + "\" name =\"" + self.flaw + "\"/> \n" +
                    "\t\t</file> \n\n")

        self.manifest.write(file)


    def endTestCase(self):
        self.manifest.write("\t</testcase> \n\n\n")

    def close(self):
        self.manifest.write("</container>")
        self.manifest.close()
