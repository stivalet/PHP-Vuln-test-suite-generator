class File :
#Class containing informations abour generated files
    def __init__ (self):
        self.path=".."
        self.content=""
        self.name=""

    #def __init__ (self, path, name, content) :
     #   self.path = path
      #  self.content = content
       # self.name = name

    def setPath(self,path):
        self.path=path

    def addPath(self,path):
        self.path+="/"+path

    def getPath(self):
        return self.path

    def setName(self,name):
        self.name=name+".php"

    def getName(self):
        return self.name

    def addContent(self,content):
        self.content+=content
