#constante
safe = "safe"
unsafe = "unsafe"
#block = "block"
#noBlock = "noBlock"
#prepared = "prepared"
#noPrepared = "noPrepared"



#Manages initial samples, which are created to generate final samples by combination
class InitialSample :
    def __init__(self, initialSample) :
        self.path = []
        tree_path = initialSample.find("path").findall("dir")
        for dir in tree_path :
            self.path.append(dir.text)

        self.comment = initialSample.find("comment").text
        self.code = initialSample.find("code").text
        self.relevancy = float(initialSample.find("relevancy").text)

class InputSample(InitialSample) :
    def __init__(self, initialSample) :
        InitialSample.__init__(self,initialSample)
        self.inputType = initialSample.find("inputType").text

class Sanitize(InitialSample) :
    def __init__(self, initialSample) :
        InitialSample.__init__(self,initialSample)
        safety = initialSample.find("safety")
        if safety.get("safe") == "1" :
            self.isSafe = safe
        else :
            self.isSafe = unsafe

class Construction(InitialSample):
    def __init__(self, initialSample) :
        InitialSample.__init__(self,initialSample)

        safety = initialSample.find("safety")
        if safety.get("safe") == "1" :
            self.isSafe = safe
        else :
            self.isSafe = unsafe
