from abc import ABCMeta, abstractmethod
import shutil
from Classes.Manifest import *


class Generator(metaclass=ABCMeta):

    def __init__(self, date, flaw):
        self.date = date
        self.manifest = Manifest(date, flaw)
        self.safe_Sample = 0
        self.unsafe_Sample = 0

    @staticmethod
    def findFlaw(fileName):
        sample = open(fileName, 'r')
        i = 0
        for line in sample.readlines():
            i += 1
            if line[:6] == "//flaw":
                break
        return i + 1

    @abstractmethod
    def generate(self, params):
        pass

    @abstractmethod
    def getType(self):
        pass

    def generateFileName(self, params, name):
        for param in params:
            name+="__"
            for dir in param.path:
                    name += dir+"-"
            name = name[:-1]
        return name

    def onDestroy(self, flaw):
        self.manifest.close()
        if self.safe_Sample+self.unsafe_Sample > 0:
            print(flaw + " generation report:")
            print(str(self.safe_Sample) + " safe samples")
            print(str(self.unsafe_Sample) + " unsafe samples")
            print(str(self.unsafe_Sample + self.safe_Sample) + " total\n")
        else:
            shutil.rmtree("../PHPTestSuite_"+self.date+"/"+flaw)

