from abc import ABCMeta, abstractmethod
import shutil
from Classes.Manifest import *


class Generator(metaclass=ABCMeta):

    def __init__(self, date, select, flaw):
        self.date = date
        self.select = select
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

    def revelancyTest(self, params):
        relevancy = 1
        for param in params:
            relevancy *= param.relevancy
            if relevancy < self.select:
                return 0
        return relevancy

    def generateFileName(self, params, name):
        for param in params:
            name+="_["
            for dir in param.path:
                    name += "("+dir+")"
            name+="]"
        return name

    def onDestroy(self, flaw):
        self.manifest.close()
        if self.safe_Sample+self.unsafe_Sample > 0:
            print(flaw + " generation report:")
            print(str(self.safe_Sample) + " safe samples")
            print(str(self.unsafe_Sample) + " unsafe samples")
            print(str(self.unsafe_Sample + self.safe_Sample) + " total\n")
        else:
            shutil.rmtree("../generation_"+self.date+"/"+flaw)

