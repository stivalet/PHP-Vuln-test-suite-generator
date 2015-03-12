from abc import ABCMeta, abstractmethod
from Classes.Manifest import *


class Generator(metaclass=ABCMeta):

    def __init__(self, date, select):
        self.date = date
        self.select = select
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

    def setFileName(self, params, name):
        for param in params:
            name+="_["
            for dir in param.path:
                    name += "("+dir+")"
            name+="]"
        return name