from abc import ABCMeta, abstractmethod


class Generator(metaclass=ABCMeta):
    def __init__(self, date, manifest, select, cwe):
        self.select = select
        self.cwe = cwe
        self.date = date
        self.manifest = manifest
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