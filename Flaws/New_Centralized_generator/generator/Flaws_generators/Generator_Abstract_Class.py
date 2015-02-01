from abc import ABCMeta, abstractmethod


class Generator(metaclass=ABCMeta):
    def __init__(self, manifest, fileManager, select, ordered):
        self.select = select
        self.ordered = ordered
        self.manifest = manifest
        self.fileManager = fileManager
        self.safe_Sample = 0
        self.unsafe_Sample = 0

    @classmethod
    def findFlaw(cls, fileName):
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