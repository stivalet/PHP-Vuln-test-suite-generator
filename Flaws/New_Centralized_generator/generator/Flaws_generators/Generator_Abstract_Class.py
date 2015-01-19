from abc import ABCMeta, abstractmethod

class Generator:
    __metaclass__ = ABCMeta

    def __init__(self, manifest, fileManager, select, ordered):
        self.select = select
        self.ordered = ordered
        self.manifest = manifest
        self.fileManager = fileManager
        self.safe_Sample = 0
        self.unsafe_Sample = 0

    @abstractmethod
    def generate(self, params): pass

    @abstractmethod
    def getType(self): pass