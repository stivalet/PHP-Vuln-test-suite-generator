from .XSS_Generator import *
from .Injection_Generator import *
from .IDOR_Generator import *
from .Dangerous_Functions_Generator import *


class Generator_factory:
    def __init__(self):
        pass

    @staticmethod
    def makeXSS_Generator(manifest, fileManager, select, ordered):
        return GeneratorXSS(manifest, fileManager, select, ordered)

    @staticmethod
    def makeInjection_Generator(manifest, fileManager, select, ordered):
        return GeneratorInjection(manifest, fileManager, select, ordered)

    @staticmethod
    def makeIDOR_Generator(manifest, fileManager, select, ordered):
        return GeneratorIDOR(manifest, fileManager, select, ordered)

    @staticmethod
    def makeDangerous_Functions_Generator(manifest, fileManager, select, ordered):
        return GeneratorDangerousFunctions(manifest, fileManager, select, ordered)
