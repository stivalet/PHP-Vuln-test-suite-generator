from .XSS_Generator import *
from .Injection_Generator import *
from .IDOR_Generator import *
from .Dangerous_Functions_Generator import *


class Generator_factory:
    def __init__(self):
        pass

    @staticmethod
    def makeXSS_Generator(date, manifest, select, ordered):
        return GeneratorXSS(date, manifest, select, ordered)

    @staticmethod
    def makeInjection_Generator(date, manifest, select, ordered):
        return GeneratorInjection(date, manifest, select, ordered)

    @staticmethod
    def makeIDOR_Generator(date, manifest, select, ordered):
        return GeneratorIDOR(date, manifest, select, ordered)

    @staticmethod
    def makeDangerous_Functions_Generator(date, manifest, select, ordered):
        return GeneratorDangerousFunctions(date, manifest, select, ordered)
