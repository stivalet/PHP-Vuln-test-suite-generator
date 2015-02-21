from .XSS_Generator import *
from .Injection_Generator import *
from .IDOR_Generator import *
from .URF_Generator import *
from .SM_Generator import *
from .SDE_Generator import *
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

    @staticmethod
    def makeURF_Generator(date, manifest, select, ordered):
        return GeneratorURF(date, manifest, select, ordered)

    @staticmethod
    def makeSM_Generator(date, manifest, select, ordered):
        return GeneratorSM(date, manifest, select, ordered)

    @staticmethod
    def makeSDE_Generator(date, manifest, select, ordered):
        return GeneratorSDE(date, manifest, select, ordered)
