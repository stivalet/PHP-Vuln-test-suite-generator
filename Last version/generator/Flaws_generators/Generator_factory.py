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
    def makeXSS_Generator(date, select):
        return GeneratorXSS(date, select)

    @staticmethod
    def makeInjection_Generator(date, select):
        return GeneratorInjection(date, select)

    @staticmethod
    def makeIDOR_Generator(date, select):
        return GeneratorIDOR(date, select)

    @staticmethod
    def makeURF_Generator(date, select):
        return GeneratorURF(date, select)

    @staticmethod
    def makeSM_Generator(date, select):
        return GeneratorSM(date, select)

    @staticmethod
    def makeSDE_Generator(date, select):
        return GeneratorSDE(date, select)
