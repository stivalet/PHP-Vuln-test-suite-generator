from .XSS_Generator import *
from .Injection_Generator import *
from .IDOR_Generator import *
from .URF_Generator import *
from .SM_Generator import *
from .SDE_Generator import *


class Generator_factory:
    def __init__(self):
        pass

    @staticmethod
    def makeXSS_Generator(date):
        return GeneratorXSS(date)

    @staticmethod
    def makeInjection_Generator(date):
        return GeneratorInjection(date)

    @staticmethod
    def makeIDOR_Generator(date):
        return GeneratorIDOR(date)

    @staticmethod
    def makeURF_Generator(date):
        return GeneratorURF(date)

    @staticmethod
    def makeSM_Generator(date):
        return GeneratorSM(date)

    @staticmethod
    def makeSDE_Generator(date):
        return GeneratorSDE(date)
