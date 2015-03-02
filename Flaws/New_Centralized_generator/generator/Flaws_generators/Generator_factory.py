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
    def makeXSS_Generator(date, manifest, select, CWElist):
        return GeneratorXSS(date, manifest, select, CWElist)

    @staticmethod
    def makeInjection_Generator(date, manifest, select, CWElist):
        return GeneratorInjection(date, manifest, select, CWElist)

    @staticmethod
    def makeIDOR_Generator(date, manifest, select, CWElist):
        return GeneratorIDOR(date, manifest, select, CWElist)

    @staticmethod
    def makeURF_Generator(date, manifest, select, CWElist):
        return GeneratorURF(date, manifest, select, CWElist)

    @staticmethod
    def makeSM_Generator(date, manifest, select, CWElist):
        return GeneratorSM(date, manifest, select, CWElist)

    @staticmethod
    def makeSDE_Generator(date, manifest, select, CWElist):
        return GeneratorSDE(date, manifest, select, CWElist)
