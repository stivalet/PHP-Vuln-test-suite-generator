from .XSS_Generator import *
from .Injection_Generator import *
from .IDOR_Generator import *
from .Dangerous_Functions_Generator import *


class Generator_factory:
    def __init__(self):
        pass

    def makeXSS_Generator(self, manifest, fileManager, select, ordered):
        return GeneratorXSS(manifest, fileManager, select, ordered)

    def makeInjection_Generator(self, manifest, fileManager, select, ordered):
        return GeneratorInjection(manifest, fileManager, select, ordered)

    def makeIDOR_Generator(self, manifest, fileManager, select, ordered):
        return GeneratorIDOR(manifest, fileManager, select, ordered)

    def makeDangerous_Functions_Generator(self, manifest, fileManager, select, ordered):
        return GeneratorDangerousFunctions(manifest, fileManager, select, ordered)
