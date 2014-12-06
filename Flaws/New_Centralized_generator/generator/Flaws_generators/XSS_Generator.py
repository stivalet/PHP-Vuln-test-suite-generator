import os
import xml.etree.ElementTree as ET
import sys

class GeneratorXSS :

    def __init__ (self,manifest,fileManager,select,ordered) :
        self.select = select
        self.ordered = ordered
        self.manifest = manifest
        self.fileManager = fileManager

    def generate (self) :
        
