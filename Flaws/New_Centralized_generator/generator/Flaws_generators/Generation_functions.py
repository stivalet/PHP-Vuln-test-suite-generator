import xml.etree.ElementTree as ET
from .InitializeSample import *


def f_construction(generator, root, params, i):
    tree_construction = ET.parse(generator.fileManager.getXML("construction")).getroot()
    for c in tree_construction:
        params[i] = Flaws(c)
        if set(generator.getType()).intersection(params[i].flaws):
            generation(generator, root, params, i + 1)


def f_sanitize(generator, root, params, i):
    tree_sanitize = ET.parse(generator.fileManager.getXML("sanitize")).getroot()
    for s in tree_sanitize:
        params[i] = Sanitize(s)
        if set(generator.getType()).intersection(params[i].flaws):
            generation(generator, root, params, i + 1)


def f_input(generator, root, params, i):
    tree_input = ET.parse(generator.fileManager.getXML("input")).getroot()
    for Input in tree_input:
        params[i] = InputSample(Input)
        generation(generator, root, params, i + 1)


options = {
    "construction": f_construction,
    "sanitize": f_sanitize,
    "input": f_input,
}


def initialization(generator, root):
    params = [None] * len(root)
    generation(generator, root, params)
    return [generator.safe_Sample, generator.unsafe_Sample]


def generation(generator, root, params, i=0):
    if i < len(root):
        options[root[i].tag](generator, root, params, i)
    else:
        generator.generate(params)