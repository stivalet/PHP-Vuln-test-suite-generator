import xml.etree.ElementTree as ET
import re

from .InitializeSample import *
from Classes.FileManager import *
from Classes.File import *


def f_construction(generator, root, params, i):
    global decorators
    tree_construction = ET.parse(FileManager.getXML("construction")).getroot()
    for c in tree_construction:
        params[i] = Construction(c)
        if set(generator.getType()).intersection(params[i].flaws):
            generation(generator, root, params, i + 1)
    decorators[i] = []


def f_sanitize(generator, root, params, i):
    global decorators
    tree_sanitize = ET.parse(FileManager.getXML("sanitize")).getroot()
    for s in tree_sanitize:
        params[i] = Sanitize(s)
        if set(generator.getType()).intersection(params[i].flaws):
            generation(generator, root, params, i + 1)
    decorators[i] = []


def f_input(generator, root, params, i):
    global decorators
    tree_input = ET.parse(FileManager.getXML("input")).getroot()
    for Input in tree_input:
        params[i] = InputSample(Input)
        generation(generator, root, params, i + 1)
    decorators[i] = []


def f_decorator(param, decorators):
    loop_alert = 0
    global function_cpt
    function_alert = 0
    global class_cpt
    global file_cpt
    global postOp
    # print(decorators)
    for d in reversed(decorators):
        if d.tag == "if":
            types = [Construction, Sanitize, ]
            if type(param) not in types:
                continue
            # XSS construction sample codes can't use this decorator
            if isinstance(param, Construction) and "XSS" in param.flaws:
                continue
            else:
                param.code[0] = param.code[0].replace("\n", "\n\t")
                param.code[0] = "if(True){\n\t" + param.code[0]
                param.code[-1] += "\n}\n"
        elif d.tag == "loop":
            types = [Construction, Sanitize, ]
            if type(param) not in types:
                continue
            # XSS construction code can't use this decorator
            if isinstance(param, Construction) and "XSS" in param.flaws:
                continue
            else:
                if d.get("type") == "while":
                    param.code[0] = param.code[0].replace("\n", "\n\t")
                    param.code[0] = "\n$loop_cpt=0;\nwhile($loop_cpt++<10){\n\t" + param.code[0]
                    param.code[-1] += "\n}\n"
                elif d.get("type") == "for":
                    param.code[0] = param.code[0].replace("\n", "\n\t")
                    param.code[0] = "\nfor($loop_cpt=0;$loop_cpt<10;$loop_cpt++){\n\t" + param.code[0]
                    param.code[-1] += "\n}\n"
                else:
                    if loop_alert == 0:
                        print("loop type not specified so it will be ignored for " + str(
                            type(param)) + " (possible options: for,while)")
                        loop_alert = 1
        elif d.tag == "function":
            types = [Construction, Sanitize, ]
            if type(param) not in types:
                continue
            if function_alert == 1:
                print("PHP doesn't support functions inside function")
                # continue
            if isinstance(param, Construction) and "XSS" in param.flaws:
                continue
            else:
                # print("source: "+str(params[i].code[-1]))
                var = re.findall("(\$[a-zA-Z_]+) ?= ?.*", param.code[0], re.I)
                # print("sortie: "+str(var)+"\n\n")
                param.code[0] = param.code[0].replace("\n", "\n\t")
                if len(var) > 0:
                    # print("sortie: " + str(var[-1]) + "\n\n")
                    var = var[-1]
                    param.code[-1] += "\n\treturn " + str(var) + ";\n}\n" + str(var) + " = f_function" + str(
                        function_cpt) + "();\n"
                else:
                    param.code[-1] = "\n\treturn " + param.code[-1] + "\n}\n" + "$f_function_var = f_function" + str(
                        function_cpt) + "();\n"
                param.code[0] = "\nfunction f_function" + str(function_cpt) + "(){\n\t" + param.code[0]
                # for line in params[i].code:
                # print(line)
                # print("\n")
                function_cpt += 1
                function_alert = 1
        elif d.tag == "class":
            types = [Construction, Sanitize, ]
            if type(param) not in types:
                continue
            if isinstance(param, Construction) and "XSS" in param.flaws:
                continue
            else:
                # print("source: "+str(params[i].code[-1]))
                var = re.findall("(\$[a-zA-Z_]+) ?= ?.*", param.code[0], re.I)
                param.code[0] = param.code[0].replace("\n", "\n\t\t")
                #print("sortie: "+str(var)+"\n\n")
                param.code[0] = "\nclass f_class" + str(class_cpt) + "{" + \
                                "\n\tprivate $_data;" + \
                                "\n\tpublic function __construct($data){" + \
                                "\n\t\t$this->setData($data);" + \
                                "\n\t}" + \
                                "\n\tpublic function setData($data){" + \
                                "\n\t\t$this->_data = $data;" + \
                                "\n\t}" + \
                                "\n\tpublic function a(){" + \
                                "\n\t\t$tainted = $this->_data;" + \
                                "\n\t\t" + param.code[0]
                if len(var) > 0:
                    #print(var)
                    var = var[-1]
                    param.code[-1] += "\n\t\treturn " + str(var) + ";\n\t}\n}\n" + "$a = new f_class" + str(
                        class_cpt) + "($tainted);\n" + str(var) + " = $a->a();\n"
                else:
                    param.code[-1] = "\n\t\treturn " + param.code[-1] + "\n\t}\n}\n" + "$f_class_var = f_class" + str(
                        class_cpt) + "($tainted);\n"
                #for line in params[i].code:
                #    print(line)
                #print("\n")
                class_cpt += 1
        elif d.tag == "file":
            types = [Construction, Sanitize, InputSample]
            if type(param) not in types:
                continue
            if isinstance(param, Construction) and "XSS" in param.flaws:
                continue
            else:
                file = File()
                file.addContent("<?php ")
                file.addContent(param.code[0])
                file.addContent(" ?>")
                file.setName("include_n" + str(file_cpt))
                param.code[0] = "\ninclude(\"" + file.getName() + "\");\n"
                postOp.append(file)
                file_cpt += 1


options = {
    "construction": f_construction,
    "sanitize": f_sanitize,
    "input": f_input,
}


def initialization(generator, root):
    params = [None] * len(root)
    global decorators
    decorators = [[] for x in range(0, len(root))]
    global function_cpt
    function_cpt = 1
    global class_cpt
    class_cpt = 1
    global file_cpt
    file_cpt = 1
    global postOp
    postOp = []
    generation(generator, root, params)
    return generator.safe_Sample, generator.unsafe_Sample


def generation(generator, root, params, i=0):
    global postOp
    global file_cpt
    global decorators
    if i < len(root):
        pos = root[i]
        while len(pos) > 0:
            decorators[i].append(pos)
            pos = pos[0]
        # print(decorator)
        options[pos.tag](generator, root, params, i)
    else:
        for i in range(0, len(root)):
            f_decorator(params[i], decorators[i])
        # print(params)
        # print(decorators)
        file = generator.generate(params)
        if file is None:
            postOp = []
        while len(postOp) > 0:
            pop = postOp.pop()
            if pop is None:
                break
            if isinstance(pop, File):
                pop.setPath(file.getPath())
                FileManager.createFile(pop)
                #print(pop.getPath()+"/"+pop.getName())




