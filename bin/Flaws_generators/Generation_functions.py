import xml.etree.ElementTree as ET
import re
import copy

from .InitializeSample import *
from Classes.FileManager import *
from Classes.File import *
import global_variables as g


def cwe_test(first_intersection):
    if len(g.cwe_list) == 0:
        return first_intersection
    first_intersection_cwe = []
    for cwe in first_intersection:
        first_intersection_cwe.append(re.findall("_([0-9]+)_", cwe)[0])
    if set(g.cwe_list).intersection(first_intersection_cwe):
        return True
    return False


def f_construction(generator, root, params, i):
    global decorators
    tree_construction = ET.parse(FileManager.getXML("construction")).getroot()
    for c in tree_construction:
        params[i] = Construction(c)
        if cwe_test(set(generator.getType()).intersection(params[i].flaws)):
            generation(generator, root, params, i + 1)
    decorators[i] = []


def f_sanitize(generator, root, params, i):
    global decorators
    tree_sanitize = ET.parse(FileManager.getXML("sanitize")).getroot()
    for s in tree_sanitize:
        params[i] = Sanitize(s)
        if cwe_test(set(generator.getType()).intersection(params[i].flaws)):
            generation(generator, root, params, i + 1)
    decorators[i] = []


def f_input(generator, root, params, i):
    global decorators
    tree_input = ET.parse(FileManager.getXML("input")).getroot()
    for Input in tree_input:
        params[i] = InputSample(Input)
        generation(generator, root, params, i + 1)
    decorators[i] = []


def f_decorator(params, decorators, i):
    loop_alert = 0
    global function_cpt
    function_alert = 0
    global class_cpt
    global file_cpt
    global postOp
    previous=None
    # print(decorators)
    for d in reversed(decorators[i]):
        if d.get("type") == "if":
            types = [Construction, Sanitize, InputSample]
            if type(params[i]) not in types:
                continue
            # XSS construction sample codes can't use this decorator
            if isinstance(params[i], Construction) and "CWE_79_XSS" in params[i].flaws:
                continue
            if "function" in params[i].code or "class" in params[i].code:
                continue
            params[i].code[0] = params[i].code[0].replace("\n", "\n\t")
            params[i].code[0] = "if(True){\n\t" + params[i].code[0] + "\n}\n"
        elif d.get("type") == "loop":
            types = [Construction, Sanitize, InputSample]
            if type(params[i]) not in types:
                continue
            # XSS construction code can't use this decorator
            if isinstance(params[i], Construction) and "CWE_79_XSS" in params[i].flaws:
                continue
            if "function" in params[i].code or "class" in params[i].code:
                continue
            if d.get("kind") == "while":
                params[i].code[0] = params[i].code[0].replace("\n", "\n\t")
                params[i].code[0] = "\n$loop_cpt=0;\nwhile($loop_cpt++<10){\n\t" + params[i].code[0]
                params[i].code[-1] += "\n}\n"
            elif d.get("kind") == "for":
                params[i].code[0] = params[i].code[0].replace("\n", "\n\t")
                params[i].code[0] = "\nfor($loop_cpt=0;$loop_cpt<10;$loop_cpt++){\n\t" + params[i].code[0]
                params[i].code[-1] += "\n}\n"
            else:
                if loop_alert == 0:
                    print("loop type not specified so it will be ignored for " + str(
                        type(params[i])) + " (possible options: for,while)")
                    loop_alert = 1
        elif d.get("type") == "function":
            types = [Construction, Sanitize, InputSample]
            if type(params[i]) not in types:
                continue
            if isinstance(params[i], Construction) and "CWE_79_XSS" in params[i].flaws:
                continue
            if previous is not None and previous.tag in ["function", "class"]:
                print("you can't instantiate function in loop/conditional/function/class structures")
                exit(1)
            else:
                # print("source: "+str(params[i]s[i].code[-1]))
                var = re.findall("(\$[a-zA-Z_]+) ?= ?.*", params[i].code[0], re.I)
                # print("sortie: "+str(var)+"\n\n")
                params[i].code[0] = params[i].code[0].replace("\n", "\n\t")
                name = ""
                for param in params:
                    for dir in param.path:
                        name += dir
                if len(var) > 0:
                    # print("sortie: " + str(var[-1]) + "\n\n")
                    var = var[-1]
                    params[i].code[-1] += "\n\treturn " + str(var) + ";\n}\n" + str(var) + " = " + name + "_function" + str(
                        function_cpt) + "($tainted);\n"
                else:
                    params[i].code[-1] += "\n}\n" + "$f_function_var = " + name + "_function" + str(function_cpt) + "($tainted);\n"
                params[i].code[0] = "\nfunction "+ name + "_function" + str(function_cpt) + "($tainted){\n\t" + params[i].code[0]
                # for line in params[i]s[i].code:
                # print(line)
                # print("\n")
                function_cpt += 1
                function_alert = 1
        elif d.get("type") == "class":
            types = [Construction, Sanitize, InputSample]
            if type(params[i]) not in types:
                continue
            if isinstance(params[i], Construction) and "CWE_79_XSS" in params[i].flaws:
                continue
            if previous is not None and previous.tag in ["loop", "if", "function", "class"]:
                print("you can't instantiate class in loop/conditional/function/class structures")
                exit(1)
            else:
                # print("source: "+str(params[i]s[i].code[-1]))
                var = re.findall("(\$[a-zA-Z_]+) ?= ?.*", params[i].code[0], re.I)
                params[i].code[0] = params[i].code[0].replace("\n", "\n\t\t")
                #print("sortie: "+str(var)+"\n\n")
                name = ""
                for param in params:
                    for dir in param.path:
                        name += dir
                params[i].code[0] = "\nclass " + name + "_class" + str(class_cpt) + "{" + \
                                "\n\tprivate $_data;" + \
                                "\n\tpublic function __construct($data){" + \
                                "\n\t\t$this->setData($data);" + \
                                "\n\t}" + \
                                "\n\tpublic function setData($data){" + \
                                "\n\t\t$this->_data = $data;" + \
                                "\n\t}" + \
                                "\n\tpublic function a(){" + \
                                "\n\t\t$tainted = $this->_data;" + \
                                "\n\t\t" + params[i].code[0]
                if len(var) > 0:
                    #print(var)
                    var = var[-1]
                    params[i].code[-1] += "\n\t\treturn " + str(var) + ";\n\t}\n}\n" + "$a = new f_class" + str(
                        class_cpt) + "($tainted);\n" + str(var) + " = $a->a();\n"
                else:
                    params[i].code[-1] += "\n\t}\n}\n" + "$f_class_var = f_class" + str(class_cpt) + "($tainted);\n"
                class_cpt += 1
        elif d.get("type") == "file":
            types = [Construction, Sanitize, InputSample]
            if type(params[i]) not in types:
                continue
            if isinstance(params[i], Construction) and "CWE_79_XSS" in params[i].flaws:
                continue
            else:
                file = File()
                file.addContent("<?php\n")
                header = open("./rights_PHP.txt", "r")
                copyright = header.readlines()
                for line in copyright:
                    file.addContent(line)
                file.addContent(params[i].code[0])
                file.addContent("\n?>")
                name=""
                for param in params:
                    if isinstance(param, Construction):
                        for param2 in params:
                            if isinstance(param2, Sanitize):
                                for value in set(param.flaws).intersection(param2.flaws):
                                    name=value
                for param in params:
                    name += "__"
                    for dir in param.path:
                        name += dir+"-"
                    name = name[:-1]
                type_param=""
                if isinstance(params[i],InputSample):
                    type_param="input"
                elif isinstance(params[i],Sanitize):
                    type_param="sanitize"
                elif isinstance(params[i],Construction):
                    type_param="construction"
                file.setName(name+"__"+type_param+"_"+str(file_cpt))
                params[i].code[0] = "\ninclude_once(\"" + file.getName() + "\");\n"
                postOp.append(file)
                file_cpt += 1
        previous = d


options = {
    "construction": f_construction,
    "sanitize": f_sanitize,
    "input": f_input,
}


def initialization(generator, root):
    params = [None] * len(root)
    global decorators
    decorators = [[] for x in range(0, len(root))]
    global postOp
    postOp = []
    generation(generator, root, params)
    return generator.safe_Sample, generator.unsafe_Sample


def generation(generator, root, params, i=0):
    global postOp
    global decorators
    global function_cpt
    function_cpt = 1
    global class_cpt
    class_cpt = 1
    global file_cpt
    file_cpt = 1
    if i < len(root):
        pos = root[i]
        while len(pos) > 0:
            decorators[i].append(pos)
            pos = pos[0]
        # print(decorator)
        options[pos.tag](generator, root, params, i)
    else:
        tmp=copy.deepcopy(params)
        for i in range(0, len(root)):
            f_decorator(tmp, decorators, i)
        # print(params)
        # print(decorators)
        file = generator.generate(tmp)
        if file is None:
            postOp = []
        while len(postOp) > 0:
            pop = postOp.pop()
            if pop is None:
                break
            if isinstance(pop, File):
                pop.setPath(file.getPath())
                FileManager.createFile(pop)
                file_cpt -= 1
                #print(pop.getPath()+"/"+pop.getName())



