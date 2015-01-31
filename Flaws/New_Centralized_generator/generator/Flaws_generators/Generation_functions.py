import xml.etree.ElementTree as ET
import re
from .InitializeSample import *


def f_construction(generator, root, params, i):
    tree_construction = ET.parse(generator.fileManager.getXML("construction")).getroot()
    for c in tree_construction:
        params[i] = Construction(c)
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


# if decorator
def f_if(generator, root, params, i):
    type = {"construction": lambda sample: Construction(sample),
            "sanitize": lambda sample: Sanitize(sample),
    }
    if root[i][0].tag not in type:
        options[root[i][0].tag](generator, root, params, i)
        return
    # print(root[i][0].tag)
    tree = ET.parse(generator.fileManager.getXML(root[i][0].tag)).getroot()
    for leaf in tree:
        params[i] = type[root[i][0].tag](leaf)

        # XSS construction code can't use this decorator
        if isinstance(params[i], Construction) and "XSS" not in params[i].flaws:
            params[i].code[0] = "if(True){\n\t" + params[i].code[0]
            params[i].code[-1] += "\n}\n"
            #for line in params[i].code:
            #    print(line)
            #print("\n")
            generation(generator, root, params, i + 1)


def f_loop(generator, root, params, i):
    global f_loop_alert
    type = {"construction": lambda sample: Construction(sample),
            "sanitize": lambda sample: Sanitize(sample),
    }
    if root[i][0].tag not in type:
        options[root[i][0].tag](generator, root, params, i)
        return
    # print(root[i][0].tag)
    tree = ET.parse(generator.fileManager.getXML(root[i][0].tag)).getroot()
    for leaf in tree:
        params[i] = type[root[i][0].tag](leaf)

        # XSS construction code can't use this decorator
        if "XSS" in generator.getType() and "XSS" in params[i].flaws:
            continue
        else:
            if root[i].get("type")=="while":
                params[i].code[0] = "\n$loop_cpt=0;\nwhile($loop_cpt++<10){\n\t" + params[i].code[0]
                params[i].code[-1] += "\n}\n"
            elif root[i].get("type")=="for":
                params[i].code[0] = "\nfor($loop_cpt=0;$loop_cpt<10;$loop_cpt++){\n\t" + params[i].code[0]
                params[i].code[-1] += "\n}\n"
            else:
                if f_loop_alert==0:
                    print("loop type not specified so it will be ignored for " + root[i][0].tag + " (possible options: for,while)")
                    f_loop_alert=1
                pass
            #for line in params[i].code:
            #    print(line)
            #print("\n")
            generation(generator, root, params, i + 1)


def f_function(generator, root, params, i):
    global f_function_cpt
    type = {"construction": lambda sample: Construction(sample),
            "sanitize": lambda sample: Sanitize(sample),
    }
    if root[i][0].tag not in type:
        options[root[i][0].tag](generator, root, params, i)
        return
    # print(root[i][0].tag)
    tree = ET.parse(generator.fileManager.getXML(root[i][0].tag)).getroot()
    for leaf in tree:
        params[i] = type[root[i][0].tag](leaf)
        #print("source: "+str(params[i].code[-1]))
        var = re.search("^(\$[^ ]+)", params[i].code[-1], re.I)
        #print("sortie: "+str(var)+"\n\n")
        params[i].code[0] = "\nfunction f_function" + str(f_function_cpt) + "(){\n\t" + params[i].code[0]
        if var is not None:
            var=var.group(1)
            params[i].code[-1] += "\n\treturn " + str(var) + ";\n}\n" + str(var) + " = f_function" + str(f_function_cpt) + "();\n"
        else:
            params[i].code[-1] = "\n\treturn " + params[i].code[-1] + "\n}\n" + "$f_function_var = f_function" + str(f_function_cpt) + "();\n"
        #for line in params[i].code:
        #    print(line)
        #print("\n")
        f_function_cpt+=1
        generation(generator, root, params, i + 1)
        f_function_cpt-=1

def f_class(generator, root, params, i):
    global f_class_cpt
    type = {"construction": lambda sample: Construction(sample),
            "sanitize": lambda sample: Sanitize(sample),
    }
    if root[i][0].tag not in type:
        options[root[i][0].tag](generator, root, params, i)
        return
    # print(root[i][0].tag)
    tree = ET.parse(generator.fileManager.getXML(root[i][0].tag)).getroot()
    for leaf in tree:
        params[i] = type[root[i][0].tag](leaf)
        #print("source: "+str(params[i].code[-1]))
        var = re.search("^(\$[^ ]+)", params[i].code[-1], re.I)
        #print("sortie: "+str(var)+"\n\n")
        params[i].code[0] = "\nclass f_class" + str(f_class_cpt) + "{" + \
                            "\n\tprivate $_data;" + \
                            "\n\tpublic function __construct($data){" + \
                            "\n\t\t$this->setData($data);" + \
                            "\n\t}" + \
                            "\n\tpublic function setData($data){" + \
                            "\n\t\t$this->_data = $data;" + \
                            "\n\t}" + \
                            "\n\tpublic function a(){" + \
                            "\n\t\t" + params[i].code[0]
        if var is not None:
            var=var.group(1)
            params[i].code[-1] += "\n\t\treturn " + str(var) + ";\n\t}\n}\n" + "$a = new f_class" + str(f_class_cpt) + "($tainted);\n" + str(var) + " = $a->a();\n"
        else:
            params[i].code[-1] = "\n\t\treturn " + params[i].code[-1] + "\n\t}\n}\n" + "$f_class_var = f_class" + str(f_class_cpt) + "($tainted);\n"
        #for line in params[i].code:
        #    print(line)
        #print("\n")
        f_class_cpt+=1
        generation(generator, root, params, i + 1)
        f_class_cpt-=1


options = {
    "construction": f_construction,
    "sanitize": f_sanitize,
    "input": f_input,
    "if": f_if,
    "loop": f_loop,
    "function": f_function,
    "class": f_class,
}


def initialization(generator, root):
    params = [None] * len(root)
    global f_loop_alert
    f_loop_alert=0
    global f_function_cpt
    f_function_cpt=1
    global f_class_cpt
    f_class_cpt=1
    generation(generator, root, params)
    return [generator.safe_Sample, generator.unsafe_Sample]


def generation(generator, root, params, i=0):
    if i < len(root):
        options[root[i].tag](generator, root, params, i)
    else:
        generator.generate(params)