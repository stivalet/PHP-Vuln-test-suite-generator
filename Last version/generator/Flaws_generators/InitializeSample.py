import os
import sys
import time
import getopt

# Constants
safe = "safe"
unsafe = "unsafe"
needQuote = "needQuote"
quote = "quote"
noQuote = "noQuote"
integer = "int"
safety = "safety"
# block = "block"
# noBlock = "noBlock"
prepared = "prepared"
noPrepared = "noPrepared"
needUrlSafe = "needUrlSafe"
urlSafe = "urlSafe"
needErrorSafe = "needErrorSafe"
errorSafe = "errorSafe"


class InitialSample:  # Initialize path,comment and relevancy parameters
    # compatible with new structure
    def __init__(self, initialSample):  # XML tree in parameter
        self.path = []
        tree_path = initialSample.find("path").findall("dir")
        for dir in tree_path:
            self.path.append(dir.text)

        self.comment = initialSample.find("comment").text
        self.relevancy = float(initialSample.find("relevancy").text)

    def addSafetyAttributes(self, initialSample):
        # Classify XSS injection/sanitization by rule of OWASP
        safeties = initialSample.find("safeties").findall("safety")
        for safety in safeties:
            if "XSS" in safety.get("flawType"):
                # Rule of sanitizing needed
                self.safeties[safety.get("flawType")]["rule"] = 0
                if safety.get("rule") is not None:
                    self.safeties[safety.get("flawType")]["rule"] = int(safety.get("rule"))

                # Escaping simple quoted is enough ?
                self.safeties[safety.get("flawType")]["simpleQuote"] = 0
                if safety.get("simpleQuote") is not None:
                    self.safeties[safety.get("flawType")]["simpleQuote"] = int(safety.get("simpleQuote"))

                # Escaping double quoted is enough ?
                self.safeties[safety.get("flawType")]["doubleQuote"] = 0
                if safety.get("doubleQuote") is not None:
                    self.safeties[safety.get("flawType")]["doubleQuote"] = int(safety.get("doubleQuote"))

                # Unsafe function & co
                self.safeties[safety.get("flawType")]["unsafe"] = 0
                if safety.get("unsafe") is not None:
                    self.safeties[safety.get("flawType")]["unsafe"] = int(safety.get("unsafe"))

                # Escape of type " -> \" needed ? (TODO : improve that)
                self.safeties[safety.get("flawType")]["escape"] = 0
                if safety.get("escape") is not None:
                    self.safeties[safety.get("flawType")]["escape"] = int(safety.get("escape"))

                # Escape of </script> needed ?
                self.safeties[safety.get("flawType")]["scriptBlock"] = 0
                if safety.get("scriptBlock") is not None:
                    self.safeties[safety.get("flawType")]["scriptBlock"] = int(safety.get("scriptBlock"))

                # Escape of </style> needed ?
                self.safeties[safety.get("flawType")]["styleBlock"] = 0
                if safety.get("styleBlock") is not None:
                    self.safeties[safety.get("flawType")]["styleBlock"] = int(safety.get("styleBlock"))

                # Prevent data from starting with "javascript" needed ?
                self.safeties[safety.get("flawType")]["URL_CSS_context"] = 0
                if safety.get("URL_CSS_context") is not None:
                    self.safeties[safety.get("flawType")]["URL_CSS_context"] = int(safety.get("URL_CSS_context"))

                # Prevent data from starting with "expression" needed ?
                self.safeties[safety.get("flawType")]["property_CSS_context"] = 0
                if safety.get("property_CSS_context") is not None:
                    self.safeties[safety.get("flawType")]["property_CSS_context"] = int(safety.get("property_CSS_context"))


class InputSample(InitialSample):  # Initialize the type of input and the code parameters of the class
    # compatible with new structure
    def __init__(self, initialSample):  # XML tree in parameter
        InitialSample.__init__(self, initialSample)
        self.inputType = initialSample.find("inputType").text
        self.code = initialSample.find("code").text


class Sanitize(InitialSample):  # Initialize rules, safety, code and escape
    # new version for new XML
    def __init__(self, initialSample):  # XML tree in parameter
        InitialSample.__init__(self, initialSample)
        self.flaws = []
        tree_flaw = initialSample.find("flaws").findall("flaw")
        for flaw in tree_flaw:
            self.flaws.append(flaw.text)

        self.code = []
        tree_code = initialSample.find("codes").findall("code")
        for code in tree_code:
            self.code.append(code.text)

        self.safeties = {}
        tree_safeties = initialSample.find("safeties").findall("safety")
        for safety in tree_safeties:
            # print("S: " + safety.get("flawType"))
            self.safeties[safety.get("flawType")] = {}
            self.safeties[safety.get("flawType")]["safe"] = 0
            self.safeties[safety.get("flawType")]["needQuote"] = 0
            self.safeties[safety.get("flawType")]["noQuote"] = 0
            self.safeties[safety.get("flawType")]["urlSafe"] = 0
            self.safeties[safety.get("flawType")]["errorSafe"] = 0

            if "XSS" in safety.get("flawType"):
                # Universal safe sanitizing (Cast & co)

                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))

                # Rule that can be always sanitize (/!\ Format)
                self.safeties[safety.get("flawType")]["rule1"] = 0
                self.safeties[safety.get("flawType")]["rule2"] = 0
                self.safeties[safety.get("flawType")]["rule3"] = 0
                self.safeties[safety.get("flawType")]["rule4"] = 0
                self.safeties[safety.get("flawType")]["rule5"] = 0

                if safety.get("rule1") is not None:
                    self.safeties[safety.get("flawType")]["rule1"] = int(safety.get("rule1"))
                if safety.get("rule2") is not None:
                    self.safeties[safety.get("flawType")]["rule2"] = int(safety.get("rule2"))
                if safety.get("rule3") is not None:
                    self.safeties[safety.get("flawType")]["rule3"] = int(safety.get("rule3"))
                if safety.get("rule4") is not None:
                    self.safeties[safety.get("flawType")]["rule4"] = int(safety.get("rule4"))
                if safety.get("rule5") is not None:
                    self.safeties[safety.get("flawType")]["rule5"] = int(safety.get("rule5"))

                self.addSafetyAttributes(initialSample)

            elif "Injection" in safety.get("flawType"):
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                if safety.get("needQuote") is not None:
                    self.safeties[safety.get("flawType")]["needQuote"] = int(safety.get("needQuote"))
                #elif safety.get("needQuote") == "-1":
                #    self.safeties[safety.get("flawType")]["noQuote"] = noQuote
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "IDOR" in safety.get("flawType"):
                #self.safe = safe if safety.get("safe") == "1" else unsafe
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "URF" in safety.get("flawType"):
                if safety.get("urlSafe") is not None:
                    self.safeties[safety.get("flawType")]["urlSafe"] = int(safety.get("urlSafe"))
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                if safety.get("needQuote") is not None:
                    self.safeties[safety.get("flawType")]["needQuote"] = int(safety.get("needQuote"))
                #elif safety.get("needQuote") == "-1":
                #    self.safeties[safety.get("flawType")]["noQuote"] = noQuote
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "SM" in safety.get("flawType"):
                if safety.get("errorSafe") is not None:
                    self.safeties[safety.get("flawType")]["errorSafe"] = int(safety.get("errorSafe"))
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe
                #self.isSafe = safe if safety.get("safe") == "1" else unsafe

            elif "SDE" in safety.get("flawType"):
                #self.safe = safe if safety.get("safe") == "1" else unsafe
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

        constraints = initialSample.find("constraints").findall("constraint")
        for constraint in constraints:
            if "Injection" in constraint.get("flawType"):
                self.constraintType = constraint.get("type")
                self.constraintField = constraint.get("field")
            if "URF" in constraint.get("flawType"):
                self.constraintType = constraint.get("type")
                self.constraintField = constraint.get("field")
                # if "IDOR" in constraint.get("flawType"):
                # self.isBlock = block if safety.find("block") == "1" else noBlock


class Construction(InitialSample):  # Load parameters and code beginning and end
    # new version for new XML
    def __init__(self, initialSample):  # Add parameters showing the beginning and the end of the sample
        InitialSample.__init__(self, initialSample)

        self.flaws = []
        tree_flaw = initialSample.find("flaws").findall("flaw")
        for flaw in tree_flaw:
            self.flaws.append(flaw.text)

        self.code = []
        tree_code = initialSample.find("codes").findall("code")
        for code in tree_code:
            self.code.append(code.text)

        self.safeties = {}
        tree_safeties = initialSample.find("safeties").findall("safety")
        for safety in tree_safeties:
            # print("F: " + safety.get("flawType"))
            self.safeties[safety.get("flawType")] = {}
            self.safeties[safety.get("flawType")]["safe"] = 0
            self.safeties[safety.get("flawType")]["quote"] = 0
            self.safeties[safety.get("flawType")]["needUrlSafe"] = 0
            self.safeties[safety.get("flawType")]["needErrorSafe"] = 0

            if "XSS" in safety.get("flawType"):
                # Universal safe sanitizing (Cast & co)
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))

                # Rule that can be always sanitize (/!\ Format)
                self.safeties[safety.get("flawType")]["rule1"] = 0
                self.safeties[safety.get("flawType")]["rule2"] = 0
                self.safeties[safety.get("flawType")]["rule3"] = 0
                self.safeties[safety.get("flawType")]["rule4"] = 0
                self.safeties[safety.get("flawType")]["rule5"] = 0

                if safety.get("rule1") is not None:
                    self.safeties[safety.get("flawType")]["rule1"] = int(safety.get("rule1"))
                if safety.get("rule2") is not None:
                    self.safeties[safety.get("flawType")]["rule2"] = int(safety.get("rule2"))
                if safety.get("rule3") is not None:
                    self.safeties[safety.get("flawType")]["rule3"] = int(safety.get("rule3"))
                if safety.get("rule4") is not None:
                    self.safeties[safety.get("flawType")]["rule4"] = int(safety.get("rule4"))
                if safety.get("rule5") is not None:
                    self.safeties[safety.get("flawType")]["rule5"] = int(safety.get("rule5"))
                self.addSafetyAttributes(initialSample)

            elif "Injection" in safety.get("flawType"):
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                if safety.get("quote") is not None:
                    self.safeties[safety.get("flawType")]["quote"] = int(safety.get("quote"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "IDOR" in safety.get("flawType"):
                #self.safe = safe if safety.get("safe") == "1" else unsafe
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #   self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "URF" in safety.get("flawType"):
                if safety.get("needUrlSafe") is not None:
                    self.safeties[safety.get("flawType")]["needUrlSafe"] = int(safety.get("needUrlSafe"))
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                if safety.get("needQuote") is not None:
                    self.safeties[safety.get("flawType")]["quote"] = int(safety.get("quote"))
                #elif safety.get("needQuote") == "-1":
                #    self.safeties[safety.get("flawType")]["noQuote"] = noQuote
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

            elif "SM" in safety.get("flawType"):
                if safety.get("needErrorSafe") is not None:
                    self.safeties[safety.get("flawType")]["needErrorSafe"] = int(safety.get("needErrorSafe"))
                if safety.get("safe")is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe
                #self.isSafe = safe if safety.get("safe") == "1" else unsafe

            elif "SDE" in safety.get("flawType"):
                #self.safe = safe if safety.get("safe") == "1" else unsafe
                if safety.get("safe") is not None:
                    self.safeties[safety.get("flawType")]["safe"] = int(safety.get("safe"))
                #else:
                #    self.safeties[safety.get("flawType")]["unsafe"] = unsafe

        constraints = initialSample.find("constraints").findall("constraint")
        for constraint in constraints:
            if "Injection" in constraint.get("flawType"):
                self.constraintType = constraint.get("type")
                self.constraintField = constraint.get("field")
            if "IDOR" in constraint.get("flawType"):
                self.prepared = prepared if constraint.find("prepared") == "1" else noPrepared
            if "URF" in constraint.get("flawType"):
                self.constraintType = constraint.get("type")
                self.constraintField = constraint.get("field")