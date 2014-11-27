import xml.etree.ElementTree as ET
import os
import sys

def main(argv) :
    tree_file = ET.parse('file.xml').getroot()
    if tree_file.find("code") is  None :
        print("Hello")

if __name__ == "__main__":
   main(sys.argv[1:])
