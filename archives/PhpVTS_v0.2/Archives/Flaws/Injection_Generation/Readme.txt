Code Injection in PHP Sample Generator

CONTENTS
---------
Each directory (SQL, LDAP, XPath) contains

- a packages subdirectory : contains 3 Python files :
						* FinalSample
						* InitialSample
						* Manifest

-  a samples subdirectory : contains various XML files 

- three files :
						*generator.py
						*execQuery.txt
						*rights.txt
------------------------------------------------------


INSTALLATION AND USAGE
----------------------
A Python installation is needed to run the generator. It can be found here : http://www.python.org/download/ (Python 3.3.3 or later).
After the installation, run generator.py, which will generate the samples in a directory called generation.
Generation directory will be created in the same directory where the generator.py is.
------------------------------------------------------


DESCRIPTION
-----------
**FinalSample**    Used by generator.py to generate samples presenting a flaw
**InitialSample**  Used by generator.py to build the structure from the XML files
**Manifest**       Used by generator.py to build the manifest.xml file describing all the generated samples

**Samples directory** Contains XML files describing techniques to produce code injection.

**generator**      Core of the program. Builds samples.
**execQuery**      Contains part of the code used to execute a query.
**rights**		   Contains copyright text inserted on the top of each generated file.
-------------------------------------------------------


SELECTIVE GENERATION
--------------------

It is possible to generate selectively samples, based on their relevancy. Doing so, it will be easier to find samples with common vulnerabilities inside the samples generated. 
Each techniques comes with a coefficient, set to :
	* 1 if the technique is common
	* 0.5 if the technique is uncommon
	* 0.25 if the technique is really tricky
When it comes to generation, each combination of several techniques calculates the relevancy of the file generated, which is the multiplication between all relevancy coefficients from the techniques in the generated samples. Each file with a final coefficient under a settable is not generated.
This value can be set using the option -r when running the program with a command line, or by changing it manually into packages/FinalSample by modifying value of select parameter at line 3 (initially, the value is 0).
-------------------------------------------------------


FALSE POSITIVES AND NEGATIVES DETECTION
---------------------------------------

It is possible to generate safe/unsafe files into two separate folders, to make false positives and false negatives detection easier. Use the option -o (or --order) when running the program with a command line to do so, or by removing comment symbols at line 5.
 

