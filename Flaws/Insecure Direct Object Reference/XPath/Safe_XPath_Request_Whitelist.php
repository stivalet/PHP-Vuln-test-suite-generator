<?php

/*Safe sample
construction : concatenation
input : get the $_GET['course_id'] in an array
sanitize : check if the course_id is in a safe whitelist*/

/*Copyright 2014 Herve BUHLER, David LUCAS, Fabien NOLLET, Axel RESZETKO

Permission is hereby granted, without written agreement or royalty fee, to

use, copy, modify, and distribute this software and its documentation for

any purpose, provided that the above copyright notice and the following

three paragraphs appear in all copies of this software.


IN NO EVENT SHALL AUTHORS BE LIABLE TO ANY PARTY FOR DIRECT,

INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE 

USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF AUTHORS HAVE

BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


AUTHORS SPECIFICALLY DISCLAIM ANY WARRANTIES INCLUDING, BUT NOT

LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A

PARTICULAR PURPOSE, AND NON-INFRINGEMENT.


THE SOFTWARE IS PROVIDED ON AN "AS-IS" BASIS AND AUTHORS HAVE NO

OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR

MODIFICATIONS.*/

$xml = simplexml_load_file("courses.xml");//file load

$tainted = $_GET['course_id'];//get the data

//compare to a whitelist
$whitelist =  array("4", "8", "15", "16", "23", "42");
if (in_array($tainted, $whitelist, true)) {
$checked_data = $tainted;
} else {
	$checked_data = $whitelist[0];
}

$query="//Course[@id=". $checked_data . "]";//query construction

$res=$xml->xpath($query);//execution
?>