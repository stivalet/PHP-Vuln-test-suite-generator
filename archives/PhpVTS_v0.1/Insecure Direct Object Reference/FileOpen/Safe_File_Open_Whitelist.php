<?php

/*Safe sample
construction : -
input : get the $_GET['data'] in an array, avoiding injection with a preg_replace
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


$tainted = $_GET['data'];

//sanitize the string
/*replace all non alphabetical, numerical, _, - characters by the character _

preg_replace("/[a-z0-9_-]/", "_",$var); > in $var replace all characters from a to z, from 0 to 9, _ and - with _
i after the /[...]/ is for "insensitive" to match both lowercase and uppercase
^ before the characters is to negate the pattern
*/
$tainted = preg_replace("/[^a-z0-9_-]/i", "_", $tainted);

//use a whitelist to prevent unauthorized data to enter the system
$whitelist =  array("file1", "file2");
if (in_array($tainted, $whitelist, true)) {
	$checked_data = $tainted;
} else {
	$checked_data = $whitelist[0];
}

fopen($checked_data, "r");
?>