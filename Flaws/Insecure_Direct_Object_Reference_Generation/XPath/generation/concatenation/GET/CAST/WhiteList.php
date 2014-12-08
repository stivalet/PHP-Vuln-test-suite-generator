<?php 
/*Safe sample
construction : concatenation
input : reads the field UserData from the variable $_GET and uses intval() function
sanitize : uses of a WhiteList */

/*COPYRIGHT 2014 TN*/


$tainted = intval($_GET['id']);
$whitelist =  array("4", "8", "15", "16", "23", "42");
if (in_array($tainted, $whitelist, true)) {
$checked_data = $tainted;
} else {
$checked_data = $whitelist[0];
}
$query="//Course[@id=". $checked_data . "]";

$xml = simplexml_load_file("users.xml");
//flaw
$res=$xml->xpath($query);

?>