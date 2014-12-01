<?php 
/*Safe sample
construction : no right verification
input : reads the field UserData from the variable $_GET
sanitize : uses a whitelist */

/*COPYRIGHT 2014 TN*/


$taintedId = $_GET['id'];
$whitelist =  array("4", "8", "15", "16", "23", "42");
if (in_array($tainted, $whitelist, true)) {
  $checked_data = $tainted;
} else {
  $checked_data = $whitelist[0];
}
$query = "SELECT * FROM COURSE where id=' $checked_data '";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$res = mysql_query($query); 
mysql_close($conn);

 ?>