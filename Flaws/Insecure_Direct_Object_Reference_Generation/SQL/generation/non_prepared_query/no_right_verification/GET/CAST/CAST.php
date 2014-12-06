<?php 
/*Unsafe sample
construction : no right verification
input : reads the field UserData from the variable $_GET and uses intval() function
sanitize : cast into int */

/*COPYRIGHT 2014 TN*/


$taintedId = intval($_GET[‘id’]);
$checked_data =  (int) $tainted ;
$query = "SELECT * FROM COURSE where id=' $checked_data '";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$res = mysql_query($query); 
mysql_close($conn);

 ?>