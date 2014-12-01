<?php 
/*Unsafe sample
construction : no right verification
input : reads the field UserData from the variable $_GET
sanitize : NONE */

/*COPYRIGHT 2014 TN*/


$taintedId = $_GET['id'];
 
$query = "SELECT * FROM COURSE where id=' $checked_data '";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$res = mysql_query($query); 
mysql_close($conn);

 ?>