<?php 
/*Safe sample
construction : right verification
input : reads the field UserData from the variable $_GET and uses intval() function
sanitize : NONE */

/*COPYRIGHT 2014 TN*/


$taintedId = intval($_GET[‘id’]);
 
$query = "SELECT * FROM COURSE, USER WHERE courseID='$checked_data'";
$query .= "AND course.allowed=$_SESSION[userid]";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$res = mysql_query($query); 
mysql_close($conn);

 ?>