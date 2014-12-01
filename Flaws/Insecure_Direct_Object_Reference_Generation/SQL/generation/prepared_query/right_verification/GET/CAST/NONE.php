<?php 
/*Safe sample
construction : prepared query and right verification
input : reads the field UserData from the variable $_GET and uses intval() function
sanitize : NONE */

/*COPYRIGHT 2014 TN*/


$taintedId = intval($_GET[‘id’]);
 
$query = "SELECT * FROM COURSE, USER WHERE courseID=?";
$query .= "AND course.allowed=$_SESSION[userid]";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $checked_data)
$stmt->execute()
mysql_close($conn);

 ?>