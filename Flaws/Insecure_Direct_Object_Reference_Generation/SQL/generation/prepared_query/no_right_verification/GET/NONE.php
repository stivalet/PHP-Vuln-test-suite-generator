<?php 
/*Unsafe sample
construction : prepared query and no right verification
input : reads the field UserData from the variable $_GET
sanitize : NONE */

/*COPYRIGHT 2014 TN*/


$taintedId = $_GET['id'];
 
$query = "SELECT * FROM COURSE WHERE id=?";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $checked_data)
$stmt->execute()
mysql_close($conn);

 ?>