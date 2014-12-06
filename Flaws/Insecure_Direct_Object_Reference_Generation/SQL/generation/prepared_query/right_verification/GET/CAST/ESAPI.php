<?php 
/*Safe sample
construction : prepared query and right verification
input : reads the field UserData from the variable $_GET and uses intval() function
sanitize : uses of ESAPI, an OWASP API */

/*COPYRIGHT 2014 TN*/


$taintedId = intval($_GET[‘id’]);
$ESAPI = new ESAPI();
ESAPI::setEncoder(new DefaultEncoder());
ESAPI::setValidator(new DefaultValidator());

//verifying the data with ESAPI
if($ESAPI->validator->isValidNumber("Course ID", $taintedId, 18, 25, false)) {
    $checked_data=$taintedId;
// query + connexion/execute/deco
//}
$query = "SELECT * FROM COURSE, USER WHERE courseID=?";
$query .= "AND course.allowed=$_SESSION[userid]";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $checked_data)
$stmt->execute()
mysql_close($conn);
}

 ?>