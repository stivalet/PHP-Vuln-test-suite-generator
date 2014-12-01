<?php 
/*Safe sample
construction : no right verification
input : reads the field UserData from the variable $_GET
sanitize : uses of ESAPI, an OWASP API */

/*COPYRIGHT 2014 TN*/


$taintedId = $_GET['id'];
$ESAPI = new ESAPI();
ESAPI::setEncoder(new DefaultEncoder());
ESAPI::setValidator(new DefaultValidator());

//verifying the data with ESAPI
if($ESAPI->validator->isValidNumber("Course ID", $taintedId, 18, 25, false)) {
    $checked_data=$taintedId;
// query + connexion/execute/deco
//}
$query = "SELECT * FROM COURSE where id=' $checked_data '";

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)
$res = mysql_query($query); 
mysql_close($conn);
}

 ?>