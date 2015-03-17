<?php
/*Safe sample
construction : interpretation
input : get the $_GET['course_id'] in an array
sanitize : get course_id allowed to the user and put them in a table. get an indirect ID from the user and with it retrieve the course_id from the table*/

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

//preparation to the indirect reference
$course_array=array();

//get the user id
$user_id = intval($_SESSION[‘user_id’]);

$conn = mysql_connect('localhost', 'mysql_user', 'mysql_password'); // Connection to the database (address, user, password)

//creation of the references with only data allowed to the user
$result = mysql_query("SELECT * FROM COURSE where course.allowed = {$user_id}");

while ($row = mysql_fetch_array($result)){
	$course_array[] = $result[‘course_id’];
}


$_SESSION[‘course_array’] = $course_array;
if (isset($_SESSION[‘course_array’])){
	$course_array = $_SESSION[‘course_array’];
	
	//get the data
	$fake_id = intval($_GET[‘id’]);
	
	if (isset($course_array[$fake_id])){
	
		//indirect reference > get the right id
		$course_id = $course_array[$fake_id];
		
		//put it in the query
		$query = "SELECT * FROM COURSE WHERE courseID={$course_id}"
		
		$res = mysql_query($query); //execution
		
	}
}
mysql_close($conn);
?>