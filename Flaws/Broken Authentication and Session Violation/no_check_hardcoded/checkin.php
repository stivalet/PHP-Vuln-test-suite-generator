<?php
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
session_start();
?>

<html>
	<head>
		<title>  Check in </title>
	</head>
	<body>
		<div><?php
			if(isset($_SESSION['userID']))
			{?>
				<p> you are already registered </p><?php
			}
			else if(isset($_POST['login']) || isset($_POST['password']))
			{
				if(!isset($_POST['login']) || $_POST['login'] == NULL)
				{?>
					<p>login missing </p>
					<form method="POST" action="#">
						login : <input type="text" name="login" /><br />
						password : <input type="password" name="password" /><br />
						<input type="submit" value="connect" />
					</form><?php
				}
				else if(!isset($_POST['password']) || $_POST['password'] == NULL)
				{?>
					<p>password missing </p>
					<form method="POST" action="#">
						login : <input type="text" name="login" /><br />
						password : <input type="password" name="password" /><br />
						<input type="submit" value="connect" />
					</form><?php
				}
				else
				{//connection
					try {
						$host = 'localhost';
						$dbname = 'authentication'; 
                                                $dsn = 'mysql:dbname='.$dbname.';host='.$host;
						$user = 'test';
						$pass = 'password';

						//connection to the DATABASE
						$dbh = new PDO($dsn, $user, $pass);

						//$sql = "SELECT * FROM ". $_GET['table'];
						$sth = $dbh->query("SELECT * FROM user where user=".$dbh->quote($_POST['login']));
						$result = $sth->fetch(PDO::FETCH_ASSOC);
						if($result)
						{?>
							<p>user already exists </p>
								<form method="POST" action="#">
								login : <input type="text" name="login" /><br />
								password : <input type="password" name="password" /><br />
								<input type="submit" value="connect" />
								</form><?php
						}

						else
						{
							$id = $dbh->query("SELECT MAX(id) FROM user");
							$id = $id->fetch()[0] + 1;
							$dbh->query("INSERT INTO user VALUES (".$id.", ".$dbh->quote($_POST['login']).", ".$dbh->quote($_POST['password']).")");
							//flaw : session token should be regenerated to prevent session fixation
							$_SESSION['userID'] = $id;
							echo "check in complete <br />";
						}

					} catch (PDOException $e) {
						print "Erreur !: " . $e->getMessage() . "<br/>";
						die();
					}
				}
			}
			else
			{?>
				<form method="POST" action="#">
					login : <input type="text" name="login" /><br />
					password : <input type="password" name="password" /><br />
					<input type="submit" value="connect" />
				</form><?php
			}?>
		</div>
	</body>
</html>
