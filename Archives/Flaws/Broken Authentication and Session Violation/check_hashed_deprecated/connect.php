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
$salt1 = "the answer to life, the universe, and everything else";
$salt2 = "42";
?>

<html>
	<head>
		<title> authentication </title>
	</head>
	<body>
		<div><?php
			if(isset($_SESSION['userID']))
			{?>
				<p> you are already logged in </p><?php
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

						$sth = $dbh->query("SELECT * FROM user where user=".$dbh->quote($_POST['login']));
						$result = $sth->fetch(PDO::FETCH_ASSOC);
						if($result)
						{
							$hash = md5($salt1 + $_POST['password'] + $salt2);
							if($result['password'] == $hash)
							{
								$_SESSION['userID'] = $result['id'];
								//flaw : the session token should be regenerated to prevent session fixation
								echo "welcome ".$result['user']."<br />";
							}
							else
							{?>
								<p>wrong password </p>
								<form method="POST" action="#">
									login : <input type="text" name="login" /><br />
									password : <input type="password" name="password" /><br />
									<input type="submit" value="connect" />
								</form><?php
							}
						}
						else
						{?>
							<p>user not found </p>
							<form method="POST" action="#">
								login : <input type="text" name="login" /><br />
								password : <input type="password" name="password" /><br />
								<input type="submit" value="connect" />
							</form><?php
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
