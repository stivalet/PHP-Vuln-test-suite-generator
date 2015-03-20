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

						$dbh = new PDO($dsn, $user, $pass);

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
							/* regexp explanation
								?=.{8,20} password length between 8 and 20 characters (use .{8,} if you don't want to set a maximum length)
								?=.*[a-z] : contains at least one lower case character
								?=.*[A-Z] : contains at least one upper case character
								?=.*[0-9] : contains at least one digit
								?=.*[$!%#] : contains at least one of the following symbols : $ ! % #
							this regexp will match if all the previous condition are verified
							*/
							if(preg_match("#.*^(?=.{8,20})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!%\#$]).*$#",$_POST['password'])){
								$id = $dbh->query("SELECT MAX(id) FROM user");
								$id = $id->fetch()[0] + 1;
								$hash = hash("sha256",$salt1 + $_POST['password'] + $salt2);
								$dbh->query("INSERT INTO user VALUES (".$id.", ".$dbh->quote($_POST['login']).", '".$hash."')");
								$_SESSION['userID'] = $id;
								//flaw : session token should be regenerated to prevent session fixation
								echo "check in complete <br />";
							}
							else{?>
								<p>your password must :
								<ul>
								<li>contain between 8 and 20 characters</li>
								<li>contain upper and lower case characters</li>
								<li>contain at least 1 digit</li>
								<li>contain at least 1 symbol from the following list : $!%#</li>
								</ul></p><?php
							}
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
