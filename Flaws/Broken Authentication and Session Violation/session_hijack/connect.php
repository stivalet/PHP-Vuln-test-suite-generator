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
class MySessionHandler extends SessionHandler
{
        public bool open ( string $save_path , string $session_id )
        {
                if(parent::open($save_path, $session_id))
                {
                        if(isset($_SESSION['userID']))
                        {
                                $ok = true;
                                if($_SERVER['REMOTE_ADDR'] != $_SESSION['userADDR'])
                                        $ok = false;
                                else if($_SERVER['HTTP_USER_AGENT'] != $_SESSION['user_agent'])
                                        $ok = false;
                                else if($_SESSION['start'] + 86400 > time())
                                        $ok = false;
                                if(!$ok)
                                {
                                        session_destroy();
                                        session_regenerate_id(true);
                                        return false;
                                }
                                else
                                        return true;

                        }
                        else
                                return true;
                }
                else
                        return false;
        }

        public bool destroy(string $session_id)
        {
                parent::destroy($session_id);
                $_SESSION = array(); //destroy all of the session variables
                if (ini_get("session.use_cookies")) {
                        $params = session_get_cookie_params();
                        setcookie(session_name(), '', time() - 42000,
                                        $params["path"], $params["domain"],
                                        $params["secure"], $params["httponly"]
                                 );
                }
        }
}

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
							$hash = hash("sha256",$salt1 + $_POST['password'] + $salt2);
							if($result['password'] == $hash)
							{
								$_SESSION['userID'] = $result['id'];
								$_SESSION['userADDR'] = $_SERVER['REMOTE_ADDR'];
                                                                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                                                                $_SESSION['start'] = time();
                                                                session_regenerate_id(true);

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
