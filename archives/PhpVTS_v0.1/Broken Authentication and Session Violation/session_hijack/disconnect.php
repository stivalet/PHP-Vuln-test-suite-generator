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
                                        session_regenerate_id();        
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
?>

<html>
	<head>
		<title> disconnection </title>
	</head>
	<body>
		<div><?php
			if(isset($_SESSION['userID']))
			{
				session_destroy();?>
				<p> you have been disconnected <br />
				<a href="connect.php">back</a></p><?php
			}?>
		</div>
	</body>
</html>
