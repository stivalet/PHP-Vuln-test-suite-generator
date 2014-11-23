<!-- 
Unsafe sample
File : unsafe, use of untrusted data in the function setInterval
input : use shell_exec to cat /tmp/tainted.txt
Uses a special_chars_filter via filter_var function -->

<!--Copyright 2014 Herve BUHLER, David LUCAS, Fabien NOLLET, Axel RESZETKO

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

MODIFICATIONS.-->

<!DOCTYPE html>
<html>
<head>
<script>
<?php
$tainted = shell_exec('cat /tmp/tainted.txt');
$checked_data = filter_var($tainted, FILTER_SANITIZE_SPECIAL_CHARS);
echo "window.setInterval('". $checked_data ."');" ;
?>
 </script>
</head>
<body>
<h1>Hello World!</h1>
</body>
</html>