<?php
require_once("DB.php");
$db = new DB("localhost", "Example", "root", "");
if ($_SERVER['REQUEST_METHOD'] == "GET") {
        if ($_GET['url'] == "auth") {
        	echo json_encode($db->query("SELECT * FROM `Registration`"));
        	print_r($_GET);
        } else if ($_GET['url'] == "Registration") {
        	echo "Registration";
        	print_r($_GET);
        } else {
        	print_r($_GET);
        }
} else if ($_SERVER['REQUEST_METHOD'] == "POST") {
        if ($_GET['url'] == "auth") {
                $postBody = file_get_contents("php://input");
                $postBody = json_decode($postBody);
                //console.log($postBody);
                //$username = $postBody->username;
                $username = $_POST['username'];
                $password = $postBody->password;
                if ($db->query('SELECT username FROM Registration WHERE username=:username', array(':username'=>$username))) {
                        if (password_verify($password, $db->query('SELECT password FROM Registration WHERE username=:username', array(':username'=>$username))[0]['password'])) {
                                $cstrong = True;
                                $token = bin2hex(openssl_random_pseudo_bytes(64, $cstrong));
                                $user_id = $db->query('SELECT id FROM Registration WHERE username=:username', array(':username'=>$username))[0]['id'];
                                $db->query('INSERT INTO login_tokens VALUES (\'\', :token, :user_id)', array(':token'=>sha1($token), ':user_id'=>$user_id));
                                echo '{ "Token": "'.$token.'" }';
                        } else {
                                http_response_code(401);
                        }
                } else {
                        http_response_code(401);
                }
        } else {
        	echo "Try it on Postman";
        }
}  else if ($_SERVER['REQUEST_METHOD'] == "DELETE") {
        if ($_GET['url'] == "auth") {
                if (isset($_GET['token'])) {
                        if ($db->query("SELECT token FROM login_tokens WHERE token=:token", array(':token'=>sha1($_GET['token'])))) {
                                $db->query('DELETE FROM login_tokens WHERE token=:token', array(':token'=>sha1($_GET['token'])));
                                echo '{ "Status": "Success" }';
                                http_response_code(200);
                        } else {
                                echo '{ "Error": "Invalid token" }';
                                http_response_code(400);
                        }
                } else {
                        echo '{ "Error": "Malformed request" }';
                        http_response_code(400);
                }
        } else {
        	echo "Try it on Postman";
        }
} else {
        echo "try it only on GET POST DELETE method";
}
?>