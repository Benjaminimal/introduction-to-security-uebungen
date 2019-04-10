<?php
/* disable error reporting */
error_reporting(0);

require_once 'creds.inc.php';

function show_header() {
	echo <<<EOT
<!DOCTYPE html>
<html lang="en">
<head>
	<title>Login V10</title>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
<!--===============================================================================================-->	
	<link rel="icon" type="image/png" href="images/icons/favicon.ico"/>
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/bootstrap/css/bootstrap.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/font-awesome-4.7.0/css/font-awesome.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="fonts/Linearicons-Free-v1.0.0/icon-font.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/animate/animate.css">
<!--===============================================================================================-->	
	<link rel="stylesheet" type="text/css" href="vendor/css-hamburgers/hamburgers.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/animsition/css/animsition.min.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="vendor/select2/select2.min.css">
<!--===============================================================================================-->	
	<link rel="stylesheet" type="text/css" href="vendor/daterangepicker/daterangepicker.css">
<!--===============================================================================================-->
	<link rel="stylesheet" type="text/css" href="css/util.css">
	<link rel="stylesheet" type="text/css" href="css/main.css">
<!--===============================================================================================-->
</head>
<body>
	
	<div class="limiter">
		<div class="container-login100">
			<div class="wrap-login100 p-t-50 p-b-90">
EOT;
}

function show_footer() {
        echo <<<EOT
			</div>
		</div>
	</div>
	

	<div id="dropDownSelect1"></div>
	
<!--===============================================================================================-->
	<script src="vendor/jquery/jquery-3.2.1.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/animsition/js/animsition.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/bootstrap/js/popper.js"></script>
	<script src="vendor/bootstrap/js/bootstrap.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/select2/select2.min.js"></script>
<!--===============================================================================================-->
	<script src="vendor/daterangepicker/moment.min.js"></script>
	<script src="vendor/daterangepicker/daterangepicker.js"></script>
<!--===============================================================================================-->
	<script src="vendor/countdowntime/countdowntime.js"></script>
<!--===============================================================================================-->
	<script src="js/main.js"></script>

</body>
</html>
EOT;
}

function show_form() {
	echo <<<EOT
				<form class="login100-form validate-form flex-sb flex-w" method="post">
					<span class="login100-form-title p-b-51">
						Login
					</span>

					
					<div class="wrap-input100 validate-input m-b-16" data-validate = "Mail is required">
						<input class="input100" type="text" name="mail" placeholder="mail">
						<span class="focus-input100"></span>
					</div>
					
					
					<div class="wrap-input100 validate-input m-b-16" data-validate = "Password is required">
						<input class="input100" type="password" name="password" placeholder="Password">
						<span class="focus-input100"></span>
					</div>
				
					<div class="container-login100-form-btn m-t-17">
						<button class="login100-form-btn" type="submit">
							Login
						</button>
					</div>

				</form>
EOT;
}

function show_failure($message) {
        echo '<div class="text-center alert alert-danger" role="alert">'.$message.'</div>';
}

function show_welcome($mail) {
        global $flag;

        echo '<div class="alert alert-success" role="alert">Welcome <b>'.$mail.'</b></div>';
        if($mail === "admin@root")
                echo "<p>The flag is <code>$flag</code></p>";
	else
		echo "<p>Move along, nothing to see here.</p>";

}

function graceful_death($message) {
        show_failure($message);
        show_footer();
        exit(1);
}

function sanitize($str) {
	if(preg_match('/["\s;\-\|&\(\)]/i', $str) !== 0) {
		graceful_death("Malicious characters detected");
	}
        $out = preg_replace('/union|select|where|and|or|concat|from/i', '', $str);
	$out = preg_replace("/'/", "\\'", $out);
	return $out;
}

function sql_execute($conn, $sql) {
	$sth = $conn->query($sql);
	if(!$sth) graceful_death("Unable to execute the query");
	$result = $sth->fetchAll();
	return $result;
}

/* Initialize the DB connection. */
try {
	$dbh = new PDO("mysql:host=".$db_params["host"].";dbname=".$db_params["database"],
	               $db_params["user"], $db_params["password"]);
	$dbh->setAttribute(PDO::ATTR_EMULATE_PREPARES, 0);
} catch(PDOException $e) {
	graceful_death('Connection failed: ' . $e->getMessage());
}
/* Start bulding the page */
show_header();
/* Check POST values. If something is wrong, e.g., hackers posting arrays, just
 * print the form and leave. */
if(isset($_POST['mail']) && isset($_POST['password']) 
&& is_string($_POST['mail']) && is_string($_POST['password'])) {
	$mail = sanitize($_POST['mail']);
        $password = sanitize($_POST['password']);
	$usrs = sql_execute($dbh, "SELECT * FROM users WHERE mail = '$mail'");
	if(count($usrs) < 1) {
		graceful_death("Mail not found");
	} elseif(count($usrs) > 1) {
		graceful_death("Multiple users returned");
	} else {
		echo '<div class="alert alert-success" role="alert">Checking password for mail <b>'.$mail.'</b>...</div>';
		flush();
		ob_flush();
		sleep(3);
		$sql = "SELECT mail FROM users WHERE mail = '" . $usrs[0]['mail'] . "' AND password = :password";
		$sth = $dbh->prepare($sql);
		if(!$sth) graceful_death();
		$sth->bindValue(':password', $password);
		$result = $sth->execute();
		if(false === $result) graceful_death();
		$result = $sth->fetchAll();
		if(count($result) === 1) {
			show_welcome($result[0]['mail']);
		} else {
			graceful_death("Wrong password");
		}
	}
} else {
        show_form();
}
show_footer();


exit(0);
?>
