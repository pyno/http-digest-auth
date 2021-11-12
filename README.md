# HTTP Digest Authentication
Burp Suite extension to handle HTTP Digest Authentication, which is no more supported by Burp Suite since version 2020.7.

![img](https://raw.githubusercontent.com/pyno/http-digest-auth/main/http-digest-auth.png)

## Why
Because, why not? ;)

No seriously, during some pentests on IoT devices I still have to deal with HTTP Digest authentication (mostly on IP cameras), and it seems other users are also struggling with this (https://forum.portswigger.net/thread/digest-auth-in-burp-was-removed-de8107ec).

So I decided to write and publish this extension, hoping it will come in handy and save someone time.

## Setup
1. Download and run Burp Suite: http://portswigger.net/burp/download.html
2. Download Jython **standalone** JAR: http://www.jython.org/download.html
3. Open burp -> Extender -> Options -> Python Environment -> Select File -> Choose the Jython standalone JAR
4. Install Autorize from the BApp Store or follow these steps:
5. Clone this repository
6. Open Burp -> Extender -> Burp Extensions -> Add -> Set Extension Type to "Python" and Choose http-digest-auth.py file.
7. See the "Digest Authentication" tab to setup the extension
8. Click on "Digest Auth is off" and profit :)

Currently the tools supports the following features:
- Set credentials
- Auto-update nonce if it detects a "401 Unauthorized" response from the server
- Show current nonce (debug purposes only)

and it works with Repeater, Scanner and Intruder tools.

**Last but not least**: PRs are always welcome!
