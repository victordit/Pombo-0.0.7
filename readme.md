
Pombo 0.0.7
Original project: http://sebsauvage.net/pombo (v 0.0.6)
Author of this version: http://victord.it

Theft-recovery tracking opensource software
For more information, see http://sebsauvage.net/pombo


****************
* News features
****************
This version is based on 0.0.6 and add some new features

- Authorization Basic: If you need add the authtype login, 
   just decomment in pombo.conf authuser and put your user,
   decomment authpsw and put your password

- Email for notification: if you want avised when Pombo is active set you email,
   just decoment in pombo.conf email and put your email
   This notification not included atach (like a new version on github https://github.com/BoboTiG/pombo)
   because is unsecure.


Installation
=============

Installation requires a small Linux knowledge, but nothing very complex. Instructions:

- Copy pombo.py to /usr/local/bin

- Copy pombo.conf to /etc

If you need create the KEY gpp:
------------------------------

reference: https://www.digitalocean.com/community/tutorials/how-to-use-gpg-to-encrypt-and-sign-messages-on-an-ubuntu-12-04-vps

- Install the software:

 ```
 sudo apt-get install gnupg

```
- Generate key

```
gpg --gen-key

```

Import your public key into the root keyring: 

```
sudo -H gpg --import yourpublickey.key

```

Choose a secret password, put it in pombo.php ($PASSWORD='mysecret';)

Put pombo.php on your webserver.

Put your GnuPG keyID, secret password and the url of pombo.php in /etc/pombo.conf:

# Pombo configuration file
[DEFAULT]
gpgkeyid=BAADF00D
password=mysecret
serverurl=http://myserver.com/pombo.php
authuser=youuserauth
authpsw=yourpasswordauth
email:yournotificationemail

Use cron to run /usr/local/bin/pombo.py every 15 minutes as root: sudo crontab -e
Then add this line:

```
 */15 * * * * /usr/local/bin/pombo.py 2>/dev/null
 
```

(Note: Don't forget to leave an empty line after the last line in your crontab file.)

- For more information about installation instructions @see: http://sebsauvage.net/pombo/installation.html



Test run
=========


Launch the command:

```
sudo -H /usr/local/bin/pombo.py
```
and see if the gpg file is sent to the webserver (You should see a message: Server responded: File stored.)


To decript file
---------------
```
gpg path_to_file/file.zip.gpg

```

- For download previous version, check: http://sebsauvage.net/pombo/pombo_0.0.6.zip



--------------------------------------------------------------------------
License
This program is distributed under the OSI-certified zlib/libpnglicense.
http://www.opensource.org/licenses/zlib-license.php

This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from
the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it freely,
subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not
       be misrepresented as being the original software.

    3. This notice may not be removed or altered from any source distribution.
--------------------------------------------------------------------------
