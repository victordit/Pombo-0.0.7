#!/usr/bin/python
# -*- coding: iso-8859-1 -*-

# Pombo 0.0.7
# Version based Pombo 0.0.6
# Theft-recovery tracking opensource software
# Author: http://sebsauvage.net/pombo
# Contributor: Extended to this version by victord.it
# Read readme.txt for more information

# This program is distributed under the OSI-certified zlib/libpnglicense .
# http://www.opensource.org/licenses/zlib-license.php
# 
# This software is provided 'as-is', without any express or implied warranty.
# In no event will the authors be held liable for any damages arising from
# the use of this software.
# 
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it freely,
# subject to the following restrictions:
# 
#     1. The origin of this software must not be misrepresented; you must not
#        claim that you wrote the original software. If you use this software
#        in a product, an acknowledgment in the product documentation would be
#        appreciated but is not required.
# 
#     2. Altered source versions must be plainly marked as such, and must not
#        be misrepresented as being the original software.
# 
#     3. This notice may not be removed or altered from any source distribution.

PROGRAMNAME="Pombo"
PROGRAMVERSION="0.0.7"
print "%s %s" % (PROGRAMNAME,PROGRAMVERSION)

import urllib,random,re,os,time,datetime,sys,platform,subprocess, \
       zipfile,hmac,hashlib,urllib2,base64,ConfigParser
       
# Make sure this script is run as root:
if os.geteuid() != 0:
    print "This program must be run as root. Aborting."
    sys.exit(1)

os.nice(20)  # Use least priority.
os.environ['DISPLAY']=":0.0"

config = ConfigParser.SafeConfigParser()
config.read("/etc/pombo.conf")
GPGKEYID  = config.get("DEFAULT","gpgkeyid") # Put you GPG key identifier here.
PASSWORD  = config.get("DEFAULT","password")  # Put the password here (same as in php file).
SERVERURL = config.get("DEFAULT","serverurl")  # URL where you have put the php script.

#check if exits authtype connection
try:
    AUTHUSER = config.get("DEFAULT","authuser")  # user for authtype server login
except Exception, e:
    AUTHUSER = None
try:
    AUTHPSW = config.get("DEFAULT","authpsw")  # password for authtype server login
except Exception, e:
    AUTHPSW = None

#check if exits email
try:
    EMAIL = config.get("DEFAULT","email")  # email for notification
except Exception, e:
    EMAIL = None

ONLYONIPCHANGE = None
try: ONLYONIPCHANGE = config.get("DEFAULT","onlyonipchange")  # URL where you have put the php script.
except ConfigParser.NoOptionError: pass


def has_authtype():

    ''' Return True if in conf is set authuser and authpsw
    '''
    if AUTHUSER != None and AUTHPSW != None :
        print "The request containt Authtype Basic"
        return True
    else : 
        return False

def request(param=None,url=SERVERURL,authuser=AUTHUSER,authpsw=AUTHPSW):

    ''' Return True if the request is 200
    '''

    request = urllib2.Request(url,param)
    #debug 
    #print "url: %s " % url
    #print "param: %s " % param

    if has_authtype() == True:
        base64string = base64.encodestring('%s:%s' % (authuser,authpsw)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string) 

    try:

        response = urllib2.urlopen(request)
        status = response.getcode()

        if status == 200 or status == 201:
            return response
        else :
            print "Error Connection with http status: %s "% status
            return None

    except Exception, ex:
            pass
            print "Error Connection: %s " % ex
            return None

# FIXME: Change network timeout ?

def public_ip():
    ''' Returns your public IP address.
        Output: The IP address in string format.
                None if not internet connection is available.
    '''
    
    ip_regex = re.compile("(([0-9]{1,3}\.){3}[0-9]{1,3})")
    ip_encode = urllib.urlencode({'myip':'1'})
    response = request(ip_encode)
    try:
        ip = response.read(256)
        if ip_regex.match(ip): return ip
    except Exception,ex:
        pass
    return None

# Prefix used to name files (computer name + date/time)
PREFIX = platform.node()+time.strftime("_%Y%m%d_%H%M%S")
print "Checking connectivity to the internet."
PUBLICIP = public_ip() # Yeah, globals, sue me.

def runprocess(commandline,useshell=False):
    ''' Runs a sub-process, wait for termination and returns
        the process output (both stdout and stderr, concatenated).

        Input: commandline : string or list of strings. First string is command, 
                             items are command-line options.
               useshell: If true, system shell will be used to run the program.
                         Otherwise, the program will be run directly with popen().
                         (Some program need to have a full shell environment in order
                         to run properly.)

        Ouput; The output of the commande (stdout and stderr concatenated)
               Empty string in case of failure.

        Example:
            print runprocess(['ifconfig','-a'])
            print runprocess('DISPLAY=:0 su %s -c "scrot %s"' % (user,filepath),useshell=True)
    '''
    try:
        myprocess = subprocess.Popen(commandline,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=useshell)
        (sout,serr) = myprocess.communicate()
        myprocess.wait()
        if not sout: sout = ''
        if not serr: serr = ''
        return sout+"\n"+serr
    except Exception, ex:  # Yeah, I know this is bad
        print "Process failed: %s (%s)" % (commandline,ex)
        return ''

def currentuser():
    ''' Return the user who is currently logged in and uses the X session. 
        None if could not be determined.
    '''
    user = None
    for line in runprocess(["who","-s"]).split('\n'):
        if "(:0)" in line:
            user = line.split(" ")[0]
    return user
    
def screenshot():
    ''' Takes a screenshot and returns the path to the saved image (in /tmp)
        None if could not take the screenshot. 
        If pngnq is installed, it will be used to reduce the size of the png (recommended)
    '''
    print "Taking screenshot."
    filepath = "/tmp/%s_screenshot.png" % PREFIX
    user = currentuser()
    if not user:
        print "Could not determine current user. Cannot take screenshot."
        return None

    runprocess('DISPLAY=:0 su %s -c "scrot %s"' % (user,filepath),useshell=True)
    if not os.path.isfile(filepath): # check that the file was properly created:
        return None
    os.system("pngnq -f %s" % filepath) # Try to run it through pngnq (if present)
    filepathnq8 = "/tmp/%s_screenshot-nq8.png" % PREFIX
    if not os.path.isfile(filepathnq8):
        print "(Skipping PNG recompression: pngnq failed or is not installed)"
    else:
        os.rename(filepathnq8,filepath)   
    return filepath
    # We use the png format, then reduce it with pngnq, 
    # which usually gives smaller files than JPEG.

def webcamshot():
    ''' Takes a snapshot with the webcam and returns the path to the saved image (in /tmp)
        None if could not take the snapshot. 
    '''
    print "Taking webcam snapshot." 
    filepath = "/tmp/%s_webcam.jpeg" % PREFIX
    os.system("streamer -q -o %s" % filepath)
    if not os.path.isfile(filepath): # check that the file was properly created:
        return None
    return filepath

def network_config():
    ''' Returns the network configuration, both wired and wireless '''
    return runprocess(["/sbin/ifconfig","-a"]) + "\n" + runprocess(["/sbin/iwconfig"])

def network_route():
    ''' Returns a traceroute to a public server in order to detect ISPs and
        nearby routeurs.
    '''
    return runprocess(['traceroute','-q1','-n','www.google.com'])

def wifiaccesspoints():
    ''' Returns a list of nearby wifi access points (AP). '''
    return runprocess(['iwlist','scanning'])

def current_network_connections():
    ''' Returns the addresses and ports to which this computer is currently connected to. '''
    return runprocess(['netstat','-putn'])

def systemreport():
    ''' Returns a system report: computer name, date/time, public IP,
        list of wired and wireless interfaces and their configuration, etc.
    '''
    report=["%s %s report" % (PROGRAMNAME,PROGRAMVERSION)]
    report.append("Computer: "+" ".join(platform.uname()))
    report.append("Public IP: %s   ( Approximate geolocation: http://www.geoiptool.com/?IP=%s )" % (PUBLICIP,PUBLICIP))
    report.append("Date/time: %s (local time)" % datetime.datetime.now())
    report.append("Network config:\n"+network_config())
    report.append("Nearby wireless access points:\n"+wifiaccesspoints())
    report.append("Network routes:\n"+network_route())
    report.append("Current network connections:\n" + current_network_connections())
    # FIXME: whatelse ? running programs ?
    separator = "\n"+75*"-"+"\n"
    return separator.join(report)
        
def snapshot():
    ''' Make a global snapshot of the system (ip, screenshot, webcam...)
        and sends it to the internet.
        If not internet connexion is available, will exit.
    '''
    # Note: when making a snapshot, we will try each and every type
    # of snapshot (screenshot, webcam, etc.)
    # If a particular snapshot fails, it will simply skip it.

    filestozip = []  # List of files to include in the zip file (full path)

    # Make sure we are connected to the internet:
    # (If the computer has no connexion to the internet, it's no use accumulating snapshots.)
    if not PUBLICIP:
        print "Computer does not seem to be connected to the internet. Aborting."
        sys.exit(2)

    if ONLYONIPCHANGE:
        filename="/var/local/pombo"
        # Read previous IP
        if not os.path.isfile(filename): # First run: file containing IP is no present.
            print "First run, writing down IP in /var/local/pombo."
            f = open(filename,"w+")
            f.write(PUBLICIP.strip())
            f.close()
        else:
            f = open(filename,"r")
            previous_ip = f.read().strip()
            f.close()
            if PUBLICIP == previous_ip:
                print "IP has not changed. Aborting."
                return
            print "IP has changed."

    # Create the system report (IP, date/hour...)
    print "Collecting system info."
    filepath = "/tmp/%s.txt" % PREFIX
    f = open(filepath,"a")
    f.write(systemreport())
    f.close()
    filestozip.append(filepath)

    # Take a screenshot
    imagepath = screenshot()
    if not imagepath: 
        print "Screenshot failed (scrot may not be installed). Skipping."
    else:
        filestozip.append(imagepath)

    # Take a webcam snapshot
    imagepath = webcamshot()
    if not imagepath: 
        print "Webcam snapshot failed (streamer may not be installed, or no webcam available). Skipping."
    else:
        filestozip.append(imagepath)

    # Zip the files:
    print "Zipping files."
    os.chdir('/tmp')
    zipfilepath = '/tmp/%s.zip'%PREFIX
    f = zipfile.ZipFile(zipfilepath,'w',zipfile.ZIP_DEFLATED)
    for filepath in filestozip:
        f.write(os.path.basename(filepath))
    f.close()

    # Remove temporary files.
    for filepath in filestozip:
        os.remove(filepath)

    # Encrypt using gpg with a specified public key
    print "Encrypting zip with GnuPG."
    os.system('gpg --batch --no-default-keyring --trust-model always -r %s -e "%s"' % (GPGKEYID,zipfilepath))
    os.remove(zipfilepath)
    gpgfilepath = zipfilepath+".gpg"
    if not os.path.isfile(gpgfilepath):
        print "GPG encryption failed. Aborting."
        sys.exit(3)

    # Read GPG file and compute authentication token
    f = open(gpgfilepath,'rw')
    filedata = base64.b64encode(f.read()) # we encode in base64 for HTTP POST
    f.close()
    os.remove(gpgfilepath)
    gpgfilename = os.path.basename(gpgfilepath)
    authtoken = hmac.new(PASSWORD,filedata+"***"+gpgfilename,hashlib.sha1).hexdigest()

    # Send to the webserver (HTTP POST).
    print "Sending %s to %s." % (gpgfilename,SERVERURL)
    parameters = {'filename':gpgfilename,'filedata':filedata,'token':authtoken,'email':EMAIL}
    response = request(urllib.urlencode(parameters))
    try:
        page = response.read(2000)
        print "Server responded: %s" % page.strip()
    except Exception,ex:
        print "Failed to send to server because: %s" % ex
        sys.exit(4)

    print "Done."
    sys.exit(0)

if __name__ == "__main__":
    snapshot()
