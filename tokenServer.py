from flask import Flask

# generateToken
import base64
import binascii
from datetime import datetime
import calendar, time
import hashlib
import hmac
import sys
import getopt



key = "e0a5ae757bcb487d901b13b3abf63569"
appID = "e2187c.vidyo.io"
vCardFile = ""
expiresInSecs = 18000



try:
    from datetime import timezone
    utc = timezone.utc
except:
    # python 2 variant
    from datetime import timedelta, tzinfo
    class UTC(tzinfo):
        ZERO = timedelta(0)
        """UTC"""

        def utcoffset(self, dt):
            return self.ZERO

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return self.ZERO

    utc = UTC()


def read_file(path):
    try:
        f = open(path, "r+b")
        return f.read()
    except e:
        print("Could not read file: %s error %s  ", path, e)
        exit(3)

def to_bytes(o):
    return str(o).encode("utf-8")

class Token:
    def __init__(self, key, appID, userName, vCardFile, expires):
        self.type    = 'provision'
        self.key     = key
        self.jid     = userName + "@" + appID
        if (vCardFile):
            self.vCard   = read_file(vCardFile).decode("utf-8").strip()
        else:
            self.vCard   = ""
        self.expires = expires

    def __str__(self):
        return "Token" + {'type'    : self.type,
                          'key'     : self.key,
                          'jid'     : self.jid,
                          'vCard'   : self.vCard[:10] + "...",
                          'expires' : self.expires}.__str__()

    def serialize(self):
        sep = b"\0" # Separator is a NULL character
        body = to_bytes(self.type) + sep + to_bytes(self.jid) + sep + to_bytes(self.expires) + sep + to_bytes(self.vCard)
        mac = hmac.new(bytearray(self.key, 'utf8'), msg=body, digestmod=hashlib.sha384).digest()
        ## Uncomment to debug
        ##sys.stderr.buffer.write( b"key : " + base64.b64encode(bytearray(self.key, 'utf8')) + b"\n" )print("bodyFull: " + self.type + "_" + self.jid + "_" + str(self.expires) + "_" + self.vCard);
        ##sys.stderr.buffer.write(b"bodyString: " + ("%s_%s_%s_%s" % (self.type, self.jid, str(self.expires), self.vCard)).encode("utf-8") + b"\n");
        ##sys.stderr.buffer.write( b"body: " + ("%s" % [b for b in body]).encode("utf-8") + b"\n" )
        ##sys.stderr.buffer.write( b"mac : " + base64.b64encode(mac) + b"\n" )
        ##sys.stderr.flush()
        ## Combine the body with the hex version of the mac
        serialized = body + sep + binascii.hexlify(mac)
        return serialized



## APPLICATION START

app = Flask(__name__)




EPOCH_SECONDS = 62167219200
    
## datetime.timestamp() by default subtracts datetime(1970, 1, 1) from the datetime
## on which we call it, therefore the number of seconds is smaller
## by (pseudocode!) seconds("1970-01-01").
## In Erlang, on the other hand, we get the actual number of seconds,
## hence we adjust for this difference here.
## IMPORTANT! A 64bit architecture is assumed! Otherwise, the timestamp
## might be stored as a 32bit integer, therefore limiting the "capacity"
## to 2038 (see https://en.wikipedia.org/wiki/Year_2038_problem).

@app.route('/<userName>')
def createToken(userName):
    expires = 10000
    if (expiresInSecs != None):
        d = datetime.now()
        expires = EPOCH_SECONDS + int(time.mktime(d.timetuple())) + int(expiresInSecs)
    elif (expiresAt != None):
        d = datetime.strptime(expiresAt, '%Y-%m-%dT%H:%M:%SZ')
        d = d.replace(tzinfo=utc)
        expires = EPOCH_SECONDS + int(calendar.timegm(d.timetuple()))
    else:
        print("expiresInSecs or expiresAt not set")
        sys.exit(2)
    token = 0
    token = Token(key, appID, userName, vCardFile, expires)
    serialized = token.serialize()
    b64 = base64.b64encode(serialized)
    return b64.decode()

if __name__ == '__main__':
	app.run(host= '0.0.0.0')