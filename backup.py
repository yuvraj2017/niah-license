import os
import json
from datetime import date
from google.cloud import storage



def getoutput(cmd):
    """Return output (stdout or stderr) of executing cmd in a shell."""
    return getstatusoutput(cmd)[1]

def getstatusoutput(cmd):
    """Return (status, output) of executing cmd in a shell."""
    # import os
    pipe = os.popen('{ ' + cmd + '; } 2>&1', 'r')
    text = pipe.read()
    sts = pipe.close()
    if sts is None: sts = 0
    if text[-1:] == '\n': text = text[:-1]
    return sts, text


today = date.today()

print(today)


os.chdir("/home/niah/niah-license")


if not os.path.exists("backup_%s" % today):
    os.mkdir("backup_%s" % today) 

cmd  = "tar -cvf static_%s.tar static" % today
status, output = getstatusoutput(cmd)

cmd = "mv static_%s.tar backup_%s" % (today, today)
status, output = getstatusoutput(cmd)

cmd  = "pg_dump -U versa -d niahdb > niahdb_%s.sql" % today
status, output = getstatusoutput(cmd)

cmd  = "mv  niahdb_%s.sql backup_%s" % (today, today)
status, output = getstatusoutput(cmd)

# os.chdir("/var")

cmd  = "tar -cvf db_%s.tar DB" % today
status, output = getstatusoutput(cmd)

cmd  = "mv db_%s.tar /home/niah/niah-license/backup_%s" % (today, today)
status, output = getstatusoutput(cmd)

os.chdir("/home/niah/niah-license")

cmd  = "tar -cvf backup_%s.tar backup_%s" % (today, today)
status, output = getstatusoutput(cmd)

cmd  = "gzip backup_%s.tar" % today
status, output = getstatusoutput(cmd)

cmd  = "rm -rf backup_%s" % today
status, output = getstatusoutput(cmd)










