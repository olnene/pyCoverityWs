from ConnectionService import ConnectionService
from XmlConfigFileRead import XmlConfigFileRead
from datetime import datetime, timedelta, timezone
import getopt
import sys

def usage():
    """Print help for this script"""
    print("File: email-notify-project.py \n")
    print("Usage:\n")
    print(" email-notify-project.py --project [Project] --config [ConfigFile] --days [Number of days]  OR\n")
    print(" email-notify-project.py -p [Project] -c [ConfigFile] -d [Number of days] \n")
    print("Options:\n")
    print(" Required:\n")
    print("  -p OR --project => Coverity Connect Project \n")
    print("\n  -c OR --config  => XML Config file. \n")
    return

def extractAttributes(attributeslist):
    hashAttributetable={}
    for attribute in attributeslist:
        hashAttributetable[attribute.attributeDefinitionId.name]= attribute.attributeValueId.name
    return hashAttributetable

def sentEmailGroup(groupid, emailSubject, emailBody):
    groupUsers=[]
    coverityObjectReturn=WSCoverity.getUsers(False,False,'Administrators',False,True,False,None,None,sizePage)

    if coverityObjectReturn.totalNumberOfRecords > 0:
        groupUsers=coverityObjectReturn.users

        for username in groupUsers:
            print("Email sent to:" + username.username)
            #WSCoverity.notify(username.username,subject,body)
    return

try:
    opts,args,=getopt.getopt(sys.argv[1:],'c:p:d:t:h',['config=','project=', 'days=','to=', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg, in opts:
    if opt in ('-h', '--help'):
        usage()
#        sys.exit()
    elif opt in ('-c', '--config'):
        xmlFilePath= arg
    elif opt in ('-p', '--project'):
        projectName= arg
    elif opt in ('-d', '--days'):
        daysBefore= arg
    elif opt in ('-t', '--to'):
        toUsers= arg
    else:
        usage()
        sys.exit(0)




ConfigFile= XmlConfigFileRead(xmlFilePath)

WSCoverity=ConnectionService(ConfigFile.getHost(),ConfigFile.getPort(),ConfigFile.getUserName(),ConfigFile.getPassword(), ConfigFile.getSSL())
fromDate= datetime.now(timezone.utc) - timedelta(days=int(daysBefore))
lastDetectedDate= datetime.now(timezone.utc) - timedelta(days=1)

new_defects=[]
mergedDefects=[]
pageStartIndex=0
numDefects=0
while True:
    sizePage=WSCoverity.pageSpecDataObj(1000,True,None,pageStartIndex)
    filterSpec=WSCoverity.projectScopeDefectFilterSpecDataObj(None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,lastDetectedDate,None,None,None,None)
    defectsPage=WSCoverity.getMergedDefectsForProjectScope(projectName,filterSpec,sizePage)
    pageStartIndex+=1000
    numDefects=defectsPage['totalNumberOfRecords']
    if numDefects > 0 :
        mergedDefects.extend(defectsPage['mergedDefects'])
    if pageStartIndex >= numDefects:
        break

print("Defects after date: "+str(fromDate) +"\n")

if len(mergedDefects) == 0:
    print("No new defects found. \n")
    body="<html><body><p>The following "
    body+="email was sent to notify 0 defects on project "+projectName + "in the past "+ daysBefore + ". No action needs to be performed"
    subject="No Defects found on "+projectName+" notification."
    body+="</p></body></html>"

    sentEmailGroup('Administrators',subject,body)
    sys.exit(0)
else:
    for dfect in mergedDefects:
        if not hasattr(dfect, 'firstDetectedSnapshotId'):
            continue
        snapshotInfo=WSCoverity.getSnapshotInformation(dfect.firstDetectedSnapshotId)
        if snapshotInfo[0].dateCreated > fromDate:
            dfect.firstDetected=snapshotInfo[0].dateCreated
            new_defects.append(dfect)

new_defects.sort(key=lambda k:k.componentName)
print(len(new_defects))
   
body="<html><body><p>The following "
if len(new_defects) == 0:
    print("No new defects found. \n")
    body+="email was sent to notify 0 defects on project "+projectName + "in the past "+ daysBefore + ". No action needs to be performed"
    subject="No Defects found on "+projectName+" notification."
    body+="</p></body></html>"

    sentEmailGroup('Administrators',subject,body)
    #sentEmailGroup('TFALs',subject,body)
    sys.exit(0)

elif len(new_defects) == 1:
    body+="defect was"
else:
    body+= str(len(new_defects)) + " defects were"

body+=" found and commited to project "+ projectName + " within the past "

if daysBefore == 1:
    subject="New defects detected in the past 24 hours by ASQC"
    body+="24 hours.</p>"
else:
    subject="New defects detected in the past "+daysBefore+" days by ASQC"
    body+=daysBefore+" days.</p>"

body+="<br/><table border=\"1\"><tr bgcolor=\"#c0c0c0\"><th>CID</th><th>Component</th><th>Checker</th><th>Severity</th><th>Impact</th><th>Owner</th><th>First Detected</th><th>File</th></tr>"
for defectValue in new_defects:
    attributes=defectValue.defectStateAttributeValues
    hashResults=extractAttributes(attributes)
    
    if defectValue.checkerName[:2] == "PW":
        defectValue.checkerName= "PW.*"
        checkerproperties=WSCoverity.getCheckerProperties("PW.*",None,None,None,None,None,None)
    elif dfect.checkerName[:2] == "RW":
                dfect.checkerName= "RW.*"
                checkerproperties=WSCoverity.getCheckerProperties("RW.*",None,None,None,None,None,None)
    else:
        checkerproperties=WSCoverity.getCheckerProperties(defectValue.checkerName,defectValue.checkerSubcategory,None,None,None,None,None)
    
    if ConfigFile.getSSL.lower() ==  'true':
        url="https://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
    else:
        url="http://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)

    body+="<tr><td><a href="+url+"\">"+str(defectValue.cid)+"</a></td><td>"+defectValue.componentName+"</td><td>"+defectValue.checkerName+"</td><td>"+hashResults['Severity']+"</td><td>"+checkerproperties[0].impact+"</td><td>"+hashResults['Owner']+"</td><td>"+str(defectValue.firstDetected)[:10]+"</td><td>"+defectValue.filePathname+"</td></tr>"

body+="</table></body></html>"

sentEmailGroup('Administrators',subject,body)
#sentEmailGroup('TFALs',subject,body)

usersIds=toUsers.split(",")
for userId in usersIds:
    print("Email sent to: "+ str(userId))
    WSCoverity.notify(userId,subject,body)
