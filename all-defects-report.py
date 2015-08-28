from ConnectionService import ConnectionService
from XmlConfigFileRead import XmlConfigFileRead
from datetime import datetime, timedelta, timezone
import getopt
import sys
import string

def extractAttributes(attributeslist):
    hashAttributetable={}
    for attribute in attributeslist:
        hashAttributetable[attribute.attributeDefinitionId.name]= attribute.attributeValueId.name
    return hashAttributetable

try:
    opts,args,=getopt.getopt(sys.argv[1:],'c:p:t:d:h',['config=','project=', 'to=', 'days=', 'help'])
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
    elif opt in ('-t', '--to'):
        emailto= arg
    else:
        usage()

ConfigFile= XmlConfigFileRead(xmlFilePath)

WSCoverity=ConnectionService(ConfigFile.getHost(),ConfigFile.getPort(),ConfigFile.getUserName(),ConfigFile.getPassword(), ConfigFile.getSSL())


defects=[]
pageStartIndex=0
numDefects=0
defectDataAppend=""

while True:
    sizePage=WSCoverity.pageSpecDataObj(1000,True,None,pageStartIndex)
    filterSpec=WSCoverity.projectScopeDefectFilterSpecDataObj(None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None)
    defectsPage=WSCoverity.getMergedDefectsForProjectScope(projectName,filterSpec,sizePage)
    pageStartIndex+=1000
    numDefects=defectsPage['totalNumberOfRecords']
    if numDefects > 0 :
        defects.extend(defectsPage['mergedDefects'])
    if pageStartIndex >= numDefects:
        break

for dfect in defects:
    attributes=dfect.defectStateAttributeValues
    hashResults=extractAttributes(attributes)
    if hashResults['DefectStatus'] == 'Fixed' or hashResults['Classification'] =='Intentional':
        snapshotInfo=WSCoverity.getSnapshotInformation(dfect.firstDetectedSnapshotId)
        dfect.firstDetected=snapshotInfo[0].dateCreated
       
        if dfect.checkerName[:2] == "PW":
            dfect.checkerName= "PW.*"
            checkerproperties=WSCoverity.getCheckerProperties("PW.*",None,None,None,None,None,None)
        else:
            checkerproperties=WSCoverity.getCheckerProperties(dfect.checkerName,dfect.checkerSubcategory,None,None,None,None,None)

        if str(ConfigFile.getSSL).lower() ==  'true':
            url="https://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(dfect.cid)
        else:
            url="http://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(dfect.cid)
        
        defectDataAppend+="<tr><td><a href="+url+">"+str(dfect.cid)+"</a></td><td>"+dfect.componentName+"</td><td>"+checkerproperties[0].category+"</td><td>"+hashResults['Legacy']+"</td><td>"+hashResults['DefectStatus']+"</td><td>"+hashResults['Classification']+"</td><td>"+checkerproperties[0].impact+"</td><td>"+hashResults['Severity']+"</td><td>"+str(dfect.firstDetected)[:10]+"</td><td>"+str(dfect.lastDetected)[:10]+"</td><td>"+hashResults['Owner']+"</td><td>"+str(dfect.occurrenceCount)+"</td><td>"+hashResults['Fix Target'] +"</td><td>"+ hashResults['Reviewed False Positive'] +"</td><td>"+dfect.filePathname+"</td></tr>"
body="<html><body><p>The following "
if len(defects) == 0:
    print("No new defects found. \n")
    body+="email was sent to notify 0 defects on project "+projectName + "in the past "+ daysBefore + ". No action needs to be performed"
    subject="No Defects found on "+projectName+" notification."
    body+="</p></body></html>"

    sentEmailGroup('Administrators',subject,body)
    #sentEmailGroup('TFALs',subject,body)
    sys.exit(0)

elif len(defects) == 1:
    body+="defect was"
else:
    body+= str(len(defects)) + " defects were"

body+=" found in project "+ projectName + " with Fixed status or  Intentional classification "

subject="Defects detected with Fixed status or Intentional classification"

body+="<br/><table border=\"1\"><tr bgcolor=\"#c0c0c0\"><th>CID</th><th>Component</th><th>Type</th><th>Legacy</th><th>Status</th><th>Classification</th><th>Impact</th><th>Severity</th><th>First Snapshot Date</th><th>Last Snapshot Date</th><th>Owner</th><th>Count</th><th>Fix Target</th><th>Reviewed False Positive</th><th>File</th></tr>"

body+=defectDataAppend
body+="</table></body></html>"

usersIds=emailto.split(",")
for userId in usersIds:
    print("Email sent to: "+ str(userId))
    WSCoverity.notify(userId,subject,body)