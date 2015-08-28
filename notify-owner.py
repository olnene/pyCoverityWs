from ConnectionService import ConnectionService
from XmlConfigFileRead import XmlConfigFileRead
from datetime import datetime, timedelta, timezone
import getopt
import sys
import string

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
            WSCoverity.notify(username.username,subject,body)
    return



try:
    opts,args,=getopt.getopt(sys.argv[1:],'c:p:t:d:h',['config=','project=', 'to=', 'days=', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg, in opts:
    if opt in ('-h', '--help'):
        usage()
        sys.exit(0)
    elif opt in ('-c', '--config'):
        xmlFilePath= arg
    elif opt in ('-p', '--project'):
        projectName= arg
    elif opt in ('-t', '--to'):
        emailto= arg
    elif opt in ('-d', '--days'):
        daysBefore= arg
    else:
        usage()

ConfigFile= XmlConfigFileRead(xmlFilePath)

WSCoverity=ConnectionService(ConfigFile.getHost(),ConfigFile.getPort(),ConfigFile.getUserName(),ConfigFile.getPassword(), ConfigFile.getSSL())
fromDate=datetime.now(timezone.utc) - timedelta(days=int(daysBefore)) 
userdefectHash={}
tfaldefectHash={}
defectsSend=[]
ownerChangesIndex=5
defects=[]
pageStartIndex=0
numDefects=0

while True:
    sizePage=WSCoverity.pageSpecDataObj(1000,True,None,pageStartIndex)
    filterSpec=WSCoverity.projectScopeDefectFilterSpecDataObj(None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,fromDate,None,None,None,None)
    defectsPage=WSCoverity.getMergedDefectsForProjectScope(projectName,filterSpec,sizePage)
    pageStartIndex+=1000
    numDefects=defectsPage['totalNumberOfRecords']
    if numDefects > 0 :
        defects.extend(defectsPage['mergedDefects'])
    if pageStartIndex >= numDefects:
        break


if len(defects) == 0:
    print("No defects, assigned within cutoff to notify about.\n")
    body="<html><body><p>The following "
    body+="email was sent to notify 0 defects assigned on project "+projectName + "in the past "+ daysBefore + ". No action needs to be performed"
    subject="No Defects assigned on "+projectName+" notification."
    body+="</p></body></html>"
    sentEmailGroup('Administrators',subject,body)
    sys.exit(0)

else:
    for dfect in defects:
        defectChanges=WSCoverity.getMergedDefectHistory(dfect['cid'],None,dfect['lastDetectedStream'])
        lastUpdate=len(defectChanges)-1
        if lastUpdate <=0:
            continue
    
        modifiedDate= defectChanges[lastUpdate]['dateModified']
        while lastUpdate >=0 and modifiedDate>=fromDate:
            ownerValue=defectChanges[lastUpdate]['attributeChanges'][ownerChangesIndex]
            if modifiedDate>=fromDate and  ownerValue != None:
                assignedOwner=defectChanges[lastUpdate]['attributeChanges'][ownerChangesIndex]['newValue']
                idOwner= assignedOwner.split("@")
            
                if not idOwner[0] in userdefectHash.keys():
                    userdefectHash[idOwner[0]]=[]
                foundFlag=0
                for foundDefect in userdefectHash[idOwner[0]]:
                    if foundDefect['cid'] == dfect['cid']:
                        foundFlag=1
                        break
                if foundFlag == 0:
                    userdefectHash[idOwner[0]].append(dfect)
                    defectsSend.append(dfect)
                    ComponentInfo=WSCoverity.getComponent(dfect.componentName)
                    if hasattr(ComponentInfo,'roleAssignments'):
                        for tfal in ComponentInfo['roleAssignments']:
                            if hasattr(tfal, 'username'):
                                tfalSplitUser=tfal.username.split("@")
                                if not tfalSplitUser[0] in tfaldefectHash.keys():
                                    tfaldefectHash[tfalSplitUser[0]]=[]
                                tfaldefectHash[tfalSplitUser[0]].append(dfect)
                            else:
                                continue
                        
                break
            else:
                lastUpdate -=1
                if lastUpdate >= 0:
                    modifiedDate= defectChanges[lastUpdate]['dateModified']

print("Processing complete")

if len(userdefectHash) ==0:
    print("No defects, assigned within cutoff to notify about.\n")
    body="<html><body><p>The following "
    body+="email was sent to notify 0 defects assigned on project "+projectName + "in the past "+ daysBefore + ". No action needs to be performed"
    subject="No Defects assigned on "+projectName+" notification."
    body+="</p></body></html>"
    sentEmailGroup('Administrators',subject,body)
    sys.exit(0)

if daysBefore == 1:
    subject="New defects detected in the past 24 hours assigned to you in Coverity Connect"
else:
    subject="New defects detected in the past " + daysBefore + " days assigned to you in Coverity Connect"

for key, value in userdefectHash.items():
    if key == 'Unassigned':
        print("Skipping unassigned defects \n")
        continue
    getOwnerInfo=WSCoverity.getUser(key)
    defectsCount=len(userdefectHash[key])

    body="<html><body><p>The following "
    if defectsCount == 1:
       body+="defect was"
    else:
        body+=str(defectsCount) + " defects were"

    body+=" assigned to you in project "+ projectName+ " within the past "
    if daysBefore==1:
        body+="24 hours.</p>"
    else:
        body+=str(daysBefore)+ " days.</p>"

    body+="<br/><table border=\"1\"><tr bgcolor=\"#c0c0c0\"><th>CID</th><th>Component</th><th>Checker</th><th>Severity</th><th>Impact</th><th>Owner</th><th>First Detected</th><th>File</th></tr>"
    for defectValue in userdefectHash[key]:
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
        
        if ConfigFile.getSSL == True:
            url="http://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        else:
            url="https://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        body+="<tr><td><a href="+url+"\">"+str(defectValue.cid)+"</a></td><td>"+defectValue.componentName+"</td><td>"+defectValue.checkerName+"</td><td>"+hashResults['Severity']+"</td><td>"+checkerproperties[0].impact+"</td><td>"+hashResults['Owner']+"</td><td>"+str(defectValue.firstDetected)[:10]+"</td><td>"+defectValue.filePathname+"</td></tr>"
    body+="</table></body></html>"
    WSCoverity.notify(key,subject,body)
print("Sending to TFAL")
if len(tfaldefectHash)==0:
    print("No TFAL assigned to Component")
    sys.exit(0)

if daysBefore == 1:
    subject="New defects assigned in the past 24 hours "
else:
    subject="New defects assigned in the past " + daysBefore + " days "

for key, value in  tfaldefectHash.items():
    if key == 'Unassigned':
        print("Skipping unassigned defects \n")
        continue
    getOwnerInfo=WSCoverity.getUser(key)
    defectsCount=len(tfaldefectHash[key])

    body="<html><body><p>The following "
    if defectsCount == 1:
       body+="defect was"
    else:
        body+=str(defectsCount) + " defects were"

    body+=" assigned in project "+ projectName+ " within the past "
    if daysBefore==1:
        body+="24 hours.</p>"
    else:
        body+=str(daysBefore)+ " days.</p>"

    body+="<br/><table border=\"1\"><tr bgcolor=\"#c0c0c0\"><th>CID</th><th>Component</th><th>Checker</th><th>Severity</th><th>Impact</th><th>Owner</th><th>First Detected</th><th>File</th></tr>"
    for defectValue in tfaldefectHash[key]:
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
        
        if ConfigFile.getSSL == True:
            url="http://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        else:
            url="https://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        body+="<tr><td><a href="+url+"\">"+str(defectValue.cid)+"</a></td><td>"+defectValue.componentName+"</td><td>"+defectValue.checkerName+"</td><td>"+hashResults['Severity']+"</td><td>"+checkerproperties[0].impact+"</td><td>"+hashResults['Owner']+"</td><td>"+str(defectValue.firstDetected)[:10]+"</td><td>"+defectValue.filePathname+"</td></tr>"
    body+="</table></body></html>"
    WSCoverity.notify(key,subject,body)

print("Sending to specific users")
usersIds=emailto.split(",")
if len(usersIds) > 0:
    defectsSend.sort(key=lambda k:k.componentName)
    body="<html><body><p>The following "
    if len(defectsSend) == 1:
            body+="defect was"
    else:
        body+= str(len(defectsSend)) + " defects were"
    body+=" assigned and commited to project "+ projectName + " within the past "
    
    if daysBefore == 1:
        subject="New defects assigned in the past 24 hours by ASQC"
        body+="24 hours.</p>"
    else:
        subject="New defects assigned in the past "+daysBefore+" days by ASQC"
        body+=daysBefore+" days.</p>"
    body+="<br/><table border=\"1\"><tr bgcolor=\"#c0c0c0\"><th>CID</th><th>Component</th><th>Checker</th><th>Severity</th><th>Impact</th><th>Owner</th><th>First Detected</th><th>File</th></tr>"
    for defectValue in defectsSend:
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
        
        if ConfigFile.getSSL == True:
            url="http://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        else:
            url="https://"+str(ConfigFile.getHost())+":"+str(ConfigFile.getPort())+"/query/defects.htm?project="+projectName+"&cid="+str(defectValue.cid)
        body+="<tr><td><a href="+url+"\">"+str(defectValue.cid)+"</a></td><td>"+defectValue.componentName+"</td><td>"+defectValue.checkerName+"</td><td>"+hashResults['Severity']+"</td><td>"+checkerproperties[0].impact+"</td><td>"+hashResults['Owner']+"</td><td>"+str(defectValue.firstDetected)[:10]+"</td><td>"+defectValue.filePathname+"</td></tr>"
    body+="</table></body></html>"
    for userId in usersIds:
        WSCoverity.notify(userId,subject,body)