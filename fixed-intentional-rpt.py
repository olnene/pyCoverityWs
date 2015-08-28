from ConnectionService import ConnectionService
from XmlConfigFileRead import XmlConfigFileRead
from datetime import datetime, timedelta, timezone
import getopt
import sys
import string
import xlsxwriter

def extractAttributes(attributeslist):
    hashAttributetable={}
    for attribute in attributeslist:
        if hasattr(attribute.attributeValueId, 'name'):
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


checkerPropertiesHash={}
ConfigFile= XmlConfigFileRead(xmlFilePath)

WSCoverity=ConnectionService(ConfigFile.getHost(),ConfigFile.getPort(),ConfigFile.getUserName(),ConfigFile.getPassword(), ConfigFile.getSSL())
filterSpec=WSCoverity.projectScopeDefectFilterSpecDataObj(None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None)

workbook=xlsxwriter.Workbook('Defect_Resolved_Report.xlsx')
header_format=workbook.add_format({'bold':True,'font_color': 'white', 'bg_color':'#0096d6','font_name':'HP Simplified', 'align':'center','valign':'center'})
header_format_bottom=workbook.add_format({'bold':True,'font_color': 'white', 'bg_color':'#0096d6','font_name':'HP Simplified','bottom':True, 'border_color':'#FFFFFF','align':'center','valign':'center'})
data_format=workbook.add_format({'font_name':'HP Simplified'})
projects =projectName.split(",")
for prName in projects:
    defects=[]
    pageStartIndex=0
    numDefects=0
    row=3
    col=0
    domain=prName.split("-")
    while True:
        sizePage=WSCoverity.pageSpecDataObj(1000,False,None,pageStartIndex)
        defectsPage=WSCoverity.getMergedDefectsForProjectScope(prName,filterSpec,sizePage)
        pageStartIndex+=1000
        numDefects=defectsPage['totalNumberOfRecords']
        if numDefects > 0 :
            defects.extend(defectsPage['mergedDefects'])
        if pageStartIndex >= numDefects:
            break

    worksheet1=workbook.add_worksheet(prName)
    worksheet1.merge_range('A1:N1',domain[len(domain)-1]+' PROJECT',header_format)
    worksheet1.merge_range('A2:N2','Defects Resolved',header_format_bottom)
    worksheet1.set_column('A:A', 10)
    worksheet1.set_column('B:D', 40)
    worksheet1.set_column('E:F', 15)
    worksheet1.set_column('G:G', 20)
    worksheet1.set_column('H:I', 15)
    worksheet1.set_column('J:K', 30)
    worksheet1.set_column('L:N', 15)

    for dfect in defects:
        if not hasattr(dfect, 'firstDetectedSnapshotId'):
            continue
        attributes=dfect.defectStateAttributeValues
        hashResults=extractAttributes(attributes)
        if hashResults['DefectStatus'] == 'Fixed' or hashResults['Classification'] =='Intentional' or hashResults['Classification'] =='False Positive':
            snapshotInfo=WSCoverity.getSnapshotInformation(dfect.firstDetectedSnapshotId)
            dfect.firstDetected=snapshotInfo[0].dateCreated
       
            if not dfect.checkerName in checkerPropertiesHash.keys():
                if dfect.checkerName[:2] == "PW":
                    dfect.checkerName= "PW.*"
                    checkerPropertiesHash[dfect.checkerName]=[]
                    checkerPropertiesHash[dfect.checkerName]=WSCoverity.getCheckerProperties("PW.*",None,None,None,None,None,None)
                
                elif dfect.checkerName[:2] == "RW":
                    dfect.checkerName= "RW.*"
                    checkerPropertiesHash[dfect.checkerName]=[]
                    checkerPropertiesHash[dfect.checkerName]=WSCoverity.getCheckerProperties("RW.*",None,None,None,None,None,None)
                else:
                    checkerPropertiesHash[dfect.checkerName]=[]
                    checkerPropertiesHash[dfect.checkerName]=WSCoverity.getCheckerProperties(dfect.checkerName,dfect.checkerSubcategory,None,None,None,None,None)
            else:
                if dfect.checkerName[:2] == "PW":
                    dfect.checkerName= "PW.*"
                                    
                if dfect.checkerName[:2] == "RW":
                    dfect.checkerName= "RW.*"    
                            
            checkerproperties=checkerPropertiesHash[dfect.checkerName]
            worksheet1.write_number(row,col,dfect.cid,data_format)
            worksheet1.write(row,col+1,dfect.componentName,data_format)
            worksheet1.write(row,col+2,checkerproperties[0].category,data_format)
            worksheet1.write(row,col+3,dfect.filePathname,data_format)
            worksheet1.write(row,col+4,hashResults['Legacy'],data_format)
            worksheet1.write(row,col+5,hashResults['DefectStatus'],data_format)
            worksheet1.write(row,col+6,hashResults['Classification'],data_format)
            worksheet1.write(row,col+7,checkerproperties[0].impact,data_format)
            worksheet1.write(row,col+8,hashResults['Severity'],data_format)
            worksheet1.write(row,col+9,str(dfect.firstDetected)[:10],data_format)
            worksheet1.write(row,col+10,str(dfect.lastDetected)[:10],data_format)
            worksheet1.write(row,col+11,hashResults['Owner'],data_format)
            worksheet1.write_number(row,col+12,dfect.occurrenceCount,data_format)
            worksheet1.write(row,col+13,hashResults['Fix Target'],data_format)
            row+=1
    worksheet1.add_table('A3:N'+str(row), {'banded_rows': True, 'columns': [{'header': 'CID'},
                                                                            {'header': 'Component'},
                                                                            {'header': 'Type'},
                                                                            {'header': 'File'},
                                                                            {'header': 'Legacy'},
                                                                            {'header': 'Status'},
                                                                            {'header': 'Classification'},
                                                                            {'header': 'Impact'},
                                                                            {'header': 'Severity'},
                                                                            {'header': 'First Snapshot Date'},
                                                                            {'header': 'Last Snapshot Date'},
                                                                            {'header': 'Owner'},
                                                                            {'header': 'Count'},
                                                                            {'header': 'Fix Target'},],
                                           'style' : 'Table Style Medium 2' })
    worksheet1.write(2,0,'CID',header_format)
    worksheet1.write(2,1,'Component',header_format)
    worksheet1.write(2,2,'Type',header_format)
    worksheet1.write(2,3,'File',header_format)
    worksheet1.write(2,4,'Legacy',header_format)
    worksheet1.write(2,5,'Status',header_format)
    worksheet1.write(2,6,'Classification',header_format)
    worksheet1.write(2,7,'Impact',header_format)
    worksheet1.write(2,8,'Severity',header_format)
    worksheet1.write(2,9,'First Snapshot Date',header_format)
    worksheet1.write(2,10,'Last Snapshot Date',header_format)
    worksheet1.write(2,11,'Owner',header_format)
    worksheet1.write(2,12,'Count',header_format)
    worksheet1.write(2,13,'Fix Target',header_format)


workbook.close()