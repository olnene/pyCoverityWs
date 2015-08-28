from suds.client import Client
from suds.wsse import *
import socket, logging
import suds
CURSOR=None
__ConfServiceClient=None
__DefServiceClient=None
__host = None
__port = None
__usr =  None
__pwd =  None
__ssl =  None

class ConnectionService(object):
    """Connnection Initialization.
     :param: 
            host [string]  => host name or ip-address.
            port [string]  => Port connection.
            usr  [string]  => Username.
            pwd  [string]  => Password.
            ssl  [boolean] => Use https and ssl security."""
    def __init__( self , host , port , usr , pwd, ssl):
        socket.setdefaulttimeout(None)
        logging.basicConfig(level=logging.INFO)
        logging.getLogger("suds.client").setLevel(logging.INFO)
             
        self.__host = host 
        self.__port = port 
        self.__usr =  usr 
        self.__pwd = pwd
        self.__ssl = ssl
        self.__confservice()
        self.__defservice()
#Create the object for the ConfigurationService connection   
    def __confservice(self):
        if self.__ssl == True:
            Url="https://"+self.__host+":"+self.__port
        else:
            Url="http://"+self.__host+":"+self.__port
        SrvWsdl=Url+"/ws/v8/configurationservice?wsdl"
        Security=suds.wsse.Security()
        Security.tokens.append(suds.wsse.UsernameToken(self.__usr, self.__pwd))
        self.__ConfServiceclient=suds.client.Client(SrvWsdl, timeout=3600)
        self.__ConfServiceclient.set_options(wsse=Security)
 
#Create the object for DefectService connection.
    def __defservice(self):
        if self.__ssl == True:
            Url="https://"+self.__host+":"+self.__port
        else:
            Url="http://"+self.__host+":"+self.__port
        SrvWsdl=Url+"/ws/v8/defectservice?wsdl"
        Security=suds.wsse.Security()
        Security.tokens.append(suds.wsse.UsernameToken(self.__usr, self.__pwd))
        self.__DefServiceclient=suds.client.Client(SrvWsdl, timeout=3600)
        self.__DefServiceclient.set_options(wsse=Security)
              
# METHOD: ConfigurationService->getProjects.
    def getProjects(self, descriptionPattern, includeChildren, includeStreams, namePattern):
        """Get a list of projects specifications (for all projects or for all filtered set of projects).
        :param:
                descriptionPattern [string] => Glob pattern matching the description of one or more projects.
                includeChildren    [boolean]=> Value of false if the results should not include roles and other properties associated with the project. Defaults to true.
                includeStreams     [boolean]=> Value of false if the results should not include streams associated with the project. Defaults to true.
                namePattern        [string] => Glob pattern matching the name of one or more projects."""
        projectfilter=self.__ConfServiceclient.factory.create("projectFilterSpecDataObj")
        projectfilter.descriptionPattern = descriptionPattern
        projectfilter.includeChildren = includeChildren
        projectfilter.includeStreams = includeStreams
        projectfilter.namePattern= namePattern
        try:
            return  self.__ConfServiceclient.service.getProjects(projectfilter)
        except suds.WebFault as detail:
            return detail
            
# METHOD: ConfigurationService->copyStream.
    def copyStream(self, projectName, streamName):
        """Make a copy of a stream. Does noy copy stream role assignments.
        :param:
                name [string] => Required. Name of the project.
                name [string] => Required. Name of the stream."""
        projectIdDataObj=self.__ConfServiceclient.factory.create("projectIdDataObj")
        projectIdDataObj.name=projectName
        streamIdObj=self.__ConfServiceclient.factory.create("streamIdObj")
        streamIdObj.name=streamName
        try:
            return self.__ConfServiceclient.service.copyStream(projectIdDataObj, streamIdObj)
        except suds.WebFault as detail:
            return detail
             
# METHOD: ConfigurationService->createAttribute.
    def createAttribute(self, attributeName, attributeType, attributeValueChangeSpecData, defaultValue, description, showInTriage):
        """"Create an attribute.
        :param:
                attributeName [string] => Name of the attribute. Required
                attributeType [string] => The type of attribute. Required
                attributeValueChangeSpec [attributeValueChangeSpecDataObj] => For a LIST_OF_VALUES attribute type only: The set of values available to the attribute.
                defaultValue [string]    => For a LIST_OF_VALUES attribute type only: The default attribute value.
                description  [string]  => Descriptions of the attribute
                showInTriage [boolean] => If true, makes the attribute available for use in the Triage pane of the UI."""
        attributeDefinitionSpecDataObj= self.__ConfServiceclient.factory.create("attributeDefinitionSpecDataObj")
        attributeDefinitionSpecDataObj.attributeName= attributeName
        attributeDefinitionSpecDataObj.attributeType= attributeType
        attributeDefinitionSpecDataObj.attributeValueChangeSpec= attributeValueChangeSpecData
        attributeDefinitionSpecDataObj.defaultValue= defaultValue
        attributeDefinitionSpecDataObj.description= description
        attributeDefinitionSpecDataObj.showInTriage=showInTriage
        try:
            self.__ConfServiceclient.service.createAttribute(attributeDefinitionSpecDataObj)
            return "Attribute created"
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getAllLdapConfigurations
    def getAllLdapConfigurations(self):
        """Return all LDAP Configurations."""
        return self.__ConfServiceclient.service.getAllLdapConfigurations()

# METHOD: ConfigurationService->getAttribute.
    def getAttribute(self, name):
        """Retrieve the properties of a specified attribute.
        :param:
                name [string] => Required. Name of the attribute."""
        attributeDefinitionId=self.__ConfServiceclient.factory.create("attributeDefinitionIdDataObj")
        attributeDefinitionId.name = name
        try:
            return self.__ConfServiceclient.service.getAttribute(attributeDefinitionId)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getCheckerProperties.
    def getCheckerProperties(self, checkerNameList, subcategoryList, domainList, categoryList, cweCategoryList, impactList, projectIdname):
        """Retrieve a list of available checker properties.
        :param:
                checkerNameList [string] => Name of the checker. Zero or more checker names allowed.
                subcategoryList [string] => Subcategorization of the software issue found by the checker.
                domainList      [string] => Domain of the checker. Zero or more domains allowed.
                categoryList    [string] => Categorization of the software issue found by checker. Zero or more categories allowed.
                cweCategoryList [string] => Common Weakness Enumeration identifier of the type of issue found by the checker. Zero or more identifiers allowed.
                impactList      [string] => Probable impact (High, Medium, or Low) of the issue found by the checker. Zero or more impact levels allowed.
                projectIdname   [string] => Required. Name of the project."""
        filterSpec= self.__ConfServiceclient.factory.create("checkerPropertyFilterSpecDataObj")
        projectId= self.__ConfServiceclient.factory.create("projectIdDataObj")
        projectId.name= projectIdname
        filterSpec.checkerNameList= checkerNameList
        filterSpec.subcategoryList= subcategoryList
        filterSpec.domainList= domainList
        filterSpec.categoryList= categoryList
        filterSpec.cweCategoryList= cweCategoryList
        filterSpec.impactList= impactList
        filterSpec.projectId= projectId
        try:
            return self.__ConfServiceclient.service.getCheckerProperties(filterSpec)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfiguratioService->getComponent.
    def getComponent(self, name):
        """Retrieve the properties of a component.
        :param:
                name [string] => Required. Name of a component in the form componentMapName.componentName (for example, myComponentMap.myComponent)."""
        componentId= self.__ConfServiceclient.factory.create("componentIdDataObj")
        componentId.name =name
        try:
            return self.__ConfServiceclient.service.getComponent(componentId)
        except suds.WebFault as detail:
            return detail
       
# METHOD: ConfigurationService->getComponentMaps.
    def getComponentMaps(self, namePattern):
        """Retrieve a list of component maps that matches a component name pattern.
        :param:
                namePattern [string] => Glob pattern matching the name of one or more component maps."""
        filterSpec= self.__ConfServiceclient.factory.create("componentMapFilterSpecDataObj")
        filterSpec.namePattern= namePattern
        try:
            return self.__ConfServiceclient.service.getComponentMaps(filterSpec)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getDefectStatuses.
    def getDefectStatuses(self):
        """Retrieve a list of Status attribute values that can be associated with a software issue."""
        return self.__ConfServiceclient.service.getDefectStatuses()

# METHOD: ConfigurationService->getGroup.
    def getGroup(self, displayName, domain, name):
        """Retrieve the properties of a user group.
        :param:
                displayName [string] => The name of a user group. To retrieve an LDAP group, you use <groupname>@<LDAPserver>.
                domain      [string] => Name of the LDAP server domain.
                name        [string] => Required. Name of the local or LDAP group."""
        groupId=self.__ConfServiceclient.factory.create("groupIdDataObj")
        domainId= self.__ConfServiceclient.factory.create("serverDomainDataObj")
        domainId.name= domain
        groupId.displayName= displayName
        groupId.domain= domainId
        groupId.name= name
        try:
            return self.__ConfServiceclient.service.getGroup(groupId)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getGroups.
    def getGroups(self, ldap, namePattern, name, userList):
        """Get a list of groups.
        :param:
                ldap        [boolean] => Value of true for LDAP groups only; otherwise, false.
                namePattern [string]  => Glob pattern matching the name of one or more groups.
                name        [string]  => Name of a project with which the group must have a role association.
                userList    [string]  => User name of a user that must belong to the group."""
        filterSpec= self.__ConfServiceclient.factory.create("groupFilterSpecDataObj")
        projectIdDataObj= self.__ConfServiceclient.factory.create("projectIdDataObj")
        projectIdDataObj.name= name
        filterSpec.ldap= ldap
        filterSpec.namePattern = namePattern
        filterSpec.projectIdDataObj= projectIdDataObj
        filterSpec.userList= userList
        try:
            return self.__ConfServiceclient.service.getGroups(filterSpec)
        except suds.WebFault  as detail:
            return detail
        
# METHOD: ConfigurationService->getSnapshotInformation.
    def getSnapshotInformation(self, id):
        """Retrieve information about a snashot in a stream.
        :param:
                id [long] => Numeric identifier for the snapshot. Required."""
        snapshotIdData=self.__ConfServiceclient.factory.create("snapshotIdDataObj")
        snapshotIdData.id=id
        try:
            return self.__ConfServiceclient.service.getSnapshotInformation(snapshotIdData)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getSnapshotsForStream.
    def getSnapshotsForStream(self, name):
        """Retrieve a set of snapshots that belong to a spcecified stream.
        :param:
                name [string] => Required. Name of the stream."""
        streamId= self.__ConfServiceclient.factory.create("streamIdDataObj")
        streamId.name= name
        try:
            return self.__ConfServiceclient.service.getSnapshotsForStream(streamId)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getStreams.
    def getStreams(self, languageList, descriptionPattern, namePattern):
        """Retrieve a set of streams.
        :param:
                languageList       [string] => Programming language matching that of one or more streams. Zero or more language filters allowed.
                descriptionPattern [string] => Glob pattern matching the description of one or more streams.
                namePattern        [string] => Glob pattern matching the name of one or more streams."""
        filterSpec= self.__ConfServiceclient.factory.create("streamFilterSpecDataObj")
        filterSpec.languageList= languageList
        filterSpec.descriptionPattern= descriptionPattern
        filterSpec.namePattern= namePattern
        try:
            return self.__ConfServiceclient.service.getStreams(filterSpec)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getUser.
    def getUser(self,username):
        """Retrieve a user by user name.
        :param:
                username [string] => User name."""
        try:
            return self.__ConfServiceclient.service.getUser(username)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->getUsers.
    def getUsers(self, assignable, disabled, groupList, includeDetails, ldap, locked, namePattern, name, pageSpecData):
        """Get users (filtered or unfiltered).
        :param:
                assignable     [boolean] => Set to true to retrieve only those users who can own software issues; false to retrieve only those who cannot. Otherwise, do not set.
                disabled       [boolean] => Set to true to retrieve disabled users only. Set to false to retrieve enabled users only. Otherwise, do not set.
                groupList      [string]  => Name of user group to which the retrieved users must belong. Zero or more groups allowed.
                includeDetails [boolean] => Set to false to prevent the inclusion of role assignments and other user details in the reqponse. Defaults to true.
                ldap           [boolean] => Set to true to retrieve only LDAP users; false to retrieve only local users. Otherwise, do not set.
                locked         [boolean] => Set to true to retrieve only those users who have been locked out; false to retrieve only unlocked users. Otherwise, do not set.
                namePattern    [string]  => Glob pattern that matches the user name of the users to retrieve.
                name           [string]  => Name of project to which the retrieved set of users must have a role association."""
        filterSpec= self.__ConfServiceclient.factory.create("userFilterSpecDataObj")
        projectIdDataObj= self.__ConfServiceclient.factory.create("projectIdDataObj")
        projectIdDataObj.name= name
        filterSpec.assignable= assignable
        filterSpec.disabled= disabled
        filterSpec.groupsList= groupList
        filterSpec.includeDetails= includeDetails
        filterSpec.ldap= ldap
        filterSpec.locked= locked
        filterSpec.namePattern= namePattern
        filterSpec.projectIdDataObj= projectIdDataObj
        try:
            return self.__ConfServiceclient.service.getUsers(filterSpec,pageSpecData)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->notify.
    def notify(self, usernames, subject, message):
        """Send an emmail notification to a specified user.
        :param:
                usernames [string] => One or more usernames.
                subject   [string] => Subject-line text for the email.
                message   [string] => Body text for the email."""
        try:
            return self.__ConfServiceclient.service.notify(usernames, subject, message)
        except suds.WebFault as detail:
            return detail

# METHOD: ConfigurationService->updateAttribute.
    def updateAttribute(self, attributeName, attributeType, attributeValueChangeSpecData, defaultValue, description, showInTriage):
        """Update an attribute specification.
        attributeName  [string] =>  Required. Name for the attribute.
        attributeType  [string] =>  The type of attribute. Required when using createAttribute().
        attributeValueChangeSpec  [attributeValueChangeSpecDataObj] => For a LIST_OF_VALUES attribute type only: The set of values available to the attribute.
        defaultValue   [string] => For a LIST_OF_VALUES attribute type only: The default attribute value.
        description    [string] => Description of the attribute.
        showInTriage   [boolean]=> If true, makes the attribute available for use in the Triage pane of the UI."""
        attributeDefinitionId= self.__ConfServiceclient.factory.create("attributeDefinitionDataObj")
        attributeDefinitionId= attributeName
        attributeDefinitionSpec= self.__ConfServiceclient.factory.create("attributeDefinitionSpecDataObj")
        attributeDefinitionSpec.attributeName= None
        attributeDefinitionSpec.attributeType= attributeType
        attributeDefinitionSpec.attributeValueChangeSpec= attributeValueChangeSpecData
        attributeDefinitionSpec.defaultValue= defaultValue
        attributeDefinitionSpec.description= description
        attributeDefinitionSpec.showInTriage= showInTriage
        try:
            self.__ConfServiceclient.service.updateAttribute(attributeDefinitionId, attributeDefinitionSpec)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getCheckerSubcategoriesForProject.
    def getCheckerSubcategoriesForProject(self, name):
        """Retrieve a list of subcatergories of software issues in the project that were found by checkers used in the analysis.
        :param:
                name [string] => Required. Name of the project."""
        projectId= self.__DefServiceclient.factory.create("projectIdDataObj")
        projectId.name = name
        try:
            return self.__DefServiceclient.service.getCheckerSubcategoriesForProject(projectId)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getCheckerSubcategoriesForStreams.
    def getCheckerSubcategoriesForStreams(self, name):
        """Retrieve a list of subcategories of software issues in the stream that were found by checkers used in the analysis.
        :param:
                name [string] => Required. Name of the stream."""
        streamIds= self.__DefServiceclient.factory.create("streamIdDataObj")
        streamIds.name= name
        try:
            return self.__DefServiceclient.service.getCheckerSubcategoriesForStreams(streamIds)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getComponentMetricsForProject .
    def getComponentMetricsForProject (self, projectName, componentName):
        """Retrieve metrics on components associated with streams in a specific project.
        :param:
                projectName   [string] => Required. Name of the project.
                componentName [string] => Name of the component in the project in the form [ComponentMap].[component]."""
        projectId= self.__DefServiceclient.factory.create("projectIdDataObj")
        projectId.name= projectName
        componentIds= self.__DefServiceclient.factory.create("componentIdDataObj")
        componentIds.name= componentName
        try:
            return self.__DefServiceclient.service.getComponentMetricsForProject(projectId,componentIds)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getFileContents.
    def getFileContents(self, name, contentsMD5, filePathname):
        """Retrieve the Base64-encoded contents of a file that contains an instance of a CID.
        :param:
                name         [string] => Required. Name of the stream.
                contentMD5   [string] => Required. MD5 checksum (a fingerprint or message digest) of the file contents. 
                                     You can get the contentsMD5 and filePathname for an instance of a CID by using getStreamDefects() with the includeDefectInstances filter set to true.
                filePathname [string] => Required. Path to the file that contains the instance of the CID. 
                                     You can get the contentsMD5 and filePathname for an instance of a CID by using getStreamDefects() with the includeDefectInstances filter set to true."""
        streamId= self.__DefServiceclient.factory.create("streamIdDataObj")
        streamId.name =name
        fileId= self.__DefServiceclient.factory.create("fileIdDataObj")
        fileId.contentMD5= contentsMD5
        fileId.filePathname= filePathname
        try:
            return self.__DefServiceclient.service.getFileContents(streamId, fileId)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getMergedDefectDetectionHistory.
    def getMergedDefectDetectionHistory(self, cid, mergeKey, name):
        """Retrieves detection history for a software issue. The return data is similar to the Detection History information in the Coverity Connect UI.
        :param:
                cid      [long]   => CID.
                mergeKey [string] => Numeric key for a CID.
                name     [string] => Required. Name of the stream."""
        mergedDefectIdDataObj= self.__DefServiceclient.factory.create("mergedDefectIdDataObj")
        streamIds= self.__DefServiceclient.factory.create("streamIdDataObj")
        mergedDefectIdDataObj.cid= cid
        mergedDefectIdDataObj.mergeKey= mergeKey
        streamIds.name= name
        try:
            return self.__DefServiceclient.service.getMergedDefectDetectionHistory(mergedDefectIdDataObj, streamIds)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getMergedDefectHistory.
    def getMergedDefectHistory(self, cid, mergeKey, name):
        """Retrieve a date and time stamped list of changes to attributes used to triage a specified CID.
        :param:
                cid      [long]   => CID.
                mergeKey [string] => Numeric key for a CID.
                name     [string] => Required. Name of the stream."""
        mergedDefectIdDataObj= self.__DefServiceclient.factory.create("mergedDefectIdDataObj")
        streamIds= self.__DefServiceclient.factory.create("streamIdDataObj")
        mergedDefectIdDataObj.cid= cid
        mergedDefectIdDataObj.mergeKey= mergeKey
        streamIds.name= name
        try:
            return self.__DefServiceclient.service.getMergedDefectHistory(mergedDefectIdDataObj,streamIds)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getMergedDefectsForProjectScope.
    def getMergedDefectsForProjectScope(self, name, projectScopeDefectFilterSpecData, pageSpecData):
        """Retrieve CIDs (filtered or unfiltered) that are in a specified project. 
        :param:
                name [string] => Required. Name of the project.
                projectScopeDefectFilterSpecData [projectScopeDefectFilterSpecDataObj] => An optional filters on the results to return.
                pageSpecData [pageSpecDataObj] => Page specifications for results."""
        projectId= self.__DefServiceclient.factory.create("projectIdDataObj")
        projectId.name= name
        try:
            return self.__DefServiceclient.service.getMergedDefectsForProjectScope(projectId,projectScopeDefectFilterSpecData,pageSpecData)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getMergedDefectsForSnapshotScope.
    def getMergedDefectsForSnapshotScope(self, name, snapshotScopeDefectFilterSpecData, pageSpecData):
        """Retrieve CIDs (filtered or unfiltered) that are in the current or specified snapshots. Optionally, perform snapshot comparisons.
        :param:
                name [string] => Required. Name of the project.
                projectScopeDefectFilterSpecData [projectScopeDefectFilterSpecDataObj] => An optional filters on the results to return.
                pageSpecData [pageSpecDataObj] => Page specifications for results.""" 
        projectId= self.__DefServiceclient.factory.create("projectIdDataObj")
        projectId.name= name
        try:
            return self.__DefServiceclient.service.getMergedDefectsForSnapshotScope(projectId, snapshotScopeDefectFilterSpecData,pageSpecData)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getMergedDefectsForStreams.
    def getMergedDefectsForStreams(self, name, mergedDefectFilterSpecData, pageSpecData, compareOutdatedStreams, compareSelector, showOutdatedStreams, showSelector):
        """Retrieve the current attributes and other properties of CIDs (filtered or unfiltered) in a specified stream.
        :param:
                name                   [string] => Required. Name of the stream.
                mergedDefectFilterSpecData [mergedDefectFilterSpecDataObj] => Filter properties used to match CIDs to return from the specified stream.
                pageSpecData           [pageSpecDataObj] => Page specifications for results.
                compareOutdatedStreams [boolean] => If set to true, includes outdated streams found in snapshots specified by compareSelector. If false, the default, only non-outdated streams are included.
                compareSelector        [string] => Snapshot ID or snapshot grammar value that is used to set the scope of snapshots to compare with the showSelector snapshot scope.
                showOutdatedStreams    [boolean] => If set to true, includes outdated streams found in snapshots specified by showSelector. If false, the default, only non-outdated streams are included.
                showSelector           [string] => Required: Snapshot ID or snapshot grammar value that is used to set the scope of snapshots
                                                   Default: last() which iincludes the latest snapshot of each stream in the project."""
        streamIds= self.__DefServiceclient.factory.create("streamIdDataObj")
        snapshotScope= self.__DefServiceclient.factory.create("snapshotScopeSpecDataObj")
        streamIds.name= name
        snapshotScope.compareOutdatedStreams= compareOutdatedStreams
        snapshotScope.compareSelector= compareSelector
        snapshotScope.showOutdatedStreams= showOutdatedStreams
        snapshotScope.showSelector= showSelector
        try:
            return self.__DefServiceclient.service.getMergedDefectsForStreams(streamIds, mergedDefectFilterSpecData, pageSpecData, snapshotScope)
        except suds.WebFault as detail:
            return detail
        
# METHOD: DefectService->getStreamDefects.
    def getStreamDefects(self, cid, mergeKey, defectStateEndDate, defectStateStartDate, includeDefectInstances, includeHistory, name):
        """Retrieve instances of software issues for one or more CIDs.
        :param:
               cid                   [long]    => CID.
               mergeKey              [string]  => Numeric key for a CID.
               defectStateEndDate    [dateTime]=> Ending date (and optionally, time) for the CIDs to return.   
               defectStateStartDate  [dateTime]=> Starting date (and optionally, time) for the CIDs to return.
               includeDefectInstances[boolean] => Set to true for data on each instance of software issue, including the ID. Defaults to false. 
               includeHistory        [boolean] => Set to true for historical triage data on each instance of the software issue. 
               name                  [string]  => Required. Name of the stream """
        mergedDefectIdDataObjs= self.__DefServiceclient.factory.create("mergedDefectIdDataObj")
        filterSpec= self.__DefServiceclient.factory.create("streamDefectFilterSpecDataObj")
        streamIdDataObj= self.__DefServiceclient.factory.create("streamIdDataObj")
        streamIdDataObj.name= name
        mergedDefectIdDataObjs.cid= cid
        mergedDefectIdDataObjs.mergeKey= mergeKey
        filterSpec.defectStateEndDate= defectStateEndDate
        filterSpec.defectStateStartDate= defectStateStartDate
        filterSpec.includeDefectInstances= includeDefectInstances
        filterSpec.includeHistory= includeHistory
        filterSpec.streamIdList= streamIdDataObj
        try:
            return self.__DefServiceclient.service.getStreamDefects(mergedDefectIdDataObjs, filterSpec)
        except suds.WebFault as detail:
            return detail
 
# METHOD: DefectService->getTrendRecordsForProject.
    def getTrendRecordsForProject(self, name, endDate, startDate):
        """Retrieve daily records on CIDs and source code in a project.
        :param:
                name      [string]   => Required. Name of the project.
                endDate   [dateTime] => End date (and optionally, time)  for the set of records to retrieve.
                startDate [dateTime] => Start date (and optionally, time) for the set of records to retrieve."""
        projectId= self.__DefServiceclient.factory.create("projectIdDataObj")
        filterSpec= self.__DefServiceclient.factory.create("projectTrendRecordFilterSpecDataObj")
        projectId.name = name
        filterSpec.endDate= endDate
        filterSpec.startDate= startDate
        try:
            return self.__DefServiceclient.service.getTrendRecordsForProject(projectId, filterSpec)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->getTriageHistory.
    def getTriageHistory(self, cid, mergeKey, name):
        """Retrieve the triage history for a software issue.
        :param:
                cid      [long]   => CID.
                mergeKey [string] => Numeric key for a CID.
                name     [string] => Required. Name of the triage store."""
        mergedDefectIdDataObj= self.__DefServiceclient.factory.create("mergedDefectIdDataObj")
        triageStoreIds= self.__DefServiceclient.factory.create("triageStoreIdDataObj")
        mergedDefectIdDataObj.cid= cid
        mergedDefectIdDataObj.mergeKey= mergeKey
        triageStoreIds.name= name
        try:
            return self.__DefServiceclient.service.getTriageHistory(mergedDefectIdDataObj, triageStoreIds)
        except suds.WebFault as detail:
            return detail

# METHOD: DefectService->updateStreamDefects.
    def updateStreamDefects(self, defectTriageId, defectTriageVerNum, id, verNum, defectStateAttributeValues):
        """Update the one or more attribute values for all instances of a CID found in a given stream. Note that this update will apply to all instances of the CID in all streams that share the same triage store. 
        :param:
                defectTriageId      [long] => Internal value for the last known triage ID. This ID changes when developers triage the issue that is associated with the id.
                defectTriageVerNum  [int]  => Internal value for the last known triage version. This number changes when developers triage the issue that is associated with the id.
                id                  [long] => Internal identifier for the software issue within the context of the stream.
                verNum              [int]  => Version number associated with the id. 
                defectStateAttributeValues  [defectStateAttributeValueDataObj] => Attribute name/value pair. One or more pairs required. """
        streamDefectIds= self.__DefServiceclient.factory.create("streamDefectIdDataObj")
        defectStateSpec= self.__DefServiceclient.factory.create("defectStateSpecDataObj")
        streamDefectIds.defectTriageId=defectTriageId
        streamDefectIds.defectTriageVerNum= defectTriageVerNum
        streamDefectIds.id= id
        streamDefectIds.verNum= verNum
        defectStateSpec.defectStateAttributeValues= defectStateAttributeValues
        try:
            self.__DefServiceclient.service.updateStreamDefects(streamDefectIds, defectStateSpec)
        except suds.WebFault as detail:
            return detail
        
# METHOD: DefectService->updateTriageForCIDsInTriageStore.
    def updateTriageForCIDsInTriageStore(self, name, cid, mergeKey, defectStateAttributeValues):
        """Update one or more attribute values for a CID in a specified triage store.
        :param:
                name     [string] => Required. Name of triage store.
                cid      [long]   => CID.
                mergeKey [string] => Numeric key for a CID.
                defectStateAttributeValues [defectStateAttributeValueDataObj] => Attribute name/value pair. One or more pairs required."""
        triageStore= self.__DefServiceclient.factory.create("triageStoreIdDataObj")
        mergedDefectIdDataObjs= self.__DefServiceclient.factory.create("mergedDefectIdDataObj")
        defectState= self.__DefServiceclient.factory.create("defectStateSpecDataObj")
        triageStore.name = name
        mergedDefectIdDataObjs.cid= cid
        mergedDefectIdDataObjs.mergeKey= mergeKey
        defectState.defectStateAttributeValues= defectStateAttributeValues
        try:
            self.__DefServiceclient.service.updateTriageForCIDsInTriageStore(triageStore, mergedDefectIdDataObjs, defectState)
        except suds.WebFault as detail:
            return detail

# DATA_TYPE: Create attributeValueChangeSpecDataObj  data type.
    def attributeValueChangeSpec(self, attributeValueIds, attributeValues):
        """Create attributeValueChangeSpecDataObj  data type.
        :param:
                attributeValueIds [attributeValueIdDataObj]    => Automatically generated set of IDs for attribute values.
                attributeValues   [ attributeValueSpecDataObj] => Set of values available to an attribute."""
        attributeValueChangeSpecDataObj= self.__ConfServiceclient.factory.create("attributeValueChangeSpecDataObj")
        attributeValueChangeSpecDataObj.attributeValueIds= attributeValueIds
        attributeValueChangeSpecDataObj.attributeValues= attributeValues
        return attributeValueChangeSpecDataObj 

# DATA_TYPE: Create attributeValueIdDataObj data type.
    def attributeValueIdsDataObj(self, name):
        """Create attributeValueIdDataObj data type
        :param:
                name [string] => Name of the automatically generated ID for the attribute value. Do not specify when creating an attribute value."""
        attributeValueIds= self.__ConfServiceclient.factory.create("attributeValueIdDataObj")
        attributeValueIds.name = name
        return attributeValueIds

# DATA_TYPE: Create attributeValueSpecDataObj data type.
    def attributeValues(self, deprecated, name):
        """Create attributeValueSpecDataObj data type.
        :param:
                deprecated [boolean] => Value of true if the specified attribute value is deprecated. Otherwise, false.
                name       [string]  => Name of the attribute value."""
        attributeValueSpecDataObj=self.__ConfServiceclient.factory.create("attributeValueSpecDataObj")
        attributeValueSpecDataObj.deprecated= deprecated
        attributeValueSpecDataObj.name= name
        return attributeValueSpecDataObj

# DATA_TYPE: Create projectScopeDefectFilterSpecDataObj data type.
    def projectScopeDefectFilterSpecDataObj(self, actionNameList, checkerCategoryList, checkerList, checkerTypeList, cidList, 
                                            clssificationNameList, componentIdExclude, componentIdList, cweList, firstDetectedEndDate, 
                                            firstDetectedStartDate, fixTargetNameList, impactNameList, issueKindList, lastDetectedEndDate,
                                            lastDetectedStartDate, legacyNameList, ownerNameList, ownerNamePattern, severityNameList):
        """Create projectScopeDefectFilterSpecDataObj data type.
        :param:
                actionNameList         [string]  => Name/value pairs for a list of attributes.
                checkerCategoryList    [string]  => List of checker categories.
                checkerList            [string]  => List of checkers.
                checkerTypeList        [string]  => List of checker types.
                cidList                [long]    => List of CIDs.
                classificationNameList [string]  => Classification of the CID.
                componentIdExclude     [boolean] => If one or more component name filters is specified, set to true to exclude matching results from the specified components. 
                                                    Defaults to false, including the matches from the components in the results.
                componentIdList        [string]  => Name of a component that contains the CID. 
                cweList                [long]    => Common Weakness Enumeration identifier of the type of issue found by the checker. Zero or more identifiers allowed.
                firstDetectedEndDate   [dateTime]=> Ending date (and optionally, time) for the date range matching the First Detected date of a CID.
                                                    Example1: 2013-03-18T12:42:19.384-07:00  Example2: 2013-03-18
                firstDetectedStartDate [dateTime]=> Starting date (and optionally, time) for the date range matching the First Detected date of a CID. 
                fixTargetNameList      [string]  => Fix target for the CID; a triage value for the CID.
                impactNameList         [string]  => Probable impact (High, Medium, or Low) of the issue found by the checker. Zero or more impact levels allowed.
                issueKindList          [string]  => Issue kind.
                lastDetectedEndDate    [dateTime]=> Ending date (and optionally, time) for the date range matching the Last Detected date of a CID.
                lastDetectedStartDate  [dateTime]=> Starting date (and optionally, time) for the date range matching the Last Detected date of a CID.
                legacyNameList         [string]  => Legacy designation for the CID (true or false), a triage value for the CID. Built-in attribute. Defaults to false.
                ownerNameList          [string]  => Owner of the CID.
                ownerNamePattern       [string]  => Glob pattern matching the first or last name of the owner of a CID.
                severityNameList       [string]  => Severity of the CID; a triage value for the CID."""
        filterSpec= self.__DefServiceclient.factory.create("projectScopeDefectFilterSpecDataObj")
        componentIdDataObj= self.__DefServiceclient.factory.create("componentIdDataObj")
        componentIdDataObj.name = componentIdList
        filterSpec.actionNameList=actionNameList
        filterSpec.checkerCategoryList= checkerCategoryList
        filterSpec.checkerList= checkerList
        filterSpec.checkerTypeList= checkerTypeList
        filterSpec.cidList= cidList
        filterSpec.classificationNameList= clssificationNameList
        filterSpec.componentIdExclude= componentIdExclude
        filterSpec.componentIdList=componentIdDataObj
        filterSpec.cweList= cweList
        filterSpec.firstDetectedEndDate= firstDetectedEndDate
        filterSpec.firstDetectedStartDate= firstDetectedStartDate
        filterSpec.fixTargetNameList= fixTargetNameList
        filterSpec.impactNameList= impactNameList
        filterSpec.issueKindList= issueKindList
        filterSpec.lastDetectedEndDate= lastDetectedEndDate
        filterSpec.lastDetectedStartDate= lastDetectedStartDate
        filterSpec.legacyNameList= legacyNameList
        filterSpec.ownerNameList= ownerNameList
        filterSpec.ownerNamePattern= ownerNamePattern
        filterSpec.severityNameList= severityNameList
        return filterSpec

# DATA_TYPE: Create  pageSpecDataObj data type.
    def  pageSpecDataObj(self, pageSize, sortAscending, sortField, startIndex):
        """Create  pageSpecDataObj data type.
        :param:
                pageSize       [int]     => Required. Up to 1000 records per page.
                sortAscending  [boolean] => Set to false to return records in reverse alphabetical or numerical order. Defaults to true.
                sortField      [string]  => Name of the field to use for sorting results. Not all fields are supported. However, you can typically sort by a field that returns numeric results, such as cid and the date fields.
                startIndex     [int]     => Zero-based index of records to return. Defaults to 0."""
        pageSpec= self.__DefServiceclient.factory.create("pageSpecDataObj")
        pageSpec.pageSize= pageSize
        pageSpec.sortAscending= sortAscending
        pageSpec.sortField= sortField
        pageSpec.startIndex= startIndex
        return pageSpec

# DATA_TYPE: Create snapshotScopeDefectFilterSpecDataObj data type.
    def snapshotScopeDefectFilterSpecDataObj(self, actionNameList, attributeDefinitionValueFilterMap, checkerCategoryList, checkerList, checkerTypeList,
                                             cidList, classificationNameList, componentIdExclude, componentIdList, cweList, externalReference, fileName,
                                             firstDetectedEndDate, firstDetectedStartDate, fixTargetNameList, functionMergeName, functionName, impactNameList,
                                             issueComparison, issueKindList, lastDetectedEndDate, lastDetectedStartDate, legacyNameList, maxOccurrenceCount,
                                             mergeExtra, mergeKey, minOccurrenceCount, ownerNameList, ownerNamePattern, severityNameList, statusNameList,
                                             streamExcludeNameList, streamExcludeQualifier, streamIncludeNameList, streamIncludeQualifier):
        """Create snapshotScopeDefectFilterSpecDataObj.
        :param:
                actionNameList 	                  [string]                                   => Name/value pairs for a list of attributes.
                attributeDefinitionValueFilterMap [attributeDefinitionValueFilterMapDataObj] => Specification of an attribute value.
                checkerCategoryList 	          [string]                                   => List of checker categories.
                checkerList 	                  [string]                                   => List of checkers.
                checkerTypeList 	              [string]                                   => List of checker types.
                cidList 	                      [long]                                     => List of CIDs.
                classificationNameList            [string]                                   => Classification of the CID. 
                componentIdExclude 	              [boolean]                                  => If one or more component name filters is specified, set to true to exclude matching results from the specified components. 
                                                                                                Defaults to false, including the matches from the components in the results.
                componentIdList                   [componentIdDataObj]                       => Name of a component that contains the CID. 
                cweList 	                      [long]                                     => Common Weakness Enumeration identifier of the type of issue found by the checker. Zero or more identifiers allowed.
                externalReference                 [string]                                   => An external reference for a CID that is used by your company to identify the software issue. Corresponds to a field in the Coverity Connect triage pane.
                fileName 	                      [string]                                   => A file name. Example: /test.c
                firstDetectedEndDate              [dateTime]                                 => Ending date (and optionally, time) for the date range matching the First Detected date of a CID.
				                                                                                Example1: 2013-03-18T12:42:19.384-07:00 Example2: 3/18/2013
                firstDetectedStartDate            [dateTime]                                 => Starting date (and optionally, time) for the date range matching the First Detected date of a CID.
		        fixTargetNameList 	              [string]                                   => Fix target for the CID; a triage value for the CID.
                functionMergeName 	              [string]                                   => Internal function name used as one of the criteria for merging separate occurrences of the same software issue, 
                                                                                                with the result that they are identified by the same CID.
                functionName 	                  [string]                                   =>	Name of the function or method.
                impactNameList 	                  [string]                                   =>	Probable impact (High, Medium, or Low) of the issue found by the checker. Zero or more impact levels allowed.
                issueComparison 	              [string]                                   =>	If set to PRESENT, returns overlapping CIDs in a snapshot comparison, that is, CIDs found in snapshot(s) to which both the showSelector and compareSelector values of the snaphotScope parameter (snapshotScopeSpecDataObj) apply.
                                                                                                If set to ABSENT, returns CIDs that are present in the snapshot(s) to which the showSelector value applies but absent from those to which the compareSelector value applies. 
                                                                                                If not set, values are PRESENT and ABSENT.
                issueKindList 	                  [string]                                   =>	Issue kind. 
                lastDetectedEndDate 	          [dateTime]                                 =>	Ending date (and optionally, time) for the date range matching the Last Detected date of a CID.
		        lastDetectedStartDate 	          [dateTime]                                 =>	Starting date (and optionally, time) for the date range matching the Last Detected date of a CID.
		        legacyNameList 	                  [string]                                   =>	Legacy designation for the CID (true or false), a triage value for the CID. Built-in attribute. Defaults to false.
                maxOccurrenceCount 	              [int]                                      =>	Maximum number of instances of software issues associated with a given CID.
		        mergeExtra 	                      [string]                                   =>	Internal property used as one of the criteria for merging occurrences of an issue.
                mergeKey 	                      [string]                                   =>	Internal signature used to merge separate occurrences of the same software issue and identify them all by the same CID.
                minOccurrenceCount 	              [int]                                      =>	Minimum number of instances of software issues associated with a given CID.
		        ownerNameList 	                  [string]                                   =>	Owner of the CID.
                ownerNamePattern 	              [string]                                   =>	Glob pattern matching the first or last name of the owner of a CID.
                severityNameList 	              [string]                                   =>	Severity of the CID; a triage value for the CID.
                statusNameList 	                  [string]                                   =>	Status of the CID. 
                streamExcludeNameList 	          [streamIdDataObj]                          =>	Identifier for a stream to exclude. 
                streamExcludeQualifier 	          [string]                                   =>	If set to ANY, the filter will exclude from the results CIDs found in each of the streams listed in the streamExcludeNameList field. 
                                                                                                If set to ALL, the filter will only exclude a CID if it is found in all listed streams. Valid values are ANY or ALL. Defaults to ANY.
                streamIncludeNameList 	          [streamIdDataObj]                          =>	Identifier for a stream to include.
                streamIncludeQualifier 	          [string]                                   =>	If set to ANY, the filter will return CIDs found in each of the streams listed in the streamIncludeNameList field.
                                                                                                If set to ALL, the filter will only return a  CID if it is found in all listed streams. Valid values are ANY or ALL. Defaults to ANY."""
        filterSpec= self.__DefServiceclient.factory.create("snapshotScopeDefectFilterSpecDataObj");
        componentIdListData= self.__DefServiceclient.factory.create("componentIdDataObj")
        streamIdDataObj= self.__DefServiceclient.factory.create("streamIdDataObj")
        streamIdDataObj2= self.__DefServiceclient.factory.create("streamIdDataObj")

        componentIdListData.name= componentIdList
        streamIdDataObj.name= streamExcludeNameList
        streamIdDataObj2.name= streamIncludeNameList
        filterSpec.actionNameList= actionNameList
        filterSpec.attributeDefinitionValueFilterMap= attributeDefinitionValueFilterMap
        filterSpec.checkerCategoryList= checkerCategoryList
        filterSpec.checkerList= checkerList
        filterSpec.checkerTypeList= checkerTypeList
        filterSpec.cidList= cidList
        filterSpec.classificationNameList= classificationNameList
        filterSpec.componentIdExclude= componentIdExclude
        filterSpec.componentIdList= componentIdListData
        filterSpec.cweList= cweList
        filterSpec.externalReference= externalReference
        filterSpec.fileName= fileName
        filterSpec.firstDetectedEndDate= firstDetectedEndDate
        filterSpec.firstDetectedStartDate= firstDetectedStartDate
        filterSpec.fixTargetNameList= fixTargetNameList
        filterSpec.functionMergeName= functionMergeName
        filterSpec.functionName= functionName
        filterSpec.impactNameList= impactNameList
        filterSpec.issueComparison= issueComparison
        filterSpec.issueKindList= issueKindList
        filterSpec.lastDetectedEndDate= lastDetectedEndDate
        filterSpec.lastDetectedStartDate= lastDetectedStartDate
        filterSpec.legacyNameList= legacyNameList
        filterSpec.maxOccurrenceCount= maxOccurrenceCount
        filterSpec.mergeExtra= mergeExtra
        filterSpec.mergeKey= mergeKey
        filterSpec.minOccurrenceCount= minOccurrenceCount
        filterSpec.ownerNameList= ownerNameList
        filterSpec.ownerNamePattern= ownerNamePattern
        filterSpec.severityNameList= severityNameList
        filterSpec.statusNameList= statusNameList
        filterSpec.streamExcludeNameList= streamIdDataObj
        filterSpec.streamExcludeQualifier= streamExcludeQualifier
        filterSpec.streamIncludeNameList= streamIdDataObj2
        filterSpec.streamIncludeQualifier= streamIncludeQualifier
        return filterSpec

# DATA_TYPE: Create  defectStateAttributeValueDataObj data type.
    def  defectStateAttributeValueDataObj(self, attributeName, valueOfAttribute):
        """Create  defectStateAttributeValueDataObj data type.
        :param:
                attributeName    [string] => Identifier for an attribute.
                valueOfAttribute [string] => Value of the attribute."""
        defectStateAttributeValues= self.__DefServiceclient.factory.create("defectStateAttributeValueDataObj ")
        attributeDefinitionId= self.__DefServiceclient.factory.create("attributeDefinitionIdDataObj")
        attributeValueId = self.__DefServiceclient.factory.create("attributeValueIdDataObj")
        attributeDefinitionId.name= attributeName
        attributeValueId.name= valueOfAttribute
        defectStateAttributeValues.attributeDefinitionId= attributeDefinitionId
        defectStateAttributeValues.attributeValueId= attributeValueId
        return defectStateAttributeValues

# DATA_TYPE: Create  mergedDefectFilterSpecDataObj data type.
    def  mergedDefectFilterSpecDataObj(self, cidList, checkerSubcategoryFilterSpecList, filenamePatternList, componentIdList, statusNameList, classificationNameList, 
                                       actionNameList, fixTargetNameList, severityNameList, legacyNameList, ownerNameList, issueKindList, attributeDefinitionValueFilterMap,
                                       componentIdExclude, defectPropertyKey, defectPropertyPattern, externalReferencePattern, firstDetectedEndDate, firstDetectedStartDate,
                                       functionNamePattern, lastDetectedEndDate, lastDetectedStartDate, lastFixedEndDate, lastFixedStartDate, lastTriagedEndDate, lastTriagedStartDate,
                                       maxCid, maxOccurrenceCount, mergedDefectIdDataObjs, minCid, minOccurrenceCount, ownerNamePattern, snapshotComparisonField,streamExcludeNameList,
                                       streamExcludeQualifier, streamIncludeNameList, streamIncludeQualifier):
        """Create  mergedDefectFilterSpecDataObj data type.
        :param:
                cidList 	[long] =>	A CID. Multiple CIDs allowed.
                checkerSubcategoryFilterSpecList 	[checkerSubcategoryFilterSpecDataObj ] =>	Checker subcategory specification. Multiple allowed.
                filenamePatternList 	[string] =>	Filename pattern for source code files that containing software issues associated with the CIDs. Up to 20 patterns allowed.
                componentIdList 	[componentIdDataObj] =>	Name of a component that contains the CID. Multiple components allowed.
                statusNameList 	[string] =>	Status of the CID. Multiple statuses allowed.
                classificationNameList 	[string] =>	Classification of the CID; a triage value for the CID. Multiple classifications allowed.
                actionNameList 	[string] =>	Name/value pairs for a list of attributes.
                fixTargetNameList 	[string] =>	Fix target for the CID; a triage value for the CID. Multiple fix targets allowed.
                severityNameList 	[string] =>	Severity of the CID; a triage value for the CID. Multiple severities allowed.
                legacyNameList 	[string] =>	Legacy designation for the CID (true or false); a triage value for the CID. Built-in attribute. Defaults to false.
                ownerNameList 	[string] =>	Owner of the CID.
                issueKindList 	[string] =>	Kind of issue identified by the CID.
                attributeDefinitionValueFilterMap 	[attributeDefinitionValueFilterMapDataObj ] =>	Specification of an attribute value.
                componentIdExclude 	[boolean] =>	If one or more component name filters is specified, set to true to exclude matching results from the specified components. Defaults to false, including the matches from the components in the results.
                defectPropertyKey 	[string] =>	Do not use this field. The API does not process these values.
                defectPropertyPattern 	[string] =>	Do not use this field. The API does not process these values.
                externalReferencePattern 	[string] =>	Glob pattern matching the value of an Ext. Reference attribute value.
                firstDetectedEndDate 	[dateTime] =>	Ending date (and optionally, time) for the date range matching the First Detected date of a CID.
		                                                Example1: 2013-03-18T12:42:19.384-07:00 	Example2: 3/18/2013
                firstDetectedStartDate 	[dateTime] =>	Starting date (and optionally, time) for the date range matching the First Detected date of a CID. 
	            functionNamePattern 	[string] =>	Glob pattern matching the name of the function (or method) associated with a CID.
                lastDetectedEndDate 	[dateTime] =>	Ending date (and optionally, time) for the date range matching the Last Detected date of a CID.
		        lastDetectedStartDate 	[dateTime] =>	Starting date (and optionally, time) for the date range matching the Last Detected date of a CID.
		        lastFixedEndDate 	[dateTime] =>	Ending date (and optionally, time) for the date range matching the Last Fixed date of a CID.
		        lastFixedStartDate 	[dateTime] =>	Starting date (and optionally, time) for the date range matching the Last Fixed date of a CID.
		        lastTriagedEndDate 	[dateTime] =>	Ending date (and optionally, time) for the date range matching the Last Triaged date of a CID.
		        lastTriagedStartDate 	[dateTime] =>	Starting date (and optionally, time) for the date range matching the Last Triaged date of a CID.
		        maxCid 	[long] =>	Upper numeric bound of CIDs to retrieve. For example, no greater than CID 25000.
	            maxOccurrenceCount 	[int] =>	Maximum number of instances of software issues associated with a given CID.
		        mergedDefectIdDataObjs 	[mergedDefectIdDataObj] =>	Identifier for a software issue.
		                                                            Multiple specifications are allowed.
                minCid 	[long] =>	Lower numeric bound of CIDs to retrieve. For example, no smaller than CID 24500.
		        minOccurrenceCount 	[int] =>	Minimum number of instances of software issues associated with a given CID.
		        ownerNamePattern 	[string] =>	Glob pattern matching the first or last name of the owner of a CID.
                snapshotComparisonField 	[string] =>	
                streamExcludeNameList 	[streamIdDataObj] =>	Identifier for a stream to exclude. Multiple streams are allowed.
                streamExcludeQualifier 	[string] =>	
                streamIncludeNameList 	[streamIdDataObj] =>	Identifier for a stream to include. Multiple streams are allowed.
                streamIncludeQualifier 	[string] =>	"""
        filterSpec= self.__DefServiceclient.factory.create("mergedDefectFilterSpecDataObj")
        filterSpec.cidList= cidList
        filterSpec.checkerSubcategoryFilterSpecList=checkerSubcategoryFilterSpecList
        filterSpec.filenamePatternList= filenamePatternList
        filterSpec.componentIdList= componentIdList
        filterSpec.statusNameList= statusNameList
        filterSpec.classificationNameList= classificationNameList
        filterSpec.actionNameList= actionNameList
        filterSpec.fixTargetNameList= fixTargetNameList
        filterSpec.severityNameList= severityNameList
        filterSpec.legacyNameList= legacyNameList
        filterSpec.ownerNameList= ownerNameList
        filterSpec.issueKindList= issueKindList
        filterSpec.attributeDefinitionValueFilterMap= attributeDefinitionValueFilterMap
        filterSpec.componentIdExclude= componentIdExclude
        filterSpec.defectPropertyKey= defectPropertyKey
        filterSpec.defectPropertyPattern= defectPropertyPattern
        filterSpec.externalReferencePattern= externalReferencePattern
        filterSpec.firstDetectedEndDate= firstDetectedEndDate
        filterSpec.firstDetectedStartDate= firstDetectedStartDate
        filterSpec.functionNamePattern= functionNamePattern
        filterSpec.lastDetectedEndDate= lastDetectedEndDate
        filterSpec.lastDetectedStartDate= lastDetectedStartDate
        filterSpec.lastFixedEndDate= lastFixedEndDate
        filterSpec.lastFixedStartDate= lastDetectedStartDate
        filterSpec.lastTriagedEndDate= lastTriagedEndDate
        filterSpec.lastTriagedStartDate= lastTriagedStartDate
        filterSpec.maxCid= maxCid
        filterSpec.maxOccurrenceCount= maxOccurrenceCount
        filterSpec.mergedDefectIdDataObjs= mergedDefectIdDataObjs
        filterSpec.minCid= minCid
        filterSpec.minOccurrenceCount= minOccurrenceCount
        filterSpec.ownerNamePattern= ownerNamePattern
        filterSpec.snapshotComparisonField= snapshotComparisonField
        filterSpec.streamExcludeNameList= streamExcludeNameList
        filterSpec.streamExcludeQualifier= streamExcludeQualifier
        filterSpec.streamIncludeNameList= streamIncludeNameList
        filterSpec.streamIncludeQualifier= streamIncludeQualifier
        return filterSpec

# DATA_TYPE: Create checkerSubcategoryFilterSpecDataObj data type.
    def checkerSubcategoryFilterSpecDataObj(self, checkerName, domain, subcategory):
        """"Create checkerSubcategoryFilterSpecDataObj data type.
        :param:
               checkerName  [string] => Checker associated with the subcategory.
               domain       [string] => Domain associated with the subcategory.
               subcategory  [string] => Subcategory on which to filter. """
        checkerSubcategoryFilterSpec= self.__DefServiceclient.factory.create("checkerSubcategoryFilterSpecDataObj")
        checkerSubcategoryFilterSpec.checkerName= checkerName
        checkerSubcategoryFilterSpec.domain= domain
        checkerSubcategoryFilterSpec.subcategory= subcategory
        return checkerSubcategoryFilterSpec

# DATA_TYPE: Create componentIdDataObj data type.
    def componentIdDataObj (self, name):
        """Create componentIdDataObj data type.
        :param:
                name [string] => Name of a component in the project in the form [componentMap].[component]."""
        componentIdList= self.__DefServiceclient.factory.create("componentIdDataObj")
        componentIdList.name= name
        return componentIdList
 
# DATA_TYPE: Create attributeDefinitionValueFilterMapDataObj data type.
    def attributeDefinitionValueFilterMapDataObj(self, attributeDefinitionId, attributeValueIdsData):
        """"Create attributeDefinitionValueFilterMapDataObj data type.
        :param:
                attributeDefinitionId  [attributeDefinitionIdDataObj] => Identifier for the attribute to filter. 
                attributeValueIds      [attributeValueIdDataObj]      => Value of the attribute to filter. Multiple values allowed."""
        attributeDefinitionValueFilterMap= self.__DefServiceclient.factory.create("attributeDefinitionValueFilterMapDataObj")
        attributeDefinitionValueFilterMap.attributeDefinitionId= attributeDefinitionId
        attributeDefinitionValueFilterMap.attributeValueIds= attributeValueIdsData
        return attributeDefinitionValueFilterMap

# DATA_TYPE: Create  attributeDefinitionIdDataObj data type.
    def  attributeDefinitionIdDataObj(self, name):
        """Create  attributeDefinitionIdDataObj data type.
        :param:
                name [string] => Name of the attribute."""
        attributeDefinitionId= self.__DefServiceclient.factory.create("attributeDefinitionIdDataObj")
        attributeDefinitionId.name= name
        return attributeDefinitionId

# DATA_TYPE: Create mergedDefectIdDataObj data type.
    def mergedDefectIdDataObj(self, cid, mergeKey):
        """Create mergedDefectIdDataObj data type.
        :param:
                cid      [long] => CID.
                mergeKey [string] => Numeric key for a CID."""
        mergedDefectIdDataObjs= self.__DefServiceclient.factory.client("mergedDefectIdDataObj")
        mergedDefectIdDataObjs.cid= cid
        mergedDefectIdDataObjs.mergeKey= mergeKey
        return mergedDefectIdDataObjs

# DATA_TYPE: Create streamIdDataObj data type.
    def streamIdDataObj(self, name):
        """Create streamIdDataObj data type.
        :param:
                name [string] => Required. Name of the stream."""
        streamIdData= self.__DefServiceclient.factory.create("streamIdDataObj")
        streamIdData.name= name
        return streamIdData
