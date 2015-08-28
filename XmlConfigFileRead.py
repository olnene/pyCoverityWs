from xml.dom.minidom import parse
import xml.dom.minidom

__DOMTree= None
__collection= None
__connect=None

class XmlConfigFileRead(object):
    """Reads the XML configuration file for Coverity scripts"""
    def __init__(self, filepath):
        self.__DOMTree = xml.dom.minidom.parse(filepath)
        self.__collection= self.__DOMTree.documentElement
        self.__connect= self.__collection.getElementsByTagName("connect")
        return

    def getHost(self):
        """"Get the host value from the config file"""
        host= self.__connect[0].getElementsByTagName("host")
        return  host[0].firstChild.nodeValue

    def getPort(self):
        """Get the port value from the config file"""
        port= self.__connect[0].getElementsByTagName("port")
        return port[0].firstChild.nodeValue

    def getSSL(self):
        ssl=self.__connect[0].getElementsByTagName("ssl")
        return ssl[0].firstChild.nodeValue

    def getUserName(self):
        user= self.__connect[0].getElementsByTagName("username")
        return user[0].firstChild.nodeValue

    def getPassword(self):
        password= self.__connect[0].getElementsByTagName("password")
        return password[0].firstChild.nodeValue