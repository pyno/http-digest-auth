from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import ITab
from java.io import PrintWriter

import logging
from gui.interface import Interface
from auth.digest_auth import DigestAuthentication

DEV = False
if DEV:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.WARNING)

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        # setup basic stuff
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._supported_tools = set(['Repeater', 'Scanner'])
        callbacks.setExtensionName("HTTP Digest Authentication")
        callbacks.registerHttpListener(self)

        # setup default username and password
        self._auth = DigestAuthentication("root","root123!")
        self._saved_nonce = None

        if DEV:
            self._enabled = True
        else:
            self._enabled = False
        self._auto_update_nonce = True

        callbacks.addSuiteTab(self)
        return

    def makeRequest(self, messageInfo, message):
        requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
        return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), 
            int(requestURL.getPort()), requestURL.getProtocol() == "https"), message)

    def processResponse(self, messageInfo):
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        headers = responseInfo.getHeaders()
        update = False
        auth_header = None
        
        logging.debug("Processing response...")
        for h in headers:
            if '401 Unauthorized' in h:
                logging.debug("Need to update...")
                update = True
            if ('WWW-Authenticate' in h) and ('nonce' in h):
                    logging.debug("Digest Auth header found...")
                    auth_header = h

        if update:
            if auth_header:
                response_digest_auth = DigestAuthentication(self._auth.username, self._auth.password, 
                        self._auth.method, self._auth.uri, auth_header)
                self._saved_nonce = response_digest_auth.nonce

                logging.debug("Sending updated request")
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                headers = requestInfo.getHeaders()
                uri = str(requestInfo.getUrl())
                method = requestInfo.getMethod()
                
                new_headers = []
                for header in headers:
                    if 'Authorization: Digest' in header:
                        self._auth.parse_auth_header(header)
                        self._auth.nonce = self._saved_nonce
                        self._auth.uri = uri
                        self._auth.method = method
                        new_headers.append(self._auth.build_digest_header())
                    else:
                        new_headers.append(header)

                body_bytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
                body_str = self._helpers.bytesToString(body_bytes)
                new_msg = self._helpers.buildHttpMessage(new_headers, body_str)
                logging.debug("\n\nSending: {}\n\n=========\n\n".format(self._helpers.bytesToString(new_msg)))
                return new_msg
        else:
            return None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self._enabled:
            return

        if not messageIsRequest:
            return

        if not self._callbacks.getToolName(toolFlag) in self._supported_tools:
            return

        requestInfo = self._helpers.analyzeRequest(messageInfo)
        headers = requestInfo.getHeaders()
        uri = str(requestInfo.getUrl())
        method = requestInfo.getMethod()
        new_headers = []

        for h in headers:
            if 'Authorization: Digest' in h:
                self._auth.parse_auth_header(h)
                if self._saved_nonce != None:
                    self._auth.nonce = self._saved_nonce
                self._auth.uri = uri
                self._auth.method = method
                new_headers.append(self._auth.build_digest_header())
            else:
                new_headers.append(h)

        body_bytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        body_str = self._helpers.bytesToString(body_bytes)
        new_msg = self._helpers.buildHttpMessage(new_headers, body_str)
        logging.debug("\n\nSending: {}\n\n=========\n\n".format(self._helpers.bytesToString(new_msg)))
        messageInfo.setRequest(new_msg)

        if self._auto_update_nonce:
            # Make a first request and check if we need to update nonce and repeat
            resp = self.makeRequest(messageInfo, new_msg)
            updated_resp = self.processResponse(resp)
            if updated_resp:
                messageInfo.setRequest(updated_resp)
        return
    
    # GETTERS / SETTERS section
    def getTabCaption(self):
        return "Digest Authentication"

    def getUiComponent(self):
        ui = Interface(self)
        ui.draw_tab()
        return ui.get_main_panel()

    def get_auto_update_nonce(self):
        return self._auto_update_nonce

    def set_auto_update_nonce(self, is_set):
        self._auto_update_nonce = is_set

    def set_username(self, username):
        self._auth.username = username

    def get_username(self):
        return self._auth.username

    def set_password(self, password):
        self._auth.password = password

    def get_password(self):
        return self._auth.password

    def get_enabled(self):
        return self._enabled

    def set_enabled(self, enabled):
        self._enabled = enabled

    def get_tools(self):
        return  self._supported_tools

    def add_tool(self, tool):
        self._supported_tools.add(tool)

    def del_tool(self, tool):
        self._supported_tools.discard(tool)

