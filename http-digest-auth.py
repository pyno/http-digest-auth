from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import ITab
from java.io import PrintWriter
from threading import Lock

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
        self._supported_tools = set(['Repeater', 'Scanner', 'Intruder', 'Proxy', 'Extender'])
        self._ui = Interface(self)
        callbacks.setExtensionName("HTTP Digest Authentication")
        callbacks.registerHttpListener(self)

        # setup default username and password
        logging.debug("New DigestAuthentication object")
        self._auth = DigestAuthentication("guest","guest")
        self._saved_nonce = None
        self._need_reauth = True

        if DEV:
            self._enabled = True
        else:
            self._enabled = False
        self._auto_update_nonce = True
        self._use_suite_scope = False

        callbacks.addSuiteTab(self)
        return

    def makeRequest(self, messageInfo, message):
        requestURL = self._helpers.analyzeRequest(messageInfo).getUrl()
        logging.debug("requestURL: {}".format(requestURL))
        return self._callbacks.makeHttpRequest(self._helpers.buildHttpService(str(requestURL.getHost()), 
            int(requestURL.getPort()), requestURL.getProtocol() == "https"), message)

    def update_current_request(self, messageInfo):
        logging.debug("update_current_request")

        logging.debug("Parsing request... ")
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        headers = requestInfo.getHeaders()
        uri = str(requestInfo.getUrl())
        method = requestInfo.getMethod()
        new_headers = []

        for header in headers:
            if 'authorization: digest' in header.lower():
                if self._saved_nonce == None:
                    logging.debug("First time, we need to save the header")
                    self._auth.parse_auth_header(header)
                    self._saved_nonce = self._auth.get_nonce()
                    logging.debug("saved_nonce is now: {}".format(self._saved_nonce))
                    self._ui.update_nonce()
            else:
                new_headers.append(header)

        # Updating cached authentication header
        if self._saved_nonce == None:
            logging.debug("First time, and we don't have any cached nonce")
            return None
        self._auth.set_nonce(self._saved_nonce)
        self._auth.uri = uri
        self._auth.method = method
        header_str = self._auth.build_digest_header()
        logging.debug("New header: {}".format(header_str))
        new_headers.append(header_str)

        body_bytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        body_str = self._helpers.bytesToString(body_bytes)
        new_msg = self._helpers.buildHttpMessage(new_headers, body_str)
        return new_msg


    def create_updated_request(self, messageInfo):
        
        logging.debug("create_updated_request")

        # parsing response
        logging.debug("Parsing response... ")
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        headers = responseInfo.getHeaders()
        auth_header = None
            
        for h in headers:
            if ('www-authenticate' in h.lower()) and ('nonce' in h.lower()): 
                logging.debug("Digest Auth header found in response...")
                auth_header = h

        if not auth_header:
            logging.debug("Digest Auth header or nonce not found!")
            return None

        logging.debug("Parsing request... ")
        requestInfo = self._helpers.analyzeRequest(messageInfo)
        headers = requestInfo.getHeaders()
        uri = str(requestInfo.getUrl())
        method = requestInfo.getMethod()
        new_headers = []

        for header in headers:
            if 'authorization: digest' in header.lower():
                continue
            else:
                new_headers.append(header)

        logging.debug("Creating new message... ")
        response_digest_auth = DigestAuthentication(header_str=auth_header)
        response_digest_auth.method = method
        response_digest_auth.uri = uri
        response_digest_auth.username = self._auth.username
        response_digest_auth.password = self._auth.password
        self._auth = response_digest_auth
        self._saved_nonce = self._auth.get_nonce()
        logging.debug("saved_nonce is now: {}".format(self._saved_nonce))
        self._ui.update_nonce()
        header_str = self._auth.build_digest_header()
        new_headers.append(header_str)

        body_bytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
        body_str = self._helpers.bytesToString(body_bytes)
        new_msg = self._helpers.buildHttpMessage(new_headers, body_str)

        return new_msg


    def check_response(self, messageInfo):
        responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        headers = responseInfo.getHeaders()
        update = False
        auth_header = None
        password_ok = False
        
        logging.debug("Processing response...")
        for h in headers:
            if '401 unauthorized' in h.lower():
                logging.debug("Got a 401 Unauthorized")
                update = True
            if ('www-authenticate' in h.lower()) and ('nonce' in h.lower()):
                logging.debug("Digest Auth header found: {}".format(h))
                auth_header = h
                if 'stale=true' in h:
                    password_ok = True
        return update, auth_header, password_ok


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # check if tool is enabled
        if not self._enabled:
            return
        
        # check if URL is in scope
        if self._use_suite_scope:
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            if not self._callbacks.isInScope(requestInfo.getUrl()):
                return

        # check if tool is enabled
        tool = self._callbacks.getToolName(toolFlag)
        if not tool in self._supported_tools:
            return

        if messageIsRequest:
            # case request
            new_req = self.update_current_request(messageInfo)
            if new_req != None:
                logging.debug("\n\nSending: {}\n\n=========\n\n".format(self._helpers.bytesToString(new_req)))
                messageInfo.setRequest(new_req)
            return
        else:
            # case response
            if self._auto_update_nonce:
                self._need_reauth, auth_header, password_ok = self.check_response(messageInfo)
                if (self._need_reauth and password_ok) or (self._saved_nonce == None):
                    da = DigestAuthentication(self._auth.username, self._auth.password, auth_header)
                    new_msg = self.create_updated_request(messageInfo)
                    logging.debug("\n\nSending: {}\n\n=========\n\n".format(self._helpers.bytesToString(new_msg)))
                    updated_resp = self.makeRequest(messageInfo, new_msg).getResponse()
                    logging.debug("\n\nResponse: {}\n\n=========\n\n".format(self._helpers.bytesToString(updated_resp)))
                    messageInfo.setResponse(updated_resp)
                else:
                    logging.debug("Allright!")
        return
    
    # GETTERS / SETTERS section
    def getTabCaption(self):
        return "Digest Authentication"

    def getUiComponent(self):
        self._ui.draw_tab()
        return self._ui.get_main_panel()

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

    def set_saved_nonce(self, nonce):
        self._saved_nonce = nonce

    def get_saved_nonce(self):
        return self._saved_nonce

    def get_password(self):
        return self._auth.password

    def get_enabled(self):
        return self._enabled

    def set_enabled(self, enabled):
        self._enabled = enabled

    def get_tools(self):
        return  self._supported_tools

    def get_use_suite_scope(self):
        return self._use_suite_scope

    def set_use_suite_scope(self, flag):
        self._use_suite_scope = flag

    def add_tool(self, tool):
        self._supported_tools.add(tool)

    def del_tool(self, tool):
        self._supported_tools.discard(tool)


