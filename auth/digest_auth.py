import logging
import hashlib
import time
import os
#from urllib.parse import urlparse
from urlparse import urlparse

class DigestAuthentication(object):

    def __init__(self, username, password, method = "GET", uri = "", header_str=None):
        self.header_list = ['username' , 'realm' , 'cnonce' , 'nonce' , 'nc' , 'uri' , 'algorithm' , 'response' , 'qop', 'opaque', 'entdig']
        self.password = password
        self.username = username
        self.method = method
        self.uri = uri
        self.realm = None
        self.cnonce = None
        self._nonce = None
        self.nc = None
        self.uri = None
        self.algorithm = None
        self.response = None
        self.qop = None
        self.opaque = None
        self.entdig = None
        if header_str:
            self.parse_auth_header(header_str)


    def parse_auth_header(self, auth_header):
        name = auth_header.split(':')[0]
        value = "".join(auth_header.split(':')[1:])
        logging.debug("name: {} - value: {}".format(name,value))
        for param in value.split(','):
            #key,val = param.split('=') # <== bad idea: some params may contain '=' sign
            # better to split separately key and val
            key = param.split('=')[0].strip()
            sep_pos = param.find('=')
            val = param[sep_pos+1:]
            val = val.strip('"')
    
            # Please do not invert cnonce, nonce and nc order
            # or you will have a not-so-nice-to-debug issue :D
            if 'username' in key:
                self.username = val
            elif 'realm' in key:
                self.realm = val
            elif 'cnonce' in key:
                self.cnonce = val
            elif 'nonce' in key:
                if not self._nonce:
                    self._nonce = val
            elif 'nc' in key:
                if not self.nc:
                    self.nc = int(val,16)
            elif 'uri' in key:
                self.uri = val
            elif 'algorithm' in key:
                self.algorithm = val
            elif 'response' in key:
                self.response = val
            elif 'qop' in key:
                self.qop = val
    

    def to_header_string(self):
        header_string = "Authorization: Digest "
        header_string += ', '.join('{0}="{1}"'.format(header,self.__dict__[header]) for header in self.header_list) 
        logging.debug('Header string: {}'.format(header_string))
        return header_string


    def set_nonce(self, nonce):
        if self._nonce != nonce:
            logging.debug("SETTING NONCE {} ==> {}".format(self._nonce, nonce))
            self._nonce = nonce
            self.nc = 0


    def get_nonce(self):
        return self._nonce


    def build_digest_header(self):
        # copy-paste from Requests module ;)
        hash_utf8 = None

        if self.algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = self.algorithm.upper()

        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8
        elif _algorithm == 'SHA-256':
            def sha256_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha256(x).hexdigest()
            hash_utf8 = sha256_utf8
        elif _algorithm == 'SHA-512':
            def sha512_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha512(x).hexdigest()
            hash_utf8 = sha512_utf8

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        p_parsed = urlparse(self.uri)
        #: path is request-uri defined in RFC 2616 which should not be empty
        path = p_parsed.path or "/"
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, self.realm, self.password)
        A2 = '%s:%s' % (self.method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        # Update nonce count
        # The module sets nc to zero when a new nonce is set
        # so here we just need to increment
        self.nc += 1

        s = str(self.nc).encode('utf-8')
        s += self._nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)

        self.cnonce = (hashlib.sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, self._nonce, self.cnonce))

        if not self.qop:
            self.response = KD(HA1, "%s:%s" % (self._nonce, HA2))
        elif self.qop == 'auth' or 'auth' in self.qop.split(','):
            # XXX: Should nc be reppresented as hex in the header string?? - hex(self.nc)
            #      Should it be reppresented as a fixed size number (e.g. 0000002c)
            noncebit = "%s:%s:%s:%s:%s" % (
                self._nonce, self.nc, self.cnonce, 'auth', HA2
            )
            self.response = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (self.username, self.realm, self._nonce, path, self.response)
        if self.opaque:
            base += ', opaque="%s"' % self.opaque
        if self.algorithm:
            base += ', algorithm="%s"' % self.algorithm
        if self.entdig:
            base += ', digest="%s"' % entdig
        if self.qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (self.nc, self.cnonce)

        return 'Authorization: Digest %s' % (base)

