// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

/* replaced to support DTLS - Gaffar */
//{{
//var crypto = require('crypto');
var crypto = require('./dtls_crypto');
//}}
var util = require('util');
var net = require('net');
var url = require('url');
var events = require('events');
var Stream = require('stream');
var END_OF_FILE = 42;
var assert = require('assert').ok;
var constants = require('constants');
var dgram = require('dgram');
var timers = require('timers');

var DEFAULT_CIPHERS = 'ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:' + // TLS 1.2
                      'RC4:HIGH:!MD5:!aNULL:!EDH';                   // TLS 1.0

// Allow {CLIENT_RENEG_LIMIT} client-initiated session renegotiations
// every {CLIENT_RENEG_WINDOW} seconds. An error event is emitted if more
// renegotations are seen. The settings are applied to all remote client
// connections.
exports.CLIENT_RENEG_LIMIT = 3;
exports.CLIENT_RENEG_WINDOW = 600;

/* Added to support dtls - Gaffar */
//{{
var INIT_STATE = 0;
var CONNECTING_STATE = 1;
var HANDSHAKE_STATE = 2;
var HANDSHAKEFAILED_STATE = 3;
var CONNECTED_STATE = 4;
var CLOSING_STATE = 5;
var DISCONNECTED_STATE = 6;
//}}


var debug;
if (process.env.NODE_DEBUG && /tls/.test(process.env.NODE_DEBUG)) {
  debug = function(a) { console.error('TLS:', a); };
} else {
  debug = function() { };
}


var Connection = null;
try {
  /* replaced by below line for dtls support - Gaffar */
  /*Connection = process.binding('crypto').Connection;*/
  //Connection = process.binding('dtls').Connection;
  Connection = require('../build/Release/node_dtls').Connection;
} catch (e) {
  throw new Error('node.js not compiled with openssl dtls support.');
}

// Convert protocols array into valid OpenSSL protocols list
// ("\x06spdy/2\x08http/1.1\x08http/1.0")
function convertNPNProtocols(NPNProtocols, out) {
  // If NPNProtocols is Array - translate it into buffer
  if (Array.isArray(NPNProtocols)) {
    var buff = new Buffer(NPNProtocols.reduce(function(p, c) {
      return p + 1 + Buffer.byteLength(c);
    }, 0));

    NPNProtocols.reduce(function(offset, c) {
      var clen = Buffer.byteLength(c);
      buff[offset] = clen;
      buff.write(c, offset + 1);

      return offset + 1 + clen;
    }, 0);

    NPNProtocols = buff;
  }

  // If it's already a Buffer - store it
  if (Buffer.isBuffer(NPNProtocols)) {
    out.NPNProtocols = NPNProtocols;
  }
}


function checkServerIdentity(host, cert) {
  // Create regexp to much hostnames
  console.log('checkServerIdentity: host: ' + host);
  function regexpify(host, wildcards) {
    console.log('checkServerIdentity: regexpify wildcards: ' + wildcards);
    // Add trailing dot (make hostnames uniform)
    if (!/\.$/.test(host)) host += '.';

    // The same applies to hostname with more than one wildcard,
    // if hostname has wildcard when wildcards are not allowed,
    // or if there are less than two dots after wildcard (i.e. *.com or *d.com)
    if (/\*.*\*/.test(host) || !wildcards && /\*/.test(host) ||
        /\*/.test(host) && !/\*.*\..+\..+/.test(host)) {
      return /$./;
    }

    // Replace wildcard chars with regexp's wildcard and
    // escape all characters that have special meaning in regexps
    // (i.e. '.', '[', '{', '*', and others)
    var re = host.replace(
        /\*([a-z0-9\\-_\.])|[\.,\-\\\^\$+?*\[\]\(\):!\|{}]/g,
        function(all, sub) {
          if (sub) return '[a-z0-9\\-_]*' + (sub === '-' ? '\\-' : sub);
          return '\\' + all;
        });

    return new RegExp('^' + re + '$', 'i');
  }

  var dnsNames = [],
      uriNames = [],
      ips = [],
      valid = false;

  console.log('checkServerIdentity: host: 2 [' + cert.subjectaltname + ']');
  // There're several names to perform check against:
  // CN and altnames in certificate extension
  // (DNS names, IP addresses, and URIs)
  //
  // Walk through altnames and generate lists of those names
  if (cert.subjectaltname) {
    console.log('altname: subjectaltname: ' + cert.subjectaltname);
    cert.subjectaltname.split(/, /g).forEach(function(altname) {
      if (/^DNS:/.test(altname)) {
        dnsNames.push(altname.slice(4));
        console.log('altname: dnsName: ' + altname.slice(4));
      } else if (/^IP Address:/.test(altname)) {
        ips.push(altname.slice(11));
        console.log('altname: ip: ' + altname.slice(11));
      } else if (/^URI:/.test(altname)) {
        var uri = url.parse(altname.slice(4));
        if (uri) {
          uriNames.push(uri.hostname);
          console.log('altname: uri: ' + uri.hostname);
        }
      }
    });
  }

  console.log('checkServerIdentity: host: 3 ' + host);
  // If hostname is an IP address, it should be present in the list of IP
  // addresses.
  if (net.isIP(host)) {
    valid = ips.some(function(ip) {
      console.log('ip === host: [' + ip + '], [' + host + ']');
      return ip === host;
    });
    console.log('checkServerIdentity: host: 31 ' + valid);
  } else {
    console.log('checkServerIdentity: host: 4 ' + host);
    // Transform hostname to canonical form
    if (!/\.$/.test(host)) host += '.';

    // Otherwise check all DNS/URI records from certificate
    // (with allowed wildcards)
    console.log('checkServerIdentity: host: 5 ' + host);
    dnsNames = dnsNames.map(function(name) {
      console.log('checkServerIdentity: host: 6 ' + name);
      return regexpify(name, true);
    });

    // Wildcards ain't allowed in URI names
    uriNames = uriNames.map(function(name) {
      console.log('checkServerIdentity: host: 7 ' + name);
      return regexpify(name, false);
    });

    dnsNames = dnsNames.concat(uriNames);

    // And only after check if hostname matches CN
    // (because CN is deprecated, but should be used for compatiblity anyway)
    var commonNames = cert.subject.CN;
    if (Array.isArray(commonNames)) {
      for (var i = 0, k = commonNames.length; i < k; ++i) {
        dnsNames.push(regexpify(commonNames[i], false));
      }
    } else {
      dnsNames.push(regexpify(commonNames, false));
    }

    valid = dnsNames.some(function(re) {
      console.log('re === host: [' + re.test(host) + '], [' + host + ']');
      return re.test(host);
    });
  }

  console.log('checkServerIdentity: host: 8 ' + host);
  return valid;
}
exports.checkServerIdentity = checkServerIdentity;


/* Added to have client handle for a UDP/DTLS client connection
 * at server side - Gaffar
 * */
//{{
function UdpClientHandle(udpServerInst, dtlsServer, sslHandle,
    destPort, destIP) {
  Stream.call(this);
  var self = this;

  self._udpServer = udpServerInst;
  self._dtlsServer = dtlsServer;
  self._sslHandle = sslHandle;
  self._destPort = destPort;
  self._destIP = destIP;
  self.readable = self.writable = true;
  self._paused = false;
  self._connectionState = DISCONNECTED_STATE;
}

util.inherits(UdpClientHandle, Stream);


UdpClientHandle.prototype.isConnected = function() {
  var self = this;
  if (self._connectionState == undefined) {
    return false;
  }
  else if (self._connectionState == CONNECTED_STATE) {
    return true;
  }
  else {
    return false;
  }
};


UdpClientHandle.prototype.getConnState = function() {
  return this._connectionState;
};


UdpClientHandle.prototype.setConnState = function(state) {
  this._connectionState = state;
};


UdpClientHandle.prototype.write = function(data /* , encoding, cb */) {
  var self = this;
  if ((!self.writable) || (self._udpServer == undefined)) {
    throw new Error('UdpClientHandle is not writable');
  }

  if (arguments[1] != undefined) {
    if (arguments[2] != undefined) {
      return self._udpServer.write(data, arguments[1], arguments[2],
          self._destPort, self._destIP);
    }
    else {
      return self._udpServer.write(data, arguments[1], self._destPort,
          self._destIP);
    }
  }
  else {
    if (arguments[2] != undefined) {
      return self._udpServer.write(data, arguments[2], self._destPort,
          self._destIP);
    }
    else {
      return self._udpServer.write(data, self._destPort, self._destIP);
    }
  }
};


UdpClientHandle.prototype.pause = function() {
  debug('paused UdpClientHandle stream');
  this._paused = true;
  if (this._udpServer != undefined) {
    //this._udpServer.pause();
  }
};


UdpClientHandle.prototype.resume = function() {
  debug('resumed UdpClientHandle stream');
  this._paused = false;
  if (this._udpServer != undefined) {
    //this._udpServer.resume();
  }
};


UdpClientHandle.prototype.end = function(d) {
  console.log('UdpClientHandle.end::> ' + this.writable);
  if (!this.writable) return;

  this.setConnState(CLOSING_STATE);
  if (this._udpServer != undefined) {
    //this._udpServer.end(d);
    this._sslHandle.destroy();
  }
  this.setConnState(DISCONNECTED_STATE);
  this.writable = false;
  if (this._dtlsServer != undefined) {
    this._dtlsServer.removeClientHandle(this._destPort, this._destIP);
  }
};


UdpClientHandle.prototype.destroy = function(err) {
  console.log('UdpClientHandle.destroy::> ' + this.writable);
  if (this._connectionState != DISCONNECTED_STATE) {
    this.setConnState(CLOSING_STATE);
    if (this._udpServer != undefined) {
      //this._udpServer.close();
      this._sslHandle.destroy();
    }
    this.setConnState(DISCONNECTED_STATE);
    this.writable = false;
    if (this._dtlsServer != undefined) {
      this._dtlsServer.removeClientHandle(this._destPort, this._destIP);
    }
  }
};

//}}


/* Added to have Stream wrapper for dgram socket, so that it
 * can pipe to EncryptedStream - Gaffar
 * */
//{{
function UdpWrapper(isServer /*, destPort, destIP, sourcePort,
    socket, listener */) {
  Stream.call(this);
  var self = this;

  self.isServer = isServer;
  if (isServer) {
    /* In UDP servert case, sourcePort is mandatory */
    if (typeof arguments[1] == 'number') {
      self.sourcePort = arguments[1];
    }

    if (typeof arguments[2] == 'object') {
      self.socket = arguments[2];

      if (typeof arguments[3] == 'function') {
        self.listener = arguments[3];
      }
    }
    else if (typeof arguments[2] == 'function') {
      self.listener = arguments[2];
    }
  }
  else {
    /* In UDP client case, destPort, and destIp is mandatory */
    if (typeof arguments[1] == 'number') {
      self.destPort = arguments[1];
    }

    if (typeof arguments[2] == 'string') {
      self.destIP = arguments[2];
    }

    if (typeof arguments[3] == 'number') {
      self.sourcePort = arguments[3];

      if (typeof arguments[4] == 'object') {
        self.socket = arguments[4];

        if (typeof arguments[5] == 'function') {
          self.listener = arguments[5];
        }
      }
      else if (typeof arguments[4] == 'function') {
        self.listener = arguments[4];
      }
    }
    else if (typeof arguments[3] == 'object') {
      self.socket = arguments[3];

      if (typeof arguments[4] == 'function') {
        self.listener = arguments[4];
      }
    }
    else if (typeof arguments[3] == 'function') {
      self.listener = arguments[3];
    }
  }

  if (!self.socket) {
    if (self.listener) {
      self.socket = dgram.createSocket('udp4', self.listener);
    }
    else {
      self.socket = dgram.createSocket('udp4');
    }
  }

  /*if (destIP)
    self.destIP = destIP;

  if (destPort)
    self.destPort = destPort;*/

  self._closed = true;
  if (self.socket) {
    if ((self.socket.fd <= 0) && (self.sourcePort) && (self.sourcePort > 0)) {
      self.socket.bind(self.sourcePort);
    }

    self.fd = self.socket.fd;
    if (self.fd > 0) {
      self._closed = false;
    }
  }
  self.readable = self.writable = true;

  self._paused = false;
  self._needDrain = false;
  self._pending = [];
  self._pendingCallbacks = [];
  self._pendingBytes = 0;

  self._writeCalled = true;

  self.socket.on('listening', function() {
    var address = self.socket.address();
    //console.log('server listening ' + address.address + ':' + address.port);
    timers.active(self);
  });

  if (!self.isServer) {
    self.socket.on('message', function(msg, rinfo) {
      //console.log('server got: ' + msg + ' from ' + rinfo.address +
      //':' + rinfo.port);
      //console.log('server got message from ' + rinfo.address + ':' + rinfo.port);
      timers.active(self);
      self.emit('data', msg);
    });
  }

  self.socket.on('error', function(errorno) {
    console.log('error: ' + errorno.errno);
    self.emit('error', errorno);
  });

  self.socket.on('close', function() {
    console.log('close: ');
    self.emit('end');
  });
}
util.inherits(UdpWrapper, Stream);


UdpWrapper.prototype.bind = function(port /* , address */) {
  var self = this;

  self.sourcePort = port;
  if (typeof arguments[1] == 'string') {
    self.address = arguments[1];
  }

  if (self.socket) {
    if (self.address) {
      self.socket.bind(port, self.address);
    } else {
      self.socket.bind(port);
    }
  } else {
    var err = errnoException(errno, 'bind');
    self.emit('error', err);
  }
};


UdpWrapper.prototype.write = function(data /* , encoding, cb, destPort, destIP */) {
  var self = this;
  if (!this.writable) {
    throw new Error('UdpWrapper is not writable');
  }

  var encoding, cb, destPort, destIP;

  // parse arguments
  if (typeof arguments[1] == 'string') {
    console.log('UdpWrapper.write::> 1');
    encoding = arguments[1];
    if (typeof arguments[2] == 'function') {
      cb = arguments[2];
      if (typeof arguments[3] == 'number') {
        destPort = arguments[3];
        if (typeof arguments[4] == 'string') {
          destIP = arguments[4];
        }
      }
    }
    else {
      if (typeof arguments[2] == 'number') {
        destPort = arguments[2];
        if (typeof arguments[3] == 'string') {
          destIP = arguments[3];
        }
      }
    }
  } else {
    console.log('UdpWrapper.write::> 2');
    if (typeof arguments[1] == 'function') {
      console.log('UdpWrapper.write::> 3');
      cb = arguments[1];
      if (typeof arguments[2] == 'number') {
        destPort = arguments[2];
        if (typeof arguments[3] == 'string') {
          destIP = arguments[3];
        }
      }
    }
    else {
      console.log('UdpWrapper.write::> 4');
      if (typeof arguments[1] == 'number') {
        destPort = arguments[1];
        if (typeof arguments[2] == 'string') {
          destIP = arguments[2];
        }
      }
    }
  }

  // Transform strings into buffers.
  if (typeof data == 'string') {
    data = new Buffer(data, encoding);
  }

  timers.active(self);

  //self._pending.push(data);
  //self._pendingCallbacks.push(cb);
  //self._pendingBytes += data.length;

  if (self.socket) {
    if (!self.isServer) {
      self.socket.send(data, 0, data.length, self.destPort, self.destIP, cb);
      self._writeCalled = false;
    }
    else {
      console.log('UdpWrapper.write::> len:[' + data.length + ']');
      console.log('UdpWrapper.write::> ' + destIP + ':' + destPort);
      self.socket.send(data, 0, data.length, destPort, destIP, cb);
      self._writeCalled = false;
    }
  }
  //this.cycle();

  if (!self._needDrain) {
    if (self._pendingBytes >= 128 * 1024) {
      self._needDrain = true;
    } else {
      self._needDrain = self._paused;
    }
  }
  return !self._needDrain;
};


UdpWrapper.prototype.pause = function() {
  debug('paused UdpWrapper stream');
  this._paused = true;
};


UdpWrapper.prototype.resume = function() {
  debug('resumed UdpWrapper stream');
  this._paused = false;
  //this.cycle();
};


UdpWrapper.prototype.setTTL = function(ttl) {
  if (this.socket) this.socket.setTTL(ttl);
};


/*UdpWrapper.prototype.setEncoding = function(encoding) {
  var StringDecoder = require('string_decoder').StringDecoder; // lazy load
  this._decoder = new StringDecoder(encoding);
}*/


UdpWrapper.prototype.end = function(d) {
  //if (this.pair._doneFlag) return;
  if (!this.writable) return;

  if (d) {
    this.write(d);
  }

  //this._pending.push(END_OF_FILE);
  //this._pendingCallbacks.push(null);

  this.writable = false;
  this.close();

  //this.cycle();
};


UdpWrapper.prototype.close = function() {
  if (this.socket) {
    this.socket.close();
    this.closed = true;
  }
};


UdpWrapper.prototype.destroySoon = function(err) {
  if (this.writable) {
    this.end();
  } else {
    this.destroy();
  }
};


UdpWrapper.prototype.destroy = function(err) {
  timers.unenroll(this);
  this.close();
};


UdpWrapper.prototype.setTimeout = function(msecs, callback) {
  if (msecs > 0 && !isNaN(msecs) && isFinite(msecs)) {
    timers.enroll(this, msecs);
    timers.active(this);
    if (callback) {
      this.once('timeout', callback);
    }
  } else if (msecs === 0) {
    timers.unenroll(this);
    if (callback) {
      this.removeListener('timeout', callback);
    }
  }
};


UdpWrapper.prototype._onTimeout = function() {
  debug('_onTimeout');
  this.emit('timeout');
};
//}}


// Base class of both CleartextStream and EncryptedStream
function CryptoStream(pair) {
  Stream.call(this);

  this.pair = pair;

  this.readable = this.writable = true;

  this._paused = false;
  this._needDrain = false;
  this._pending = [];
  this._pendingCallbacks = [];
  this._pendingBytes = 0;
}
util.inherits(CryptoStream, Stream);


CryptoStream.prototype.write = function(data /* , encoding, cb */) {
  if (this == this.pair.cleartext) {
    debug('cleartext.write called with ' + data.length + ' bytes');
  } else {
    debug('encrypted.write called with ' + data.length + ' bytes');
  }

  if (!this.writable) {
    throw new Error('CryptoStream is not writable');
  }

  var encoding, cb;

  // parse arguments
  if (typeof arguments[1] == 'string') {
    encoding = arguments[1];
    cb = arguments[2];
  } else {
    cb = arguments[1];
  }


  // Transform strings into buffers.
  if (typeof data == 'string') {
    data = new Buffer(data, encoding);
  }

  debug((this === this.pair.cleartext ? 'clear' : 'encrypted') + 'In data');

  this._pending.push(data);
  this._pendingCallbacks.push(cb);
  this._pendingBytes += data.length;

  this.pair._writeCalled = true;
  this.pair.cycle();

  // In the following cases, write() should return a false,
  // then this stream should eventually emit 'drain' event.
  //
  // 1. There are pending data more than 128k bytes.
  // 2. A forward stream shown below is paused.
  //    A) EncryptedStream for CleartextStream.write().
  //    B) CleartextStream for EncryptedStream.write().
  //
  if (!this._needDrain) {
    if (this._pendingBytes >= 128 * 1024) {
      this._needDrain = true;
    } else {
      if (this === this.pair.cleartext) {
        this._needDrain = this.pair.encrypted._paused;
      } else {
        this._needDrain = this.pair.cleartext._paused;
      }
    }
  }
  return !this._needDrain;
};


CryptoStream.prototype.pause = function() {
  debug('paused ' + (this == this.pair.cleartext ? 'cleartext' : 'encrypted'));
  this._paused = true;
};


CryptoStream.prototype.resume = function() {
  debug('resume ' + (this == this.pair.cleartext ? 'cleartext' : 'encrypted'));
  this._paused = false;
  this.pair.cycle();
};


CryptoStream.prototype.setTimeout = function(timeout, callback) {
  if (this.socket) this.socket.setTimeout(timeout, callback);
};


CryptoStream.prototype.setNoDelay = function(noDelay) {
  if (this.socket) this.socket.setNoDelay(noDelay);
};


CryptoStream.prototype.setKeepAlive = function(enable, initialDelay) {
  if (this.socket) this.socket.setKeepAlive(enable, initialDelay);
};


CryptoStream.prototype.setEncoding = function(encoding) {
  var StringDecoder = require('string_decoder').StringDecoder; // lazy load
  this._decoder = new StringDecoder(encoding);
};


// Example:
// C=US\nST=CA\nL=SF\nO=Joyent\nOU=Node.js\nCN=ca1\nemailAddress=ry@clouds.org
function parseCertString(s) {
  var out = {};
  var parts = s.split('\n');
  for (var i = 0, len = parts.length; i < len; i++) {
    var sepIndex = parts[i].indexOf('=');
    if (sepIndex > 0) {
      var key = parts[i].slice(0, sepIndex);
      var value = parts[i].slice(sepIndex + 1);
      if (key in out) {
        if (!Array.isArray(out[key])) {
          out[key] = [out[key]];
        }
        out[key].push(value);
      } else {
        out[key] = value;
      }
    }
  }
  return out;
}


CryptoStream.prototype.getPeerCertificate = function() {
  if (this.pair.ssl) {
    var c = this.pair.ssl.getPeerCertificate();

    if (c) {
      if (c.issuer) c.issuer = parseCertString(c.issuer);
      if (c.subject) c.subject = parseCertString(c.subject);
      return c;
    }
  }

  return null;
};

CryptoStream.prototype.getSession = function() {
  if (this.pair.ssl) {
    return this.pair.ssl.getSession();
  }

  return null;
};

CryptoStream.prototype.isSessionReused = function() {
  if (this.pair.ssl) {
    return this.pair.ssl.isSessionReused();
  }

  return null;
};

CryptoStream.prototype.getCipher = function(err) {
  if (this.pair.ssl) {
    return this.pair.ssl.getCurrentCipher();
  } else {
    return null;
  }
};


CryptoStream.prototype.end = function(d) {
  if (this.pair._doneFlag) return;
  if (!this.writable) return;

  if (d) {
    this.write(d);
  }

  this._pending.push(END_OF_FILE);
  this._pendingCallbacks.push(null);

  // If this is an encrypted stream then we need to disable further 'data'
  // events.

  this.writable = false;

  this.pair.cycle();
};


CryptoStream.prototype.destroySoon = function(err) {
  if (this.writable) {
    this.end();
  } else {
    this.destroy();
  }
};


CryptoStream.prototype.destroy = function(err) {
  if (this.pair._doneFlag) return;
  this.pair.destroy();
};


CryptoStream.prototype._done = function() {
  this._doneFlag = true;

  if (this.pair.cleartext._doneFlag &&
      this.pair.encrypted._doneFlag &&
      !this.pair._doneFlag) {
    // If both streams are done:
    if (!this.pair._secureEstablished) {
      this.pair.error();
    } else {
      this.pair.destroy();
    }
  }
};


// readyState is deprecated. Don't use it.
Object.defineProperty(CryptoStream.prototype, 'readyState', {
  get: function() {
    if (this._connecting) {
      return 'opening';
    } else if (this.readable && this.writable) {
      return 'open';
    } else if (this.readable && !this.writable) {
      return 'readOnly';
    } else if (!this.readable && this.writable) {
      return 'writeOnly';
    } else {
      return 'closed';
    }
  }
});


// Move decrypted, clear data out into the application.
// From the user's perspective this occurs as a 'data' event
// on the pair.cleartext.
// also
// Move encrypted data to the stream. From the user's perspective this
// occurs as a 'data' event on the pair.encrypted. Usually the application
// will have some code which pipes the stream to a socket:
//
//   pair.encrypted.on('data', function (d) {
//     socket.write(d);
//   });
//
CryptoStream.prototype._push = function() {
  if (this == this.pair.encrypted && !this.writable) {
    // If the encrypted side got EOF, we do not attempt
    // to write out data anymore.
    return;
  }


  while (!this._paused) {
    var chunkBytes = 0;
    /* replaced to avoid incomplete bio reads from mem_buff for dtls - Gaffar */
    //{{
    /*if (!this._pool || (this._poolStart >= this._poolEnd)) {
      this._pool = new Buffer(16 * 4096);
      this._poolStart = 0;
      this._poolEnd = this._pool.length;
    }*/
    if (!this._pool || ((this._poolStart + 5000) >= this._poolEnd)) {
      this._pool = new Buffer(16 * 4096);
      this._poolStart = 0;
      this._poolEnd = this._pool.length;
    }
    //}}
    var start = this._poolStart;

    do {
      chunkBytes = this._pusher(this._pool,
                                this._poolStart,
                                this._poolEnd - this._poolStart);

      if (this.pair.ssl && this.pair.ssl.error) {
        this.pair.error();
        return;
      }

      this.pair.maybeInitFinished();

      if (chunkBytes >= 0) {
        this._poolStart += chunkBytes;
      }

    } while (chunkBytes > 0 && this._poolStart < this._poolEnd);

    var bytesRead = this._poolStart - start;

    assert(bytesRead >= 0);

    // Bail out if we didn't read any data.
    if (bytesRead == 0) {
      if (this._internallyPendingBytes() == 0 && this._destroyAfterPush) {
        this._done();
      }
      return;
    }

    var chunk = this._pool.slice(start, this._poolStart);

    if (this === this.pair.cleartext) {
      debug('cleartext emit "data" with ' + bytesRead + ' bytes');
    } else {
      debug('encrypted emit "data" with ' + bytesRead + ' bytes');
    }

    if (this._decoder) {
      var string = this._decoder.write(chunk);
      if (string.length) this.emit('data', string);
    } else {
      this.emit('data', chunk);
    }

    // Optimization: emit the original buffer with end points
    if (this.ondata) this.ondata(this._pool, start, this._poolStart);
  }
};


// Push in any clear data coming from the application.
// This arrives via some code like this:
//
//   pair.cleartext.write("hello world");
//
// also
//
// Push in incoming encrypted data from the socket.
// This arrives via some code like this:
//
//   socket.on('data', function (d) {
//     pair.encrypted.write(d)
//   });
//
CryptoStream.prototype._pull = function() {
  var havePending = this._pending.length > 0;

  assert(havePending || this._pendingBytes == 0);

  while (this._pending.length > 0) {
    if (!this.pair.ssl) break;

    var tmp = this._pending.shift();
    var cb = this._pendingCallbacks.shift();

    assert(this._pending.length === this._pendingCallbacks.length);

    if (tmp === END_OF_FILE) {
      // Sending EOF
      if (this === this.pair.encrypted) {
        debug('end encrypted ' + this.pair.fd);
        this.pair.cleartext._destroyAfterPush = true;
      } else {
        // CleartextStream
        assert(this === this.pair.cleartext);
        debug('end cleartext');

        this.pair.ssl.shutdown();

        // TODO check if we get EAGAIN From shutdown, would have to do it
        // again. should unshift END_OF_FILE back onto pending and wait for
        // next cycle.

        this.pair.encrypted._destroyAfterPush = true;
      }
      this.pair.cycle();
      this._done();
      return;
    }

    if (tmp.length == 0) continue;

    var rv = this._puller(tmp);

    if (this.pair.ssl && this.pair.ssl.error) {
      this.pair.error();
      return;
    }

    this.pair.maybeInitFinished();

    if (rv === 0 || rv < 0) {
      this._pending.unshift(tmp);
      this._pendingCallbacks.unshift(cb);
      break;
    }

    this._pendingBytes -= tmp.length;
    assert(this._pendingBytes >= 0);

    if (cb) cb();

    assert(rv === tmp.length);
  }

  // If pending data has cleared, 'drain' event should be emitted
  // after write() returns a false.
  // Except when a forward stream shown below is paused.
  //   A) EncryptedStream for CleartextStream._pull().
  //   B) CleartextStream for EncryptedStream._pull().
  //
  if (this._needDrain && this._pending.length === 0) {
    var paused;
    if (this === this.pair.cleartext) {
      paused = this.pair.encrypted._paused;
    } else {
      paused = this.pair.cleartext._paused;
    }
    if (!paused) {
      debug('drain ' + (this === this.pair.cleartext ? 'clear' : 'encrypted'));
      var self = this;
      process.nextTick(function() {
        self.emit('drain');
      });
      this._needDrain = false;
      if (this.__destroyOnDrain) this.end();
    }
  }
};


function CleartextStream(pair) {
  CryptoStream.call(this, pair);
}
util.inherits(CleartextStream, CryptoStream);


CleartextStream.prototype._internallyPendingBytes = function() {
  if (this.pair.ssl) {
    return this.pair.ssl.clearPending();
  } else {
    return 0;
  }
};


CleartextStream.prototype._puller = function(b) {
  debug('clearIn ' + b.length + ' bytes');
  return this.pair.ssl.clearIn(b, 0, b.length);
};


CleartextStream.prototype._pusher = function(pool, offset, length) {
  debug('reading from clearOut');
  if (!this.pair.ssl) return -1;
  //return this.pair.ssl.clearOut(pool, offset, length);

  var ret = this.pair.ssl.clearOut(pool, offset, length);
  return ret;
};

CleartextStream.prototype.address = function() {
  return this.socket && this.socket.address();
};

CleartextStream.prototype.__defineGetter__('remoteAddress', function() {
  return this.socket && this.socket.remoteAddress;
});


CleartextStream.prototype.__defineGetter__('remotePort', function() {
  return this.socket && this.socket.remotePort;
});


function EncryptedStream(pair) {
  CryptoStream.call(this, pair);
}
util.inherits(EncryptedStream, CryptoStream);


EncryptedStream.prototype._internallyPendingBytes = function() {
  if (this.pair.ssl) {
    return this.pair.ssl.encPending();
  } else {
    return 0;
  }
};


EncryptedStream.prototype._puller = function(b) {
  debug('writing from encIn');
  return this.pair.ssl.encIn(b, 0, b.length);
};


EncryptedStream.prototype._pusher = function(pool, offset, length) {
  debug('reading from encOut');
  if (!this.pair.ssl) return -1;
  return this.pair.ssl.encOut(pool, offset, length);
};


function onhandshakestart() {
  debug('onhandshakestart');

  var self = this, ssl = this.ssl;

  if (ssl.timer === null) {
    ssl.timer = setTimeout(function timeout() {
      ssl.handshakes = 0;
      ssl.timer = null;
    }, exports.CLIENT_RENEG_WINDOW * 1000);
  }
  else if (++ssl.handshakes > exports.CLIENT_RENEG_LIMIT) {
    // Defer the error event to the next tick. We're being called from OpenSSL's
    // state machine and OpenSSL is not re-entrant. We cannot allow the user's
    // callback to destroy the connection right now, it would crash and burn.
    process.nextTick(function() {
      var err = new Error('TLS session renegotiation attack detected.');
      if (self.cleartext) self.cleartext.emit('error', err);
    });
  }
}


function onhandshakedone() {
  // for future use
  debug('onhandshakedone');
}


/**
 * Provides a pair of streams to do encrypted communication.
 */

function SecurePair(credentials, isServer, requestCert, rejectUnauthorized,
                    options) {
  if (!(this instanceof SecurePair)) {
    return new SecurePair(credentials,
                          isServer,
                          requestCert,
                          rejectUnauthorized,
                          options);
  }

  var self = this;

  options || (options = {});

  events.EventEmitter.call(this);

  this._secureEstablished = false;
  this._isServer = isServer ? true : false;
  this._encWriteState = true;
  this._clearWriteState = true;
  this._doneFlag = false;

  if (!credentials) {
    this.credentials = crypto.createCredentials();
  } else {
    this.credentials = credentials;
  }

  if (!this._isServer) {
    // For clients, we will always have either a given ca list or be using
    // default one
    requestCert = true;

  }

  this._rejectUnauthorized = rejectUnauthorized ? true : false;
  this._requestCert = requestCert ? true : false;

  this.ssl = new Connection(this.credentials.context,
      this._isServer ? true : false,
      this._isServer ? this._requestCert : options.servername,
      this._rejectUnauthorized);

  if (this._isServer) {
    this.ssl.onhandshakestart = onhandshakestart.bind(this);
    this.ssl.onhandshakedone = onhandshakedone.bind(this);
    this.ssl.handshakes = 0;
    this.ssl.timer = null;
  }

  if (process.features.tls_sni) {
    if (this._isServer && options.SNICallback) {
      this.ssl.setSNICallback(options.SNICallback);
    }
    this.servername = null;
  }

  if (process.features.tls_npn && options.NPNProtocols) {
    this.ssl.setNPNProtocols(options.NPNProtocols);
    this.npnProtocol = null;
  }

  /* Acts as a r/w stream to the cleartext side of the stream. */
  this.cleartext = new CleartextStream(this);

  /* Acts as a r/w stream to the encrypted side of the stream. */
  this.encrypted = new EncryptedStream(this);

  process.nextTick(function() {
    /* The Connection may be destroyed by an abort call */
    if (self.ssl) {
      self.ssl.start();
    }
    self.cycle();
  });
}

util.inherits(SecurePair, events.EventEmitter);


exports.createSecurePair = function(credentials,
                                    isServer,
                                    requestCert,
                                    rejectUnauthorized) {
  var pair = new SecurePair(credentials,
                            isServer,
                            requestCert,
                            rejectUnauthorized);
  return pair;
};




/* Attempt to cycle OpenSSLs buffers in various directions.
 *
 * An SSL Connection can be viewed as four separate piplines,
 * interacting with one has no connection to the behavoir of
 * any of the other 3 -- This might not sound reasonable,
 * but consider things like mid-stream renegotiation of
 * the ciphers.
 *
 * The four pipelines, using terminology of the client (server is just
 * reversed):
 *  (1) Encrypted Output stream (Writing encrypted data to peer)
 *  (2) Encrypted Input stream (Reading encrypted data from peer)
 *  (3) Cleartext Output stream (Decrypted content from the peer)
 *  (4) Cleartext Input stream (Cleartext content to send to the peer)
 *
 * This function attempts to pull any available data out of the Cleartext
 * input stream (4), and the Encrypted input stream (2).  Then it pushes any
 * data available from the cleartext output stream (3), and finally from the
 * Encrypted output stream (1)
 *
 * It is called whenever we do something with OpenSSL -- post reciving
 * content, trying to flush, trying to change ciphers, or shutting down the
 * connection.
 *
 * Because it is also called everywhere, we also check if the connection has
 * completed negotiation and emit 'secure' from here if it has.
 */
SecurePair.prototype.cycle = function(depth) {
  if (this._doneFlag) return;

  depth = depth ? depth : 0;

  if (depth == 0) this._writeCalled = false;

  var established = this._secureEstablished;

  if (!this.cycleEncryptedPullLock) {
    this.cycleEncryptedPullLock = true;
    debug('encrypted._pull');
    this.encrypted._pull();
    this.cycleEncryptedPullLock = false;
  }

  if (!this.cycleCleartextPullLock) {
    this.cycleCleartextPullLock = true;
    debug('cleartext._pull');
    this.cleartext._pull();
    this.cycleCleartextPullLock = false;
  }

  if (!this.cycleCleartextPushLock) {
    this.cycleCleartextPushLock = true;
    debug('cleartext._push');
    this.cleartext._push();
    this.cycleCleartextPushLock = false;
  }

  if (!this.cycleEncryptedPushLock) {
    this.cycleEncryptedPushLock = true;
    debug('encrypted._push');
    this.encrypted._push();
    this.cycleEncryptedPushLock = false;
  }

  if ((!established && this._secureEstablished) ||
      (depth == 0 && this._writeCalled)) {
    // If we were not established but now we are, let's cycle again.
    // Or if there is some data to write...
    this.cycle(depth + 1);
  }
};


SecurePair.prototype.maybeInitFinished = function() {
  if (this.ssl && !this._secureEstablished && this.ssl.isInitFinished()) {
    if (process.features.tls_npn) {
      this.npnProtocol = this.ssl.getNegotiatedProtocol();
    }

    if (process.features.tls_sni) {
      this.servername = this.ssl.getServername();
    }

    this._secureEstablished = true;
    debug('secure established');
    this.emit('secure');
  }
};


SecurePair.prototype.destroy = function() {
  var self = this;

  if (!this._doneFlag) {
    this._doneFlag = true;

    if (this.ssl.timer) {
      clearTimeout(this.ssl.timer);
      this.ssl.timer = null;
    }

    this.ssl.error = null;
    this.ssl.close();
    this.ssl = null;

    self.encrypted.writable = self.encrypted.readable = false;
    self.cleartext.writable = self.cleartext.readable = false;

    process.nextTick(function() {
      self.cleartext.emit('end');
      self.encrypted.emit('close');
      self.cleartext.emit('close');
    });
  }
};


SecurePair.prototype.error = function() {
  if (!this._secureEstablished) {
    var error = this.ssl.error;
    if (!error) {
      error = new Error('socket hang up');
      error.code = 'ECONNRESET';
    }
    this.destroy();
    this.emit('error', error);
  } else {
    var err = this.ssl.error;
    this.ssl.error = null;

    if (this._isServer &&
        this._rejectUnauthorized &&
        /peer did not return a certificate/.test(err.message)) {
      // Not really an error.
      this.destroy();
    } else {
      this.cleartext.emit('error', err);
    }
  }
};

// TODO: support anonymous (nocert) and PSK


// AUTHENTICATION MODES
//
// There are several levels of authentication that TLS/SSL supports.
// Read more about this in "man SSL_set_verify".
//
// 1. The server sends a certificate to the client but does not request a
// cert from the client. This is common for most HTTPS servers. The browser
// can verify the identity of the server, but the server does not know who
// the client is. Authenticating the client is usually done over HTTP using
// login boxes and cookies and stuff.
//
// 2. The server sends a cert to the client and requests that the client
// also send it a cert. The client knows who the server is and the server is
// requesting the client also identify themselves. There are several
// outcomes:
//
//   A) verifyError returns null meaning the client's certificate is signed
//   by one of the server's CAs. The server know's the client idenity now
//   and the client is authorized.
//
//   B) For some reason the client's certificate is not acceptable -
//   verifyError returns a string indicating the problem. The server can
//   either (i) reject the client or (ii) allow the client to connect as an
//   unauthorized connection.
//
// The mode is controlled by two boolean variables.
//
// requestCert
//   If true the server requests a certificate from client connections. For
//   the common HTTPS case, users will want this to be false, which is what
//   it defaults to.
//
// rejectUnauthorized
//   If true clients whose certificates are invalid for any reason will not
//   be allowed to make connections. If false, they will simply be marked as
//   unauthorized but secure communication will continue. By default this is
//   false.
//
//
//
// Options:
// - requestCert. Send verify request. Default to false.
// - rejectUnauthorized. Boolean, default to false.
// - key. string.
// - cert: string.
// - ca: string or array of strings.
//
// emit 'secureConnection'
//   function (cleartextStream, encryptedStream) { }
//
//   'cleartextStream' has the boolean property 'authorized' to determine if
//   it was verified by the CA. If 'authorized' is false, a property
//   'authorizationError' is set on cleartextStream and has the possible
//   values:
//
//   "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_CRL",
//   "UNABLE_TO_DECRYPT_CERT_SIGNATURE", "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
//   "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY", "CERT_SIGNATURE_FAILURE",
//   "CRL_SIGNATURE_FAILURE", "CERT_NOT_YET_VALID" "CERT_HAS_EXPIRED",
//   "CRL_NOT_YET_VALID", "CRL_HAS_EXPIRED" "ERROR_IN_CERT_NOT_BEFORE_FIELD",
//   "ERROR_IN_CERT_NOT_AFTER_FIELD", "ERROR_IN_CRL_LAST_UPDATE_FIELD",
//   "ERROR_IN_CRL_NEXT_UPDATE_FIELD", "OUT_OF_MEM",
//   "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN",
//   "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
//   "CERT_CHAIN_TOO_LONG", "CERT_REVOKED" "INVALID_CA",
//   "PATH_LENGTH_EXCEEDED", "INVALID_PURPOSE" "CERT_UNTRUSTED",
//   "CERT_REJECTED"
//
//
// TODO:
// cleartext.credentials (by mirroring from pair object)
// cleartext.getCertificate() (by mirroring from pair.credentials.context)
function Server(/* bindPort, [options], listener */) {
  var self = this;
  var bindPort, options, listener;
  bindPort = 0;
  if (typeof arguments[0] == 'number') {
    bindPort = arguments[0];
    console.log('Server :>> 1 bindPort:' + bindPort);

    if (typeof arguments[1] == 'object') {
      console.log('Server :>> 2');
      console.log('Server :>> arg2: ' + arguments[1]);
      options = arguments[1];

      if (typeof arguments[2] == 'function') {
        console.log('Server :>> 2.2');
        listener = arguments[2];
      }
      else {
        console.log('Server :>> 2.3');
        console.log('Server :>> arg3: ' + arguments[2]);
      }
    }
    else if (typeof arguments[1] == 'function') {
      listener = arguments[1];
      console.log('Server :>> 3');
    }
    else if ((arguments[1] == undefined) && (typeof arguments[2] == 'function')) {
      console.log('Server :>> 4');
      listener = arguments[2];
    }
    console.log('Server :>> 5');
  }
  else if (typeof arguments[0] == 'object') {
    console.log('Server :>> 6');
    options = arguments[0];
    listener = arguments[1];
  } else if (typeof arguments[0] == 'function') {
    console.log('Server :>> 7');
    options = {};
    listener = arguments[0];
  }
  else if ((arguments[0] == undefined) && (typeof arguments[1] == 'function')) {
    console.log('Server :>> 8');
    options = {};
    listener = arguments[1];
  }
  console.log('Server :>> 9');

  if (!(this instanceof Server)) return new Server(options, listener);
  console.log('Server :>> 10');

  self._contexts = [];


  // Handle option defaults:
  self.setOptions(options);

  var sharedCreds = crypto.createCredentials({
    pfx: self.pfx,
    key: self.key,
    passphrase: self.passphrase,
    cert: self.cert,
    ca: self.ca,
    ciphers: self.ciphers || DEFAULT_CIPHERS,
    secureProtocol: self.secureProtocol,
    secureOptions: self.secureOptions,
    crl: self.crl,
    sessionIdContext: self.sessionIdContext
  });

  /* added for dtls support - Gaffar */
  //{{
  self.client_map = {};
  /*if (!self.client_map) {
    self.client_map = {};
  }*/
  //}}


  // constructor call
  /* commented below code for dtls support - Gaffar */
  //{{
  /*net.Server.call(this, function(socket) {

    var creds = crypto.createCredentials(null, sharedCreds.context);

    var pair = new SecurePair(creds,
                              true,
                              self.requestCert,
                              self.rejectUnauthorized,
                              {
                                NPNProtocols: self.NPNProtocols,
                                SNICallback: self.SNICallback
                              });

    var cleartext = pipe(pair, socket);
    cleartext._controlReleased = false;

    pair.on('secure', function() {
      pair.cleartext.authorized = false;
      pair.cleartext.npnProtocol = pair.npnProtocol;
      pair.cleartext.servername = pair.servername;

      if (!self.requestCert) {
        cleartext._controlReleased = true;
        self.emit('secureConnection', pair.cleartext, pair.encrypted);
      } else {
        var verifyError = pair.ssl.verifyError();
        if (verifyError) {
          pair.cleartext.authorizationError = verifyError.message;

          if (self.rejectUnauthorized) {
            socket.destroy();
            pair.destroy();
          } else {
            cleartext._controlReleased = true;
            self.emit('secureConnection', pair.cleartext, pair.encrypted);
          }
        } else {
          pair.cleartext.authorized = true;
          cleartext._controlReleased = true;
          self.emit('secureConnection', pair.cleartext, pair.encrypted);
        }
      }
    });
    pair.on('error', function(err) {
      self.emit('clientError', err);
    });

  });*/
  //}}


  /* added to create dgram socket for dtls support  - Gaffar */
  //{{
  self.bindPort = bindPort;
  var udpWrapper = new UdpWrapper(true, bindPort, function(msg, rinfo) {
    var conn_state = DISCONNECTED_STATE;
    var clientHandle = self.getClientHandle(rinfo.port, rinfo.address);
    if ((clientHandle != undefined) || (clientHandle != null)) {
      conn_state = clientHandle.getConnState();
    }
    console.log('conn_state :>> [' + conn_state + ']');
    if (conn_state == DISCONNECTED_STATE) {

      var creds = crypto.createCredentials(null, sharedCreds.context);

      var pair = new SecurePair(creds,
                                true,
                                self.requestCert,
                                self.rejectUnauthorized,
                                {
                                  NPNProtocols: self.NPNProtocols,
                                  SNICallback: self.SNICallback
                                });

      clientHandle = new UdpClientHandle(udpWrapper, self, pair, rinfo.port, rinfo.address);
      clientHandle.setConnState(CONNECTING_STATE);
      self.addClientHandle(rinfo.port, rinfo.address, clientHandle);
      var cleartext = pipe(pair, clientHandle);
      cleartext._controlReleased = false;

      pair.on('secure', function() {
        console.log('secure callback :>> ');
        clientHandle.setConnState(HANDSHAKE_STATE);
        pair.cleartext.authorized = false;
        pair.cleartext.npnProtocol = pair.npnProtocol;
        pair.cleartext.servername = pair.servername;

        if (!self.requestCert) {
          clientHandle.setConnState(CONNECTED_STATE);
          console.log('secure callback :>> 1 emiting secureConnection');
          cleartext._controlReleased = true;
          self.emit('secureConnection', pair.cleartext, pair.encrypted);
        } else {
          var verifyError = pair.ssl.verifyError();
          if (verifyError) {
            pair.cleartext.authorizationError = verifyError.message;
            //clientHandle.setConnState(HANDSHAKEFAILED_STATE);
            clientHandle.setConnState(DISCONNECTED_STATE);

            if (self.rejectUnauthorized) {
              console.log('secure callback :>> clientHandle.destroy()');
              clientHandle.destroy();
              pair.destroy();
            } else {
              console.log('secure callback :>> 2 emiting secureConnection');
              cleartext._controlReleased = true;
              self.emit('secureConnection', pair.cleartext, pair.encrypted);
            }
          } else {
            pair.cleartext.authorized = true;
            clientHandle.setConnState(CONNECTED_STATE);
            cleartext._controlReleased = true;
            console.log('secure callback :>> 3 emiting secureConnection');
            self.emit('secureConnection', pair.cleartext, pair.encrypted);
          }
        }
      });
      pair.on('error', function(err) {
        console.log('error callback :>> [' + err + ']');
        self.emit('clientError', err);
        self.removeClientHandle(rinfo.port, rinfo.address);
      });

      clientHandle.emit('data', msg);
    }
    else if ((conn_state == CONNECTED_STATE) || (conn_state == CONNECTING_STATE) || (conn_state == HANDSHAKE_STATE)) {
      if ((clientHandle != undefined) || (clientHandle != null)) {
        console.log('client data received :>> len:[' + msg.length + '], data:[' + msg + ']');
        clientHandle.emit('data', msg);
      }
      else
        self.emit('data', msg);
    }
    else {
      self.emit('data', msg);
    }

    //self.emit('data', msg);
  });

  self._udpWrapper = udpWrapper;
  //}}


  if (listener) {
    console.log('Server :>> listening for secureConnection');
    self.on('secureConnection', listener);
  }
  else {
    console.log('Server :>> not listening for secureConnection');
  }
}

//util.inherits(Server, net.Server);
util.inherits(Server, events.EventEmitter);
exports.Server = Server;
exports.createServer = function(bindPort, options, listener) {
  return new Server(bindPort, options, listener);
};


Server.prototype.setOptions = function(options) {
  if (typeof options.requestCert == 'boolean') {
    this.requestCert = options.requestCert;
  } else {
    this.requestCert = false;
  }

  if (typeof options.rejectUnauthorized == 'boolean') {
    this.rejectUnauthorized = options.rejectUnauthorized;
  } else {
    this.rejectUnauthorized = false;
  }

  if (options.pfx) this.pfx = options.pfx;
  if (options.key) this.key = options.key;
  if (options.passphrase) this.passphrase = options.passphrase;
  if (options.cert) this.cert = options.cert;
  if (options.ca) this.ca = options.ca;
  if (options.secureProtocol) this.secureProtocol = options.secureProtocol;
  if (options.crl) this.crl = options.crl;
  if (options.ciphers) this.ciphers = options.ciphers;
  var secureOptions = options.secureOptions || 0;
  if (options.honorCipherOrder) {
    secureOptions |= constants.SSL_OP_CIPHER_SERVER_PREFERENCE;
  }
  if (secureOptions) this.secureOptions = secureOptions;
  if (options.NPNProtocols) convertNPNProtocols(options.NPNProtocols, this);
  if (options.SNICallback) {
    this.SNICallback = options.SNICallback;
  } else {
    this.SNICallback = this.SNICallback.bind(this);
  }
  if (options.sessionIdContext) {
    this.sessionIdContext = options.sessionIdContext;
  } else if (this.requestCert) {
    this.sessionIdContext = crypto.createHash('md5')
                                  .update(process.argv.join(' '))
                                  .digest('hex');
  }
};

// SNI Contexts High-Level API
Server.prototype.addContext = function(servername, credentials) {
  if (!servername) {
    throw 'Servername is required parameter for Server.addContext';
  }

  var re = new RegExp('^' +
                      servername.replace(/([\.^$+?\-\\[\]{}])/g, '\\$1')
                                .replace(/\*/g, '.*') +
                      '$');
  this._contexts.push([re, crypto.createCredentials(credentials).context]);
};

Server.prototype.SNICallback = function(servername) {
  var ctx;

  this._contexts.some(function(elem) {
    if (servername.match(elem[0]) !== null) {
      ctx = elem[1];
      return true;
    }
  });

  return ctx;
};

Server.prototype.bind = function(bindPort /*, host*/) {
  var self = this;

  self.bindPort = bindPort;
  if (typeof arguments[1] == 'string') {
    self.host = arguments[1];
  }

  if (self._udpWrapper) {
    return self._udpWrapper.bind(bindPort, self.host);
  }
};


Server.prototype.isConnected = function(destPort, destIP) {
  var self = this;
  var key = destIP + ':' + destPort;
  var clientHandle = self.client_map[key];
  if ((clientHandle == undefined) || (clientHandle == null)) {
    return false;
  }
  else {
    return clientHandle.isConnected();
  }
};


Server.prototype.getClientHandle = function(destPort, destIP) {
  var self = this;
  var key = destIP + ':' + destPort;
  var clientHandle = self.client_map[key];
  if ((clientHandle == undefined) || (clientHandle == null)) {
    return;
  }
  else {
    return clientHandle;
  }
};


Server.prototype.addClientHandle = function(destPort, destIP, clientHandle) {
  var self = this;
  var key = destIP + ':' + destPort;
  self.client_map[key] = clientHandle;
};


Server.prototype.removeClientHandle = function(destPort, destIP) {
  var self = this;
  var key = destIP + ':' + destPort;
  var clientHandle = self.client_map[key];
  if ((clientHandle == undefined) || (clientHandle == null)) {
    return;
  }
  else {
    delete self.client_map[key];
    if (clientHandle.getConnState() != DISCONNECTED_STATE) {
      clientHandle.destroy();
    }
    return clientHandle;
  }
};


// Target API:
//
//  var s = tls.connect({port: 8000, host: "google.com"}, function() {
//    if (!s.authorized) {
//      s.destroy();
//      return;
//    }
//
//    // s.socket;
//
//    s.end("hello world\n");
//  });
//
//
exports.connect = function(/* [port, host], options, cb */) {
  var options, port, host, cb, sourcePort;

  if (typeof arguments[0] === 'object') {
    options = arguments[0];
    if (options.port) {
      port = options.port;
    }
    if (options.host) {
      host = options.host;
    }
    if (options.sourcePort) {
      sourcePort = options.sourcePort;
    }
  } else if (typeof arguments[1] === 'object') {
    options = arguments[1];
    port = arguments[0];
    if (options.host) {
      host = options.host;
    }
    if (options.sourcePort) {
      sourcePort = options.sourcePort;
    }
  } else if (typeof arguments[2] === 'object') {
    options = arguments[2];
    port = arguments[0];
    host = arguments[1];
    if (options.sourcePort) {
      sourcePort = options.sourcePort;
    }
  } else if (typeof arguments[3] === 'object') {
    options = arguments[3];
    port = arguments[0];
    host = arguments[1];
    sourcePort = arguments[2];
  } else {
    // This is what happens when user passes no `options` argument, we can't
    // throw `TypeError` here because it would be incompatible with old API
    if (typeof arguments[0] === 'number') {
      port = arguments[0];
    }
    if (typeof arguments[1] === 'string') {
      host = arguments[1];
    }
    if (typeof arguments[2] === 'number') {
      sourcePort = arguments[2];
    }
  }

  options = util._extend({ port: port, host: host, sourcePort: sourcePort }, options || {});

  if (typeof arguments[arguments.length - 1] === 'function') {
    cb = arguments[arguments.length - 1];
  }

  /* replaced by below code to create dgram socket instead of stream socket  - Gaffar */
  //{{
  //var socket = options.socket ? options.socket : new net.Stream();
  //var socket = options.socket ? options.socket : dgram.createSocket('udp4');
  var udpWrapper = new UdpWrapper(false, port, host, sourcePort);
  //}}

  var sslcontext = crypto.createCredentials(options);

  convertNPNProtocols(options.NPNProtocols, this);
  var hostname = options.servername || options.host || 'localhost',
      pair = new SecurePair(sslcontext, false, true,
                            options.rejectUnauthorized === true ? true : false,
                            {
                              NPNProtocols: this.NPNProtocols,
                              servername: hostname
                            });

  if (options.session) {
    pair.ssl.setSession(options.session);
  }

  /* replaced by below code for dtls support - Gaffar */
  //{{
  //var cleartext = pipe(pair, socket);
  var cleartext = pipe(pair, udpWrapper);
  //}}
  if (cb) {
    cleartext.on('secureConnect', cb);
  }

  /* Commented as now socket type is dgram - Gaffar */
  //{{
  /*if (!options.socket) {
    socket.connect({
      port: options.port,
      host: options.host,
      localAddress: options.localAddress
    });
  }*/
  //}}

  pair.on('secure', function() {
    var verifyError = pair.ssl.verifyError();

    cleartext.npnProtocol = pair.npnProtocol;

    /*console.log('dtls.connect ::> verifyError:[' + verifyError + ']');
    // Verify that server's identity matches it's certificate's names
    if (!verifyError) {
      var validCert = checkServerIdentity(hostname,
                                          pair.cleartext.getPeerCertificate());
      if (!validCert) {
        verifyError = new Error('Hostname/IP doesn\'t match certificate\'s ' +
                                'altnames');
      }
    }*/

    //console.log('dtls.connect ::> verifyError:[' + verifyError + ']');
    if (verifyError) {
      cleartext.authorized = false;
      cleartext.authorizationError = verifyError.message;

      if (pair._rejectUnauthorized) {
        console.log('dtls.connect ::> emitting error');
        cleartext.emit('error', verifyError);
        pair.destroy();
      } else {
        console.log('dtls.connect ::> emitting secureConnect');
        cleartext.emit('secureConnect');
      }
    } else {
      cleartext.authorized = true;
      cleartext.emit('secureConnect');
    }
  });
  pair.on('error', function(err) {
    cleartext.emit('error', err);
  });

  cleartext._controlReleased = true;
  return cleartext;
};


function pipe(pair, socket) {
  pair.encrypted.pipe(socket);
  socket.pipe(pair.encrypted);

  pair.fd = socket.fd;
  var cleartext = pair.cleartext;
  cleartext.socket = socket;
  cleartext.encrypted = pair.encrypted;
  cleartext.authorized = false;

  function onerror(e) {
    if (cleartext._controlReleased) {
      cleartext.emit('error', e);
    }
  }

  function onclose() {
    socket.removeListener('error', onerror);
    socket.removeListener('end', onclose);
    socket.removeListener('timeout', ontimeout);
  }

  function ontimeout() {
    cleartext.emit('timeout');
  }

  socket.on('error', onerror);
  socket.on('close', onclose);
  socket.on('timeout', ontimeout);

  return cleartext;
}
