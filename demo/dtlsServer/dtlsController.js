dtls_server = require('./dtls/dtlsServer.js');
utils = require('./Utils.js');

utils.retrieveIp("www.google.com",80,init);

function init(localIp){
    var inst_server = dtls_server.initServer(localIp);
    inst_server.startDtlsServer(23232);
    //inst_server.startTunnel(8080,5060)

}
