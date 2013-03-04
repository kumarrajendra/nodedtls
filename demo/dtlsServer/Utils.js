
var net = require("net");

exports.retrieveIp = function(server,port,clientRef) {
    console.log("Connecting to::"+server+":port:"+port)
    var socket = net.createConnection(port, server);
    socket.on('connect', function() {

        var localip = String((socket.address().address));
        clientRef(localip);
        console.log("Server Listening on::"+localip);
        socket.end();
    });
    socket.on('error', function(e) {
        console.log("retrieveip",e)
    });
};


