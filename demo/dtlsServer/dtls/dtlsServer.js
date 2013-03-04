var dtls = require('../../../'), fs = require('fs'), sys = require('sys'),net = require('net');;
var sys = require('sys'),
    events = require('events');




exports.initServer = function(pLocalIP){

    return new dtlsServer(pLocalIP);

};

function dtlsServer(pLocalIp){
    //sys.puts("DTLS server started.");
    console.log("DTLS server started.");
    events.EventEmitter.call(this);

    this.clientIP=pLocalIp;
    /*this.options = {
        key: fs.readFileSync('./dtls/server.key'),
        cert: fs.readFileSync('./dtls/cert.pem')
    };*/
    this.options = {
        key: fs.readFileSync('dtls/key/private-key.pem'),
        cert: fs.readFileSync('dtls/key/public-cert.pem')
    };

};

sys.inherits(dtlsServer, events.EventEmitter);

dtlsServer.prototype.startDtlsServer = function(port){

    var self = this;
    var dtlsServer = dtls.createServer(port, this.options, function (socket) {
        self.tunnelSocket = socket;
        self.tunnelSocket.host = socket.remoteAddress;
        self.tunnelSocket.port = socket.remotePort;
        sys.puts("DTLS connection established");
        console.log("DTLS connection established");
        socket.setEncoding('utf8');
        socket.addListener("data", self.handleData.bind(self));
        socket.addListener("close", self.handleClose.bind(self));

    });
};

dtlsServer.prototype.handleData = function (data){
    //sys.puts("Server Data received: " + data);
    console.log("Server Data received: ");
    var self = this;
    if(this.tunnelSocket!=undefined){
        //this.tunnelSocket.write("Hello from server:"+this.tunnelSocket.host);
        //self.emit("sipData",data,self.tunnelSocket.host,self.tunnelSocket.port);
        this.tunnelSocket.write(data);
    }
};
dtlsServer.prototype.handleClose = function (){
    console.log("DTLS Client closed received");
};
dtlsServer.prototype.sendData = function(data){
    if(this.tunnelSocket!=undefined){
        console.log("sending data:: "+data);
        this.tunnelSocket.write(data);
       // self.emit("sipData",data,self.tunnelSocket.host,self.tunnelSocket.port);
    }
}

dtlsServer.prototype.startTunnel = function(serverPort,tunnelport){
    /*var options = {
        cert: fs.readFileSync('./dtls/cert.pem'),
        ca: fs.readFileSync('./dtls/cert.pem')
    };*/
    var options = {
        cert: fs.readFileSync('dtls/key/public-cert.pem'),
        ca: fs.readFileSync('dtls/key/public-cert.pem')
    };


    sys.puts("Tunnel started.");
    console.log("Tunnel started.");
    var client = this;

// try to connect to the server
    client.socket = dtls.connect(serverPort, options, function() {
        if (client.socket.authorized) {
            sys.puts("Auth success, connected to DTLS server");
            console.log("Auth success, connected to DTLS server");
        } else {
            //Something may be wrong with your certificates
            sys.puts("Failed to auth DTLS connection: ");
            console.log("Failed to auth DTLS connection: ");
            sys.puts(client.socket.authorizationError);
        }
    });

    client.socket.addListener("data", function (data) {
        //sys.puts("Tunnel Data received from server: " + data);
        console.log("Tunnel Data received from server: " + data);
        if(client.clientSocket != undefined)
            client.clientSocket.write(data);
    });

    var server = net.createServer(function (socket) {
        client.clientSocket = socket;
        socket.addListener("connect", function () {
            sys.puts("Tunnel Connection from " + socket.remoteAddress);
            console.log("Tunnel Connection from " + socket.remoteAddress);
        });

        socket.addListener("data", function (data) {
            sys.puts("Tunnel Data received from client: " + data);
            console.log("Tunnel Data received from client: " + data);
            client.socket.write(data);
        });
        socket.addListener("end", function () {
            //close the tunnel when the client finishes the connection.
            sys.puts("Client ended the connection::"+socket.remoteAddress)
            console.log("Client ended the connection::"+socket.remoteAddress)
        });

        socket.addListener("close", function () {
            //close the tunnel when the client finishes the connection.
            sys.puts("Client closed the connection::"+socket.remoteAddress)
            console.log("Client closed the connection::"+socket.remoteAddress)
        });
    });

    server.listen(tunnelport);

}
