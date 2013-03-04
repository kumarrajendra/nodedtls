var dtls = require('../'), fs = require('fs'), sys = require('sys'), net = require('net');
var loop = require('nodeload');
var log4js = require('log4js');
var microtime = require('microtime');
var dgram = require('dgram');


log4js.configure({
    "appenders": [
        {
            type: "console"
            , category: "console"
        },
        {
            "type": "file",
            "filename": "tcp_fourth.log",
            "maxLogSize": 4056000,
            "backups": 3,
            "category": "clientLog"
        }
    ]
});

var udpSock;

//var options = {
//    cert: fs.readFileSync('cert.pem'),
//    ca: fs.readFileSync('cert.pem'),
//};

/*var options = {
    cert: fs.readFileSync('client-cert.pem'),
    ca: fs.readFileSync('client-cert.pem'),
};*/

var options = {
    cert: fs.readFileSync('public-cert.pem'),
    ca: fs.readFileSync('public-cert.pem'),
};

/*var options = {
    cert: fs.readFileSync('f5cert4_15.crt'),
    ca: fs.readFileSync('f5cert4_15.crt'),
};*/

sys.puts("Tunnel started.");
var client = this;
var requests=0;
var minTime = 9999999;
var maxTime = 0;
var total = 0;


logger=log4js.getLogger('clientLog');

function createDgramSocket() {
	udpSock = dgram.createSocket("udp4");
	udpSock.bind(8081);
}


function connectToDtlsServer(requestId){

    var startTime = microtime.now();

    var srcPort = 23233 + requestId;
    //var socket = dtls.connect(8080,"192.168.2.35",options, function() 
    var socket = dtls.connect(23232,"192.168.2.79",srcPort, options, function() {
    //var socket = dtls.connect(23232,"192.168.4.15",23231, options, function() {
		console.log('>>>>>>>>>>> dtls.connect callback()');
        if (socket.authorized) {
			console.log('>>>>>>>>>>> dtls.connect callback() ::> authorized');
            socket.id = requestId;
            var connectTime = microtime.now()-startTime;

            logger.info("Auth success, connected to TLS server id:"+startTime);
//            if(connectTime < minTime){
//                minTime = connectTime;
//            }
//            if(connectTime > maxTime){
//                maxTime = connectTime;
//            }
//            total = total + connectTime;

            //socket.startTime = microtime.now();
            /*startTime = microtime.now();
			var send_data = "echo message " + startTime;
            //socket.write("echo message");
            socket.write(send_data);
			console.log(">>>>>>>>>>> sending data to echo server ::> send_data:["+ send_data +"]");*/
        } else {
			console.log(">>>>>>>>>>> dtls.connect callback() ::> authorizationError:[" + socket.authorizationError+ "]");
			if(socket.authorizationError == 'DEPTH_ZERO_SELF_SIGNED_CERT') {
				console.log(">>>>>>>>>>> dtls.connect callback() ::> DEPTH_ZERO_SELF_SIGNED_CERT");
				var peer_cert = socket.getPeerCertificate();
				if(peer_cert) {
					console.log(">>>>>>>>>>> dtls.connect callback() ::> Got peer_cert:[" +peer_cert+ "]");
				}
			} else {
				console.log(">>>>>>>>>>> dtls.connect callback() ::> Failed to auth TLS connection");
    	        logger.info("Failed to auth DTLS connection: ");
        	    logger.info(socket.authorizationError);
			}
        }
        startTime = microtime.now();
		var send_data = "echo message " + startTime;
        //socket.write("echo message");
        socket.write(send_data);
		console.log(">>>>>>>>>>> sending data to echo server ::> send_data:["+ send_data +"]");
    });

    socket.addListener("data", function (data) {
        logger.info("Data received from server id:" + startTime);

        var connectTime = microtime.now()-startTime;

        if(connectTime < minTime){
            minTime = connectTime;
        }
        if(connectTime > maxTime){
            maxTime = connectTime;
        }
        total = total + connectTime;


        logger.info("Mintime:" + minTime);
        logger.info("Maxtime:" + maxTime);
        logger.info("avg:" + total/socket.id);
		console.log(">>>>>>>>>>> data event received ::> recv_data:["+ data +"]");
		//console.log("recvd echo for requestId:["+ requestId +"]");

		//startTime = microtime.now();
		//var send_data = "echo message " + startTime;
		//socket.write(send_data);
		//console.log(">>>>>>>>>>> sending data to echo server ::> send_data:["+ send_data +"]");
    });
    socket.addListener("connect", function (data) {
        logger.info("Connected to server id:"+socket.id);
		console.log(">>>>>>>>>>> connect event received ::> server id:["+ socket.id +"]");
    });

	socket.addListener('error', function(err) {
		console.log("socket.error ::> [" + err +"]");
		if(err.message == 'DEPTH_ZERO_SELF_SIGNED_CERT') {
			console.log("socket.error ::> DEPTH_ZERO_SELF_SIGNED_CERT");
		}
	});
};
function connectToTcpServer(requestId){
    var startTime = microtime.now();

    //var tcpSocket = net.connect(9090,"192.168.2.35", function()
    var tcpSocket = net.connect(9090,"192.168.3.75", function() 
	{
        tcpSocket.id = requestId;
        var connectTime = microtime.now()-startTime;

        logger.info(" connected to TCP server id:"+tcpSocket.id);
        if(connectTime < minTime){
            minTime = connectTime;
        }
        if(connectTime > maxTime){
            maxTime = connectTime;
        }
        total = total + connectTime;

        tcpSocket.write("echo message");
    });

    tcpSocket.addListener("data", function (data) {
        logger.info("Data received from server id:"+tcpSocket.id );
        logger.info("tcp Mintime:" + minTime);
        logger.info("tcp Maxtime:" + maxTime);
        logger.info("tcp avg:" + total/tcpSocket.id);

    });
    tcpSocket.addListener("connect", function (data) {
        logger.info("Connected to server id:"+tcpSocket.id);
    });
};



function executeTask()
{
    logger.info('Connecting to server id:'+microtime.now());
    //connectToTcpServer(requests);
    connectToDtlsServer(requests);
    requests++;
}


var loopOption=
{
    fun: function(finished)
    {
        executeTask();
        finished();
    },
    rps: 5,
    numberOfTimes: 1,
    concurrency: 1

};

l = new loop.Loop(loopOption).start();






