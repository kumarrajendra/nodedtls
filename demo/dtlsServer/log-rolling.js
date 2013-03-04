var log4js = require('log4js')
    , log
    , i = 0;
log4js.configure({
    "appenders": [
        {
            type: "console"
            , category: "console"
        },
//        {
//            "type": "file",
//            "filename": "logs/UAClient.log",
//            "maxLogSize": 4056000,
//            "backups": 3,
//            "category": "UAClient"
//        },
        {
            "type": "file",
            "filename": "logs/UAServer.log",
            "maxLogSize": 4056000,
            "backups": 3,
            "category": "UAServer"
        }
//        {
//            "type": "file",
//            "filename": "logs/startClient.log",
//            "maxLogSize": 405600,
//            "backups": 3,
//            "category": "startClient"
//        },
//        {
//            "type": "file",
//            "filename": "logs/applog.log",
//            "maxLogSize": 405600,
//            "backups": 3,
//            "category": "app"
//        }
    ]
});


exports.getLogger = function(pCategory){
    return log4js.getLogger(pCategory);
}
