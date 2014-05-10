#!/usr/bin/env node

var _ = require('underscore');
var fs = require('fs');
var os = require('os');
var util = require('util');
var events = require('events');

var http = require('http');
var https = require('https');
var connect = require('connect');
var express = require('express');
var socketio = require("socket.io");
var path = require('path');
// var colors = require('colors');

var zutils = require('../zetta-utils');
var zstats = require('zetta-stats');
var zrpc = require('../zetta-rpc');
var exec = require('child_process').exec;
var getmac = require('getmac');
var mongo = require('mongodb');
// var Mailer = require('./lib/mailer');

// temporary hack while working on translation module
var os = require('os');
if (os.hostname() == 'CARBIDE-ALPHA') 
    var translator = require('../translation');
else
    var translator = require('translation');


function getConfig(name) {

    var host_filename = name+'.'+os.hostname()+'.conf';
    var filename = name+'.conf';

    var data = undefined;

    if(fs.existsSync(host_filename)) {
        data = fs.readFileSync(host_filename);
    }
    else {
        data = fs.readFileSync(filename);
    }

//  console.log(data.toString('utf-8'));
    return eval('('+data.toString('utf-8')+')');
}


function Application(appFolder, appConfig) {
    var self = this;
    events.EventEmitter.call(this);

    if(_.isString(appConfig))
        self.config = getConfig(path.join(appFolder,'config', appConfig));
    else
    if(_.isObject(appConfig))
        self.config = appConfig;
    else
        throw new Error("Application() requires config object as argument");

    if(!self.config.application)
        throw new Error("Application() requires 'application' attribute in the config");

    if(self.config.translator)
        self.translator = translator;

    http.globalAgent.maxSockets = self.config.maxSockets || 1024; // 1024;
    https.globalAgent.maxSockets = self.config.maxSockets || 1024;
    if(process.platform != 'win32') {
        try { require('posix').setrlimit('nofile', self.config.socket_limit); } catch(ex) {
            console.error(ex.stack);
        }
    }

    self.pingDataObject = { }


    self.initCertificates = function(callback) {
        if(self.verbose)
            console.log('zetta-app: loading certificates from ',appFolder+'/'+self.config.certificates);
        if(self.certificates)
            callback && callback();

        self.certificates = {
            key: fs.readFileSync(path.join(appFolder,self.config.certificates)+'.key').toString(),
            cert: fs.readFileSync(path.join(appFolder,self.config.certificates)+'.crt').toString(),
            ca: [ ]
        }

        /*        var cert = [ ]
         var chain = fs.readFileSync(__dirname + '/certificates/gd_bundle-g2.crt').toString().split('\n');
         _.each(chain, function(line) {
         cert.push(line);
         if(line.match('/-END CERTIFICATE-/')) {
         certificates.ca.push(cert.join('\n'));
         cert = [ ]
         }
         })
         */

        callback && callback();
    }


    self.initMonitoringInterfaces = function(callback) {
        self.stats = new zstats.StatsD(self.config.statsd, self.mac, self.config.application);
        self.profiler = new zstats.Profiler(self.stats);
        self.monitor = new zstats.Monitor(self.stats);

        callback();
    }

/*    var databaseConfig = [
        {
            config: 'main',
            collections: [
                {collection: 'resources', indexes: 'owner'},
                {collection: 'users', indexes: 'email->unique|google.id|facebook.id'}
            ]
        }
    ];


*/
    self.initDatabaseConfig = function(callback) {

        var dbconf = self.databaseConfig;

        if (typeof(dbconf) == 'string')
            dbconf = [ dbconf ];

        console.log("Connecting to database...".bold);

        self.db = { }
        self.databases = { }

        initDatabaseConnection();

        function initDatabaseConnection() {
            var config = dbconf.shift();
            if (!config)
                return finish();

            var name = config.config;// || config.alias;
            if (typeof(self.config.db) != 'object' || !self.config.db[name]) {
                console.error(("Unable to find DB configuration for " + name).red.bold);
                return callback(new Error("Unable to find DB configuration (Update local config file!)"));
            }

            mongo.Db.connect(self.config.db[name], function (err, database) {
                if (err)
                    return callback(err);

                self.databases[name] = database;

                console.log("DB '" + (name) + "' connected", self.config.db[name]);
                zutils.bind_database_config(database, config.collections, function (err, db) {
                    if (err)
                        return callback(err);
                    _.extend(self.db, db);
                    initDatabaseConnection();
                })
            })
        }

        function finish() {
            self.databases['main'].createCollection('msg', { capped: true, size: self.config.msg_db_max_size, max: self.config.msg_db_max_count }, function (err, collection) {
                if (err)
                    return callback(err);
                self.db.msg = collection;
                callback();
            })
        }
    }

    self.initDatabaseCollections = function(callback) {
        console.log("Connecting to database...".bold);

        self.db = { }
        self.databases = { }

        mongo.Db.connect(self.config.mongodb, function (err, database) {
            if (err)
                return callback(err);

            self.database = database;

            console.log("Database connected", self.config.mongodb);
            zutils.bind_database_config(database, self.databaseCollections, function (err, db) {
                if (err)
                    return callback(err);
                _.extend(self.db, db);
                callback();
            })
        })
    }


/*    self.initMailer = function(callback) {
        self.mailer = Mailer(self);

        callback();
    }
*/

    self.initExpress = function(callback) {
        var ExpressSession = require('express-session');
        var ErrorHandler = require('errorhandler');

        self.app = express();

        self.app.set('views', path.join(appFolder,'views'));
        self.app.set('view engine', 'ejs');
        self.app.engine('html', require('ejs').renderFile);
        self.app.use(require('body-parser')());//express.json());
        self.app.use(require('method-override')());
        self.app.use(require('cookie-parser')());

        if(self.config.mongodb) {
            var MongoStore = require('connect-mongo')(ExpressSession);
            self.app.sessionStore = new MongoStore({url: self.config.mongodb});
            self.app.use(ExpressSession({
                secret: self.config.session.secret,
                key: self.config.session.key,
                cookie: self.config.session.cookie,
                store: self.app.sessionStore
            }));
        }
        else
        if(self.config.http && self.config.http.session) {
            self.app.sessionSecret = self.config.http.session.secret;
            var CookieSession = require('cookie-session');
            self.app.use(CookieSession({
                secret: self.config.http.session.secret,
                key: self.config.http.session.key,
            }));
        }

        self.app.use(translator.useSession);

        if(self.router)
            self.router.init(self.app);

        self.emit('init::express', self.app);

        if(self.config.http.static) {
            var ServeStatic = require('serve-static');
            _.each(self.config.http.static, function(dst, src) {
                console.log('HTTP serving '+src.cyan.bold+' -> '+dst.cyan.bold);
                self.app.use('src', ServeStatic(path.join(appFolder, dst)));
            })
        }

//        self.app.get('/', ServeStatic(path.join(appFolder, 'http/')));
/*
        self.app.use(function (err, req, res, next) {
            if (typeof err == 'number') {
                err = new HttpError(err);
            }

            if (err instanceof HttpError) {
                res.sendHttpError(err);
            } else {
                if (self.config.env == 'development') {
                    ErrorHandler()(err, req, res, next);
                } else {
                    log.error(err);
                    err = new HttpError(500);
                    res.sendHttpError(err);
                }
            }
        });
*/

        if(self.config.translator) {
            translator.init(self.config.translator, function () {
                translator.separateEditor();
                finish();
            });

            return;
        }
        
        finish();

        function finish() {
            callback();
        }


    };

    self.initRedirect = function(callback) {

/*        var http_app = express();
        http_app.get('*', function (req, res) {
            res.redirect("https://" + req.headers.host + req.url);
        })
        var http_server = http.createServer(http_app);

        http_server.listen(self.config.http.port, function (err) {
            if (err) {
                console.error("Unable to start HTTP server on port" + self.config.http.port);
                return callback(err);
            }
            console.log("HTTP Server listening on port " + self.config.http.port);
            callback && callback();
        })
*/
    }

    self.initHttpServer = function(callback) {

        var CERTIFICATES = (self.config.http.ssl && self.config.certificates) ? self.certificates : null;

        var https_server = CERTIFICATES ? https.createServer(CERTIFICATES, self.app) : http.createServer(self.app);
        self.io = socketio.listen(https_server, { 'log level': 0, 'secure': CERTIFICATES ? true : false });
        if(self.router && self.router.initWebSocket)
            self.router.initWebSocket(self.io);
        self.emit('init::websockets');
        https_server.listen(self.config.http.port, function (err) {
            if (err) {
                console.error("Unable to start HTTP(S) server on port" + self.config.http.port);
                return callback(err);
            }

            console.log('HTTP server listening on port ' + self.config.http.port);

            if (!CERTIFICATES)
                console.log(("WARNING - SSL is currently disabled").magenta.bold);

            if (self.config.secure_under_username) {
                console.log("Securing run-time to user '" + self.config.secure_under_username + "'");
                zutils.secure_under_username(self.config.secure_under_username);
            }

            self.emit('init::http-server')
            callback();
        });
    };

    self.initSupervisors = function(callback) {
        if(!self.certificates)
            throw new Error("Application supervisor requires configured certificates");
        console.log("Connecting to supervisor(s)...".bold);
        self.rpc = new zrpc.Client({
            address: self.config.supervisor.address,
            auth: self.config.supervisor.auth,
            certificates: self.certificates,
            node: self.mac,
            designation: self.config.application,
            pingDataObject : self.pingDataObject
        });
        self.rpc.registerListener(self);
        callback();

        self.on('git-pull', function () {
            console.log("Executing git pull");
            exec("git pull", function (err, stdout, stderr) {
                console.log(stdout);
            })
        })

        self.on('git-pull-restart', function () {
            console.log("Executing git pull & restarting on user request");
            exec("git pull", function (err, stdout, stderr) {
                console.log(stdout);
                dpc(5000, function () {
                    process.exit(0);
                })
            })
        })
    }

    // --

    function updateServerStats() {

        self.pingDataObject.loadAvg = self.monitor.stats.loadAvg;
        self.pingDataObject.memory = self.monitor.stats.memory;

        dpc(5 * 1000, updateServerStats)
    }

    // --

    self.run = function(callback) {

        var steps = new zutils.Steps();
        
        self.config.certificates && steps.push(self.initCertificates);
        self.config.statsd && steps.push(self.initMonitoringInterfaces);
        self.config.mongodb && self.databaseConfig && steps.push(self.initDatabaseConfig);
        self.config.mongodb && self.databaseCollections && steps.push(self.initDatabaseCollections);
        self.emit('init::database');
        if(self.config.http) {
            steps.push(self.initExpress);
            steps.push(self.initHttpServer);
        }
        //self.config.mailer && steps.push(initMailer);
        self.config.supervisor && self.config.supervisor.address && steps.push(self.initSupervisors);
        getmac.getMac(function (err, mac) {
            if (err) return callback(err);
            self.mac = mac.split(process.platform == 'win32' ? '-' : ':').join('').toLowerCase();

            self.emit('init::build', steps);

            steps.run(function (err) {
                if (err)
                    throw err;

                self.config.statsd && updateServerStats();
                self.emit('init::done');
                console.log("init OK".bold);
                callback && callback();
            })

        })

        return self;
    }

    dpc(function() {
        self.run();
    })
}

util.inherits(Application, events.EventEmitter);

Application.getConfig = getConfig;

module.exports = {
    Application : Application
}