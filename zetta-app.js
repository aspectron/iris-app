#!/usr/bin/env node
//
// -- Zetta Toolkit - Application Framework
//
//  Copyright (c) 2011-2014 ASPECTRON Inc.
//  All Rights Reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

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
var UUID = require('node-uuid');

var zutils = require('zetta-utils');
var zstats = require('zetta-stats');
var zrpc = require('zetta-rpc');
var zlogin = require('zetta-login');
var exec = require('child_process').exec;
var getmac = require('getmac');
var mongo = require('mongodb');
var bcrypt = require('bcrypt-nodejs');
// var Mailer = require('./lib/mailer');

// temporary hack while working on translation module
var os = require('os');
var child_process = require('child_process');
//var translator = require('zetta-translator');
var Translator = require('zetta-translator');

var _cl = console.log;
console.log = function() {
    var args = Array.prototype.slice.call(arguments, 0);
    args.unshift(zutils.tsString()+' ');
    return _cl.apply(console, args);
}

function getConfig(name) {

    var filename = name+'.conf';
    var host_filename = name+'.'+os.hostname()+'.conf';
    var local_filename = name+'.local.conf';

    var data = [ ]; // undefined;

    fs.existsSync(filename) && data.push(fs.readFileSync(filename) || null);
    fs.existsSync(host_filename) && data.push(fs.readFileSync(host_filename) || null);
    fs.existsSync(local_filename) && data.push(fs.readFileSync(local_filename) || null);

    if(!data[0] && !data[1])
        throw new Error("Unable to read config file:"+(filename+'').magenta.bold)
    function merge(dst, src) {
        _.each(src, function(v, k) {
            if(_.isArray(v)) { dst[k] = [ ]; merge(dst[k], v); }
            // if(_.isArray(v)) { if(!_.isArray(dst[k])) dst[k] = [ ]; merge(dst[k], v); }
            else if(_.isObject(v)) { if(!dst[k]) dst[k] = { };  merge(dst[k], v); }
            else { if(_.isArray(src)) dst.push(v); else dst[k] = v; }
        })
    }

    var o = { }
    _.each(data, function(conf) {
        if(!conf || !conf.toString('utf-8').length)
            return;
        var layer = eval('('+conf.toString('utf-8')+')');
        merge(o, layer);
    })

    return o;
}

function readJSON(filename) {
    if(!fs.existsSync(filename))
        return undefined;
    var text = fs.readFileSync(filename, { encoding : 'utf-8' });
    if(!text)
        return undefined;
    try { 
        return JSON.parse(text); 
    } catch(ex) { 
        console.log("Error parsing file:",filename); 
        console.log(ex); 
        console.log('Offending content follows:',text); 
    }
    return undefined;
}

function writeJSON(filename, data) {
    fs.writeFileSync(filename, JSON.stringify(data, null, '\t'));
}

function Application(appFolder, appConfig) {
    var self = this;
    events.EventEmitter.call(this);
    self.readJSON = readJSON;
    self.writeJSON = writeJSON;

    self.appFolder = appFolder;

    self.pkg = self.readJSON(path.join(appFolder,'package.json'));
    if(!self.pkg)
        throw new Error("Application Unable to read package.json");

    if(!self.pkg.name)
        throw new Error("package.json must contain module 'name' field");

    self.getConfig = function(name) {
        return getConfig(path.join(appFolder,'config', name))
    }

    self.config = self.getConfig(self.pkg.name);

    self.settings = { }

    /*if(_.isString(appConfig))
        self.config = getConfig(path.join(appFolder,'config', appConfig));
    else
    if(_.isObject(appConfig))
        self.config = appConfig;
    else
        throw new Error("Application() requires config object as argument");

    if(!self.config.application)
        throw new Error("Application() requires 'application' attribute in the config");
*/
    //if(self.config.caption)
    //    zutils.render(self.config.caption);



    http.globalAgent.maxSockets = self.config.maxHttpSockets || 1024; // 1024;
    https.globalAgent.maxSockets = self.config.maxHttpSockets || 1024;
    if(process.platform != 'win32' && self.config.maxSockets) {
        if(fs.existsSync('node_modules/posix')) {
            try { require('posix').setrlimit('nofile', self.config.maxSockets); } catch(ex) {
                console.error(ex.stack);
            }
        }
        else
            console.log("WARNING - Please install POSIX module (npm install posix)".red.bold);
    }

    self.pingDataObject = { }

    // ---



    self.restoreDefaultSettings = function(name, force) {
        var filename = path.join(self.appFolder,'config', name+'.settings');
        if(!fs.existsSync(filename)) {
            self.settings = { }
            return;
        }
        var data = fs.readFileSync(filename);
        self.settings = eval('('+data.toString('utf-8')+')');
    }


    self.restoreSettings = function(name) {
        self.restoreDefaultSettings(name);

        var host_filename = path.join(self.appFolder,'config', name+'.'+os.hostname().toLowerCase()+'.settings');
        if(!fs.existsSync(host_filename))
            return;
        var data = fs.readFileSync(host_filename);
        var settings = eval('('+data.toString('utf-8')+')');
        _.each(settings, function(o, key) {
            if(self.settings[key])
                self.settings[key].value = o.value;
        })
    }

    self.storeSettings = function(name) {
        var host_filename = path.join(self.appFolder,'config', name+'.'+os.hostname().toLowerCase()+'.settings');
        fs.writeFileSync(host_filename, JSON.stringify(self.settings, null, '\t'));
    }


    // ---

    self.initTranslator = function(callback) {
        if(self.config.translator) {
            var options = {
                storagePath: path.join(appFolder,'config'),
                rootFolderPath: appFolder
            };
            options = _.extend(self.config.translator, options);

            self.translator = new Translator(options, function() {
                self.translator.separateEditor();
            });
        }

        callback();
    }

    // ---

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
        self.stats = new zstats.StatsD(self.config.statsd, self.uuid, self.pkg.name);
//        self.stats = new zstats.StatsD(self.config.statsd, self.uuid, self.config.application);
        self.profiler = new zstats.Profiler(self.stats);
        self.monitor = new zstats.Monitor(self.stats, self.config.monitor);

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
        console.log("Connecting to database...".bold);

        self.db = { }
        self.databases = { }

        initDatabaseConnection();

        function initDatabaseConnection() {
            var config = dbconf.shift();
            if (!config)
                return callback();



            var name = config.config;// || config.alias;

            /*if (typeof(self.config.db) != 'object' || !self.config.db[name]) {
                console.error(("Unable to find DB configuration for " + name).red.bold);
                return callback(new Error("Unable to find DB configuration (Update local config file!)"));
            }*/


            var db = self.config.mongodb[name];

            if(!db)
                throw new Error("Config missing database configuration for '"+name+"'");

            mongo.Db.connect(db, function (err, database) {
                if (err)
                    return callback(err);

                self.databases[name] = database;

                console.log("DB '" + (name) + "' connected", self.config.mongodb[name].bold);
                zutils.bind_database_config(database, config.collections, function (err, db) {
                    if (err)
                        return callback(err);
                    _.extend(self.db, db);
                    initDatabaseConnection();
                })
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


    self.initExpressConfig = function(callback) {
        // console.log("initExpress");
        var ExpressSession = require('express-session');

        self.app = express();

        self.app.set('views', path.join(appFolder,'views'));
        self.app.set('view engine', 'ejs');
        self.app.engine('html', require('ejs').renderFile);
        self.app.use(require('body-parser')());//express.json());
        self.app.use(require('method-override')());
        self.app.use(require('cookie-parser')(self.config.http.session.secret));

        if(self.config.mongodb) {
            var MongoStore = require('connect-mongo')(ExpressSession);
            self.app.sessionStore = new MongoStore({url: self.config.mongodb.main || self.config.mongodb}, function() {
                self.app.use(ExpressSession({
                    secret: self.config.http.session.secret,
                    key: self.config.http.session.key,
                    cookie: self.config.http.session.cookie,
                    store: self.app.sessionStore
                }));

                return callback();
            });
        }
        else
        if(self.config.http && self.config.http.session) {
            self.app.sessionSecret = self.config.http.session.secret;
            var CookieSession = require('cookie-session');
            self.app.use(CookieSession({
                secret: self.config.http.session.secret,
                key: self.config.http.session.key,
            }));

            return callback();
        }
    }


    self.initExpressHandlers = function(callback) {
        var ErrorHandler = require('errorhandler')();

        var isErrorView = fs.existsSync(path.join(self.appFolder,'views','error.ejs'));
        self.handleHttpError = function(response, req, res, next) {
            if(req.xhr) {
                res.json({errors: _.isArray(response.errors) ? response.errors : [response.errors]});
                return;
            }
            else
            if(isErrorView) {
                res.render('error', { error : error });
                return;
            }
            else {
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
                res.end("Server Error");
                return;
            }
        }


        if(self.config.translator)
            self.app.use(self.translator.useSession);


        /**
         * response = {
         *  status: {Number}
         *  errors: {String | Array}
         * }
         */

        function HttpError(response) {
            res.status(response.status);
            self.handleHttpError(respo)
        }

        self.app.use(function(req, res, next) {
            res.sendHttpError = function (response) {
                self.handleHttpError(response, req, res, next);
            }

            next();
        })

        var loginConfig = self.config.http.login;
        if(loginConfig && loginConfig.authenticator) {
            switch(loginConfig.authenticator.type) {
                case 'basic' : {
                    console.log("AUTHENTICATOR CONFIG:", loginConfig.authenticator);
                    console.log("LOGIN CONFIG:", loginConfig);
                    self.authenticator = new zlogin.BasicAuthenticator(self, loginConfig.authenticator);
                    self.login = new zlogin.Login(self, self.authenticator, loginConfig);
                    self.login.init(self.app);
                } break;
            }
        }

        if(self.router)
            self.router.init(self.app);

        self.emit('init::express', self.app);

        if(self.config.http.static) {
            var ServeStatic = require('serve-static');
            _.each(self.config.http.static, function(dst, src) {
                console.log('HTTP serving '+src.cyan.bold+' -> '+dst.cyan.bold);
                self.app.use(src, ServeStatic(path.join(appFolder, dst)));
            })
        }

        /**
        *  Handles errors were sent via next() method
        *
        * following formats are supported:
        *  next(new Error('Something blew up'));
        *  next(400);
        *  next({status: 400, errors: 'Activation code is wrong'});
        *  next({status: 400, errors: ['Activation code is wrong']});
        *
        */
        self.app.use(function (err, req, res, next) {
            if (typeof err == 'number') {
                err = {
                    status: err,
                    errors: http.STATUS_CODES[err] || "Error"
                };
            } 
            else
            if (typeof err == 'string') {
                console.error(err);
                err = {
                    status: 500,
                    errors: 'Internal Server Error'
                };
            } 
            else 
            if (err instanceof Error) {
                if (self.config.development) {
                    err.status = 500;
                    return ErrorHandler(err, req, res, next);
                } 
                else 
                {
                    console.error(err.stack);
                    err = {
                        status: 500,
                        errors: 'Internal Server Error'
                    };
                }
            }

            res.sendHttpError(err);
        });

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
        //console.log("init::websockets".yellow.bold);
        self.config.websocket && self.initWebsocket(function(){});
        self.emit('init::websockets');
        //console.log("init::http::done".yellow.bold);
        self.emit('init::http::done');
        //console.log("Starting listening...".yellow.bold);
        //console.log("PORT IS:",self.config.http.port);
        //console.log("CONFIG IS:", self.config);
        https_server.listen(self.config.http.port, function (err) {
            if (err) {
                console.error("Unable to start HTTP(S) server on port" + self.config.http.port);
                return callback(err);
            }

            console.log('HTTP server listening on port ' + (self.config.http.port+'').bold);

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
        // console.log("initSupervisors");
        if(!self.certificates)
            throw new Error("Application supervisor requires configured certificates");
        console.log("Connecting to supervisor(s)...".bold, self.config.supervisor.address);
        self.supervisor = new zrpc.Client({
            address: self.config.supervisor.address,
            auth: self.config.supervisor.auth,
            certificates: self.certificates,
            node: self.mac,
            mac: self.mac,
            uuid : self.uuid,
            designation: self.pkg.name, // self.config.application,
            pingDataObject : self.pingDataObject
        });
        self.supervisor.registerListener(self);
        callback();

        self.on('package::info::get', function(msg) {
            console.log(msg.op.yellow.bold);
            self.supervisor.dispatch({ op : 'package::info::data', uuid : self.uuid, pkg : self.pkg })
        })

/*
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

        self.on('package::config::set', function(msg) {
            var config = path.join(self.appFolder,'config',self.config.application+'.local.conf');
            fs.writeFileSync(config, JSON.stringify(msg.config, null, '\t'));
            dpc(function() {
                // process.exit(0);
            })
        })

        self.on('package::config::get', function(msg) {
            var config = path.join(self.appFolder,'config',self.config.application+'.local.conf');
            var text = fs.readFileSync(config, { encoding : 'utf-8'});
            try { 
                var o = JSON.parse(text); 
                o && self.rpc.dispatch({ op : 'package::config::set', config : o })
            } catch(ex) { return console.log(ex.stack); }

        })

        self.on('package::info::get', function(msg) {
            self.rpc.dispatch({ op : 'package::info::set', pkg : self.pkg })
        })

        self.on('node::get-runtime-info', function() {
            var o = {
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?

                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
                // TODO - READ CONFIG FILES?
            }
        })
*/        
    }

    self.initWebsocket = function(callback) {
        self.webSocketMap = [ ]
        self.webSockets = self.io.of(self.config.websocket.path).on('connection', function(socket) {
            console.log("websocket "+socket.id+" connected");
            self.emit('websocket::connect', socket);
            self.webSocketMap[socket.id] = socket;
            socket.on('disconnect', function() {
                self.emit('websocket::disconnect', socket);
                delete self.webSocketMap[socket.id];
                console.log("websocket "+socket.id+" disconnected");
            })
            socket.on('rpc::request', function(msg) {
                try {
                    var listeners = self.listeners(msg.req.op);
                    if(listeners.length == 1) {
                        listeners[0].call(socket, msg.req, function(err, resp) {
                            socket.emit('rpc::response', {
                                _resp : msg._req,
                                err : err,
                                resp : resp,
                            });
                        })
                    }
                    else
                    if(listeners.length)
                    {
                        socket.emit('rpc::response', {
                            _resp : msg._req,
                            err : { error : "Too many handlers for '"+msg.req.op+"'" }
                        });
                    }
                    else
                    {
                        socket.emit('rpc::response', {
                            _resp : msg._req,
                            err : { error : "No such handler '"+msg.req.op+"'" }
                        });
                    }
                }
                catch(ex) { console.error(ex.stack); }
            });

            socket.on('message', function(msg) {
                try {
                    self.emit(msg.op, msg, socket);
                }
                catch(ex) { console.error(ex.stack); }
            });
        });

        callback();
    }

    // --

    function updateServerStats() {

        self.pingDataObject.loadAvg = self.monitor.stats.loadAvg;
        self.pingDataObject.memory = self.monitor.stats.memory;

        dpc(5 * 1000, updateServerStats)
    }

    // --

    var initStepsBeforeHttp_ = [ ]
    var initSteps_ = [ ]

    self.initBeforeHttp = function(fn) {
        initStepsBeforeHttp_.push(fn);
    }

    self.init = function(fn) {
        initSteps_.push(fn);
    }

    self.run = function(callback) {

        var steps = new zutils.Steps();


        self.config.translator && steps.push(self.initTranslator);
        self.config.certificates && steps.push(self.initCertificates);
        self.config.statsd && steps.push(self.initMonitoringInterfaces);
        self.config.mongodb && self.databaseConfig && steps.push(self.initDatabaseConfig);
        self.config.mongodb && self.databaseCollections && steps.push(self.initDatabaseCollections);
        self.emit('init::database', steps);
        _.each(initStepsBeforeHttp_, function(fn) {
            steps.push(fn);
        })
        if(self.config.http) {
            steps.push(self.initExpressConfig);
            steps.push(self.initExpressHandlers);
            steps.push(self.initHttpServer);
        }
        //self.config.mailer && steps.push(initMailer);
        self.config.supervisor && self.config.supervisor.address && steps.push(self.initSupervisors);

        getmac.getMac(function (err, mac) {
            if (err) return callback(err);
            self.mac = mac.split(process.platform == 'win32' ? '-' : ':').join('').toLowerCase();
            self.macBytes = _.map(self.mac.match(/.{1,2}/g), function(v) { return parseInt(v, 16); })

            var uuid = self.appFolder.replace(/\\/g,'/').split('/').pop();
            if(!uuid || uuid.length != 36) {
                var local = self.readJSON('uuid');
                if(local && local.uuid)
                    uuid = local.uuid;
                else {
                    uuid = UUID.v1({ node : self.macBytes });
                    self.writeJSON("uuid", { uuid : uuid });
                }
            }
            self.uuid = uuid;

            console.log("App UUID:".bold,self.uuid.bold);

            _.each(initSteps_, function(fn) {
                steps.push(fn);
            })

            self.emit('init::build', steps);

            steps.run(function (err) {
                if (err)
                    throw err;

                self.config.statsd && updateServerStats();
                console.log("init OK".bold);
                self.emit('init::done');
                callback && callback();
            })

        })

        return self;
    }

    self.caption = self.pkg.name;
    dpc(function() {
        if(self.caption) {
            zutils.render(self.caption.replace('-',' '), null, function(err, caption) {
                console.log('\n'+caption);
                dpc(function() {
                    self.run();
                })
            })
        }
        else {
            self.run();
        }
    })

}

util.inherits(Application, events.EventEmitter);

Application.getConfig = getConfig;

module.exports = {
    Application : Application
}