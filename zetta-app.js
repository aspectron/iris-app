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
// var colors = require('colors');

var zutils = require('zetta-utils');
var zstats = require('zetta-stats');
var zrpc = require('zetta-rpc');
var exec = require('child_process').exec;
var getmac = require('getmac');
var mongo = require('mongodb');
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

function Bash(options)
{
    var self = this;
    self.options = options;
    self.relaunch = true;

    self.terminate = function() {
        if(self.process) {
            self.relaunch = false;
            self.process.kill('SIGTERM');
            delete self.process;
        }
        else
            console.error("Unable to terminate process, no process present");
    }

    self.restart = function() {
        if(self.process) {
            self.process.kill('SIGTERM');
        }
    }

    self.run = function() {

        if(self.process) {
            console.error(self.options);
            throw new Error("Process is already running!");
        }

        self.relaunch = true;
        self.process = child_process.spawn('bash',['--verbose']);

        self.process.stdout.on('data',function (data) {
            process.stdout.write(data);
            options.stdout(data);

        });

        self.process.stderr.on('data',function (data) {
            process.stderr.write(data);
            options.stdout(data);
        });

        self.process.on('exit',function (code) {
            if(code) {
                console.log("BASH exited with code "+code);
            }

            delete self.process;

            if(self.relaunch) {
                console.log("Restarting BASH");
                dpc(self.run, options.restart_delay || 0);
            }
        });
    }
}



function getConfig(name) {

    var host_filename = name+'.'+os.hostname()+'.conf';
    var filename = name+'.conf';

    var data = [ ]; // undefined;

    if(fs.existsSync(filename))
        data.push(fs.readFileSync(filename) || null);
    if(fs.existsSync(host_filename))
        data.push(fs.readFileSync(host_filename) || null);

    if(!data[0] && !data[1])
        throw new Error("Unable to read config file:",(filename+'').magenta.bold)
    function merge(dst, src) {
        _.each(src, function(v, k) {
            if(_.isArray(v)) { if(!dst[k]) dst[k] = [ ]; merge(dst[k], v); }
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


function Application(appFolder, appConfig) {
    var self = this;
    events.EventEmitter.call(this);

    self.appFolder = appFolder;

    if(_.isString(appConfig))
        self.config = getConfig(path.join(appFolder,'config', appConfig));
    else
    if(_.isObject(appConfig))
        self.config = appConfig;
    else
        throw new Error("Application() requires config object as argument");

    if(!self.config.application)
        throw new Error("Application() requires 'application' attribute in the config");

    if(self.config.caption)
        zutils.render(self.config.caption);

    if(self.config.translator)
        self.translator = new Translator({ storagePath : path.join(appFolder,'config') });

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

        //if (typeof(dbconf) == 'string')
        //    dbconf = [ dbconf ];



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

                console.log("DB '" + (name) + "' connected", self.config.mongodb[name]);
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
            self.app.sessionStore = new MongoStore({url: self.config.mongodb.main || self.config.mongodb});
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

        if(self.config.translator)
            self.app.use(self.translator.useSession);


        self.app.use(function(req, res, next) {
            res.sendHttpError = function (error) {
                res.status(error.status);
                if (res.req.headers['x-requested-with'] == 'XMLHttpRequest') {
                    res.json(error);
                } else {
                    res.render("error", {error: error});
                }
            };

            next();
        })

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

//        self.app.get('/', ServeStatic(path.join(appFolder, 'http/')));

//        self.on('init::http::done', function() {
    
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
    
//        })


        if(self.config.translator) {
            self.translator.init(self.config.translator, function () {
                self.translator.separateEditor();
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
        self.emit('init::http::done');
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
        console.log("Connecting to supervisor(s)...".bold, self.config.supervisor.address);
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

    self.initBash = function(callback) {
console.log("init::BASH".cyan.bold);

        self.bash = new Bash({
            stdout : function(data) {
                self.rpc.dispatch({
                    op : 'console',
                    data : data.toString('utf-8')
                })
            }
        })

        // if(process.platform != 'win32')
            dpc(function(){
                self.bash.run();
            })

        callback && callback();
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
        self.emit('init::database', steps);
        if(self.config.http) {
            steps.push(self.initExpress);
            steps.push(self.initHttpServer);
        }
        //self.config.mailer && steps.push(initMailer);
        self.config.supervisor && self.config.supervisor.address && steps.push(self.initSupervisors);
        self.config.supervisor && self.config.supervisor.console && steps.push(self.initBash);
        getmac.getMac(function (err, mac) {
            if (err) return callback(err);
            self.mac = mac.split(process.platform == 'win32' ? '-' : ':').join('').toLowerCase();

            self.emit('init::build', steps);

            steps.run(function (err) {
console.log("init::run".cyan.bold);
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

    dpc(function() {
        self.run();
    })
}

util.inherits(Application, events.EventEmitter);

Application.getConfig = getConfig;

module.exports = {
    Application : Application
}