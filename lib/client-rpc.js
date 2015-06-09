var util = require('util');
var events = require('events');

module.exports = ClientRPC;

function ClientRPC(core, options) {
    var self = this;
    events.EventEmitter.call(this);

    self.webSocketMap = { }
    self.userTracking = { }
    self.socketInitFnList = [ ]
    self.subscriptions = { }
    self.sidWebSocketMap = { }


    core.on('init::websockets', function() {
        self.initWebSockets(core.io);
    })


    self.bindRPC = function(rpc) {
        self.rpc = rpc;


        self.rpc.on('connect', function() {
            self.onlineMode = true;
            //self.webSockets.emit('online');
            self.emitToSockets('online');
        })

        self.rpc.on('disconnect', function() {
            self.onlineMode = false;
            self.emitToSockets('offline');
            //self.webSockets.emit('offline');
//          self.webSockets.emit('reload');
        })

    }

    self.initSocket = function(fn) {
        self.socketInitFnList.push(fn);
    }

    self.getToken = function(socket) {
        var info = self.getSocketInfo(socket);
        return self.userTracking[info.sid] && self.userTracking[info.sid].token;
    }

    self.getUser = function(socket) {
        var info = self.getSocketInfo(socket);
        return self.userTracking[info.sid];
    }

    self.getSocketInfo = function(socket) {
        var info = socket.__info;
        if(!info)
            info = socket.__info = {
                sid : core.getSocketSessionId(socket),
                refs : 0,
                subscriptions : { },
                auth : false
            }
        return info;
    }


    self.initWebSockets = function(io) {

        self.webSockets = io.of(options.path).on('connection', function(socket) {

            socket.emit('rpc-init', { });
        
            var info = self.getSocketInfo(socket);
            //info.sid = self.getSessionId(socket); //, function(err, user) {
            //info.sid = sid;
//          var uid = null;

            self.webSocketMap[socket.id] = socket;

            var wsList = self.sidWebSocketMap[info.sid];
            if(!wsList)
                wsList = self.sidWebSocketMap[info.sid] = [ socket ];
            else
                wsList.push(socket);

            /*if(err) {
                console.error(err);
                //console.log(socket);
                socket.disconnect();
                return;
            }
            */

            /*if(!user.token) {
                console.error("Error: no user token during websocket connect");
                socket.disconnect();
                return;
            }
            */


// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???
// DO WE NEED TRY / CATCH HANDLERS HERE ???


            console.log("private websocket "+socket.id+" connected");
            self.emit('websocket::connect', socket);
            
            
            //initSocket(socket);
            _.each(self.socketInitFnList, function(fn) {
                fn.call(self, socket)
            })


            //if(!self.webSocketTokens[user.token])
            //  self.webSocketTokens[user.token] = [ ]
            //self.webSocketTokens[user.token].push(socket.id);

            socket.on('disconnect', function() {
                self.emit('websocket::disconnect', socket);
                
                delete self.webSocketMap[socket.id];


                wsList.splice(wsList.indexOf(socket),1);

                self.cleanupSocketSubscriptions(socket);

                //if(self.webSocketTokens[user.token]) {
                //  self.webSocketTokens[user.token] = _.without(self.webSocketTokens[user.token], socket.id);
                //  if(!self.webSocketTokens[user.token].length)
                //      delete self.webSocketTokens[user.token];
                //}
                console.log("private websocket "+socket.id+" disconnected");
            })

            /*
            socket.on('rpc::request', function(msg) {
                try {
                    if(!msg.req) {

                        socket.emit('rpc::response', {
                            err : { error : "Malformed request" }
                        });

                    }
                    else {

                        msg.req.user = self.userTracking[info.sid];
                        if(!self.authenticator)
                            msg.req.token = msg.req.user && msg.req.user.token;
                        //console.log("msg.token:",msg.req.token,"info.sid:",info.sid);
                        //console.log("msg:",msg);

                        var listeners = self.listeners(msg.req.op);
                        console.log("listeners:",listeners);
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
                }
                catch(ex) { console.error(ex.stack); }
            });*/


            socket.on('rpc::request', function(msg) {
                try {
                    if(!msg.req) {

                        socket.emit('rpc::response', {
                            err : { error : "Malformed request" }
                        });

                    }
                    else {
                        
                        msg.req.user = self.userTracking[info.sid];
                        if(!core.authenticator)
                            msg.req.token = msg.req.user && msg.req.user.token;
                        

                        var iface;
                        var op = msg.req.op;

                        var parts = op.split('::');
                        var type = parts.shift();
                        op = parts.join('::');

                        var iface = type == 'rpc' ? self : core.iface[type];

                        if(!iface) {
                            return socket.emit('rpc::response', {
                                _resp : msg._req,
                                err : { error : "No such interface '"+msg.req.op+"'" }
                            });
                        }
                        else
                        if(!parts.length) {
                            return socket.emit('rpc::response', {
                                _resp : msg._req,
                                err : { error : "Missing message for interface '"+msg.req.op+"'" }
                            });

                        }

                        listeners = iface.listeners(op);                            

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
                }
                catch(ex) { console.error(ex.stack); }
            });


            socket.on('message', function(msg) {
                try {
//                      self.emit('websocket::'+msg.op, msg, socket, user.token);

                    msg.user = self.userTracking[info.sid];
                    if(!self.authenticator)
                        msg.token = msg.user && msg.user.token;
                    console.log("msg.token:",msg.token,"info.sid:",info.sid);
                    console.log("msg:",msg);

                    //self.emit(msg.op, msg, socket);

                    var listeners = self.listeners(msg.op);
                    if(!listeners.length) {

                    }
                    else {
                        for(var i = 0; i < listeners.length; i++)
                            listeners[i].call(socket, msg);
                    }



                }
                catch(ex) { console.error(ex.stack); }
            });
        });     




    }


    self.channels = { }


    self.on('subscribe', function(_args, callback) {
        var socket = this;
        var args = _args.info;
        var ident = args.realm+':'+args.op+':'+args.ident;

        if(!self.channels[ident])
            return callback({ error : 'No such channel' })

        //if(!socket._info)
        //    socket._info = { subscriptions : { }, refs : 0 }
        var info = self.getSocketInfo(socket);
        info.subscriptions[ident] = true;
        info.refs++;
        // subscriptions++;

        var sub = self.subscriptions[ident];
        if(!sub)
            sub = self.subscriptions[ident] = [ ]
        sub.push(socket);

//self.rpc.dispatch({ op : 'debug-push-orders', info : args });
//console.log('subscribing...', args);

        core.emit('subscription', args, socket);



        callback();

    })

    self.on('unsubscribe', function(_args, callback) {
        var socket = this;
        var args = _args.info;
        var ident = args.realm+':'+args.op+':'+args.ident;

        if(socket.__info) {
            var info = socket.__info;
            delete info.subscriptions[ident];
            info.refs--;
        }

        // subscriptions--;

        var sub = self.subscriptions[ident];
        if(sub) {
            var idx = sub.indexOf(socket);
            (idx != -1) && sub.splice(idx, 1);
        }
console.log('unsubscribing...');


        callback();
    })

    self.cleanupSocketSubscriptions = function(socket) {
        var info = socket.__info;
        if(info) {
            _.each(info.subscriptions, function(_misc, op) {
                var sub = self.subscriptions[op];
                if(sub) {
                    var idx = sub.indexOf(socket);
                    (idx != -1) && sub.splice(idx, 1);
                }
            })

            delete info.subscriptions;
        }
    }



    self.on('login', function(args, callback) {
        var socket = this;
        var info = self.getSocketInfo(socket);
        console.log("main login:",info);

        self.login(info, args, callback);
    })

// TODO - BROADCAST TO ALL SOCKETS FOR THE SAME USER
// SO THAT LOGIN CAUSES USER INTERFACE REFRESH IN ALL WINDOWS
// OPENED BY THE SAME BROWSER (SAME SESSION ID (SID))


    self.login = function(info, args, callback) {


        if(!args.username)
            return callback({ error : "Username required"})

        if(self.authenticator) {
            self.authenticator.authenticate(args, function(err, user) {
                console.log("AUTHENTICATE",arguments);
                if(err)
                    return callback(err);

                if(!user)
                    return callback(null, { allow : false });

                var token = {
                    ts : Date.now(),
                    user : user
                }

                self.userTracking[info.sid] = {
                    token : token,
                    id : user._id.toHexString()
                }
                callback(null, { allow : true });
            })
        }else {
            if(!self.rpc)
                throw new Error("'login' - RPC object is not set in brt-polymer instance")

            self.rpc.dispatch({
                op : 'authenticate',
                username : args.username,
                password : args.password
            }, function(err, resp) {

                console.log("LOGIN RESPONSE",resp);

                if(err)
                    return callback(err);

                if(resp.token) {
                    info.auth = true;
                    self.userTracking[info.sid] = {
                        token : resp.token,
                        id : resp.id,
                        nick : 'john-doe'
                    }
                    //self.tokenTracking[info.sid] = resp.token;
                    //self.idTracking[info.sid] = resp.id;
                    callback(null, { allow : true });
                }
                else {
                    callback(null, { allow : false });
                }
            })
        }
    }


//    self.logout = function(args, callback) {

    self.on('logout', function(args, callback) {

        var info    = self.getSocketInfo(this);
        var token   = self.getToken(this);

        if(self.authenticator) {
            delete info.auth;
            delete self.userTracking[info.sid];
            callback(null, {success: true});
        }else{
            if(!self.rpc)
                throw new Error("'logout' - RPC object is not set in brt-polymer instance");

            self.rpc.dispatch({
                op : 'logout',
                token : token
            }, function(err, resp) {
                console.log("logout callback");
                delete info.auth;
                //delete self.tokenTracking[info.sid];
                //delete self.idTracking[info.sid];
                delete self.userTracking[info.sid];
                callback(null, {success: true});
            })
        }
    })

    self.on('get-user-login', function(args, callback) {
        var info = self.getSocketInfo(this);
        var resp = {
            allow : self.userTracking[info.sid] && self.userTracking[info.sid].token ? true : false
        }
        callback(null, resp);
    })

    self.on('test-login', function(args) {
        console.log("test login:",this.__info);
        var info = self.getSocketInfo(this);
        console.log("INFO DURING TEST:",info);

        // console.log("THIS SOCKET IS ",self.tokenTracking[info.sid] ? "LOGGED IN".green.bold : "NOT LOGGED IN".red.bold);

    })







}

util.inherits(ClientRPC, events.EventEmitter);
