//
// -- Zetta Toolkit - User Login
//
//  Copyright (c) 2014 ASPECTRON Inc.
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

var fs = require('fs');
var _ = require('underscore');
var events = require('events');
var util = require('util');
var crypto = require('crypto');
var scrypt = require('./scrypt');
var base58 = require('zetta-base58');
var path = require('path');
// var ServeStatic = require('serve-static');
var notp = require('notp');
var base32 = require('thirty-two');

// http://stackoverflow.com/questions/14382725/how-to-get-the-correct-ip-address-of-a-client-into-a-node-socket-io-app-hosted-o
function getClientIp(req) {
	var ipAddress;
	// Amazon EC2 / Heroku workaround to get real client IP
	var forwardedIpsStr = req.header('x-forwarded-for'); 
	if (forwardedIpsStr) {
		// 'x-forwarded-for' header may return multiple IP addresses in
		// the format: "client IP, proxy 1 IP, proxy 2 IP" so take the
		// the first one
		var forwardedIps = forwardedIpsStr.split(',');
		ipAddress = forwardedIps[0];
	}
	if (!ipAddress) {
		// Ensure getting client IP address still works in
		// development environment
		ipAddress = req.connection.remoteAddress;
	}
	return ipAddress;
}


function Login(core, authenticator, options) {
	var self = this;
	events.EventEmitter.call(self);
	self.loginTracking = { }
    self.throttle = {attempts : 3, min : 3 }
    if(_.isObject(options.throttle))
    	_.extend(self.throttle, options.throttle);
    self.authenticator = authenticator;

    function getLoginTracking(ip) {
    	var o = self.loginTracking[ip];
    	if(!o) 
    		o = self.loginTracking[ip] = { unblock_ts : 0, attempts : 0, failures : 0 }
    	return o;
    }

	self.authenticate = function(args, callback) {
	    if(!self.authenticator)
	    	throw new Error("Login constructor requires authenticator argument");
		
		return self.authenticator.authenticate(args, callback);
	}

    self._getLogin = function (viewPath, req, res) {
		res.setHeader('login-required', true);
        res.render(viewPath,
            { Client : self.getClientJavaScript() }, function(err, html) {
                if(err) {
                    console.log(err);
                    return res.end("Server Error");
                }
                res.end(strip(html));
            });
    };

	self.getLogin = function(req, res, next) {
		self._getLogin(options.view || path.join(__dirname, 'views/login.ejs'), req, res);
	}

	self.postChallenge = function(req, res, next) {
		res.type('application/json');
		var ts = Date.now();
        var ip = getClientIp(req);
        var o = getLoginTracking(ip);

        if(options.throttle && o.unblock_ts > ts)
            return res.json(401, { error : "Your access to the login system remains blocked for "+getDurationString(o.unblock_ts-ts), throttle : true, ts: parseInt( (o.unblock_ts-ts) / 1000 ) });
        o.attempts++;        
        if(options.throttle && o.attempts > self.throttle.attempts) {
            o.attempts = 0;
            o.failures++;
            o.unblock_ts = ts+(self.throttle.min*((o.failures+1)/2)*60*1000);
            return res.json(401, { error : "Your access to the login system has been blocked for "+getDurationString(o.unblock_ts-ts), throttle : true, ts: parseInt( (o.unblock_ts-ts) / 1000 ) });
        }
		var auth = self.authenticator.getClientAuth(function(err, auth) {
			req.session.auth = auth;
			res.json(200, { auth : auth });
		});
	}

    self.logout = function(req, res, next) {
		var user = req.session.user;
		if(user){
			delete req.session.user;
			self.emit('user-logout', user);
		}
	}

	self.getLogout = function(req, res, next) {
		self.logout.apply(self, arguments);
		res.redirect(options.logoutRedirect || '/');
	}

	self.postLogout = function(req, res, next) {
		self.logout.apply(self, arguments);
		res.send(200);
	}

	self.postLogin = function(req, res, next) {
        res.type('application/json');

        if(!req.session.auth)
            return res.json(401, { error : "User name and password required" });

        if(!req.body.username || !req.body.password || !req.body.sig)
            return res.json(401, { error : "User name and password required" });

        var ts = Date.now();
        var ip = getClientIp(req);
        var o = getLoginTracking(ip);
        if(options.throttle && o.unblock_ts > ts)
            return res.json(401, { error : "Your access to the login system remains blocked for another "+getDurationString(o.unblock_ts-ts), throttle : true, ts: parseInt( (o.unblock_ts-ts) / 1000 ) });
        
        self.authenticate({ 
        	username : req.body.username, 
        	password : req.body.password, 
        	auth : req.session.auth,
        	sig : req.body.sig,
        	totpToken : req.body.totpToken
        }, function(err, user) {
        	delete req.session.auth;

            if(!user) {
                if(options.throttle && o.attempts > self.throttle.attempts) {
                    o.attempts = 0;
                    o.failures++;
                    o.unblock_ts = ts+(self.throttle.min*((o.failures+1)/2)*60*1000);
                    res.json(401, { error : "Your access to the login system has been blocked for "+getDurationString(o.unblock_ts-ts), throttle : true, ts: parseInt( (o.unblock_ts-ts) / 1000 ) });
                }
                else {
		            if(err)
		                res.json(401, err);
		            else
	                    res.json(401, { error : "Wrong login credentials" });
                }
            }
            else
            {
                if(user.blocked || user.blacklisted) {
                    res.json(401, { error : "User access blocked by administration"});
                }
                else {
					self.validateUser(user, function(err, userOk) {
			            if(err)
			                res.json(401, err);
			            else 
			            {
			                delete self.loginTracking[ip];
			                req.session.user = user;
			                delete req.session.auth;
				            self.emit('user-login', user);
				            (self.authenticator instanceof events.EventEmitter) && self.authenticator.emit('user-login', user);
			                res.json({ success : true });
			            }
					})
				}
            }

        })
	}

	self.validateUser = function(user, callback) {
/*
        if(!user.confirmed) {
            return callback({ error : "Waiting for user confirmation"});
        }
*/
		callback(null, true);
	}

	function strip(str) {
		return str;
	    //return str.replace(/\s{2,}/g, ' ');//.replace(/ENTER/g,'\n');
	    //return str.replace(/[\n\r]/g, ' ').replace(/\s{2,}/g, ' ');//.replace(/ENTER/g,'\n');
	    //return str.replace(/[\n\r]/g, '\t').replace(/ {2,}/g, ' ');//.replace(/\/**\//g,'/*\n*/');
	}

	function getDurationString(d) {
		var m = Math.floor(d / 1000 / 60);
		var s = Math.floor(d / 1000 % 60);
		if(s < 10) s = '0'+s;
		return m+' min '+s+' sec';
	}


/*
	self.init = function(app) {
		var _path = options.path || '';
		app.get(_path+'/logout', self.getLogout);
		app.post(_path+'/logout', self.postLogout);
		app.get(_path+'/login', self.getLogin);
		app.post(_path+'/challenge', self.postChallenge);
		app.post(_path+'/login', self.postLogin);

		app.use('/login/resources', ServeStatic(path.join(__dirname, 'http')));	

		app.use(function(req, res, next) {
			if(!req.session.user)
				return res.redirect('/login');
			next();
		})	
	}
*/
	self.getClientJavaScript = function() {
		var text = Client.toString();
		text = text
			.replace("CLIENT_PATH", JSON.stringify(options.path || ''))
			.replace("CLIENT_ARGS", JSON.stringify(self.authenticator.client));
		return "("+text+")()";
	}
}
util.inherits(Login, events.EventEmitter);


function Authenticator(core, options) {
	var self = this;
	events.EventEmitter.call(self);
	self.client = options.client;

	self.iterations = options.iterations || 100000;
	self.keylength = options.keylength || 4096/32;
	self.saltlength = options.saltlength || 4096/32;

	function encrypt(text) {
		if(!text || !options.cipher)
			return text;
		var key = _.isString(options.key) ? new Buffer(options.key,'hex') : options.key;
	    var cipher = crypto.createCipher(options.cipher, key);
	    var crypted = cipher.update(text, 'utf8', 'binary');
	    crypted += cipher.final('binary');
	    return  base58.encode(new Buffer(crypted, 'binary'));
	}
	 
	function decrypt(text, callback) {
		if(!text || !options.cipher)
			return callback(null, text);
		
		var key = _.isString(options.key) ? new Buffer(options.key,'hex') : options.key;
		base58.decode(text, function(err, data) {
			if(err)
				return callback(err);

		    var decipher = crypto.createDecipher(options.cipher, key);
		    var decrypted = decipher.update(data, 'binary', 'utf8');
		    decrypted += decipher.final('utf8');
		    callback(null, decrypted);
		});
	}

	function hex2uint8array(hex) {
		var bytes = new Uint8Array(hex.length/2);
		for(var i=0; i< hex.length-1; i+=2){
		    bytes[i] = (parseInt(hex.substr(i, 2), 16));
		}
		return bytes;
	}

	self.getClientAuth = function(callback) {
		crypto.randomBytes(256, function(err, bytes) {
			if(err)
				return callback(err);

			callback(null, bytes.toString('hex'));
		})
	}

	self.generatePBKDF2 = function(password, salt, iterations, keylength, callback) {
		crypto.pbkdf2(password, salt, iterations, keylength, function(err, key) {
			if(err)
				return callback(err);
			var res = ['pbkdf2', iterations, keylength, base58.encode(key), base58.encode(salt)].join(':');
			callback(null, res);
		})		
	}

	self.generateStorageHash = function(password, salt, callback) {
		if(!password)
			return callback('No password provided')
		
		if(_.isFunction(salt)) {
			callback = salt;
			salt = undefined;
		}

		if(_.isString(salt)) {
			salt = new Buffer(salt, 'hex');
		}

		if(!salt) {
			crypto.randomBytes(self.saltlength, function(err, _salt) {
				if(err)
					return callback(err);
				self.generatePBKDF2(password, _salt, self.iterations, self.keylength, function(err, key) {
					callback(err, encrypt(key));
				})
			});		
		} else {
			self.generatePBKDF2(password, salt, self.iterations, self.keylength, function(err, key) {
				callback(err, encrypt(key));
			})
		}			
	}

	self.generateExchangeHash = function(password, callback) {
		if(options.client.sha256) {
			var hash = crypto.createHash('sha256').update(password).digest('hex');
			callback(null, hash);
		}
		else
		if(options.client.scrypt) {
			var sc = options.client.scrypt;

	    	var hash = scrypt.crypto_scrypt(scrypt.encode_utf8(password),
					      hex2uint8array(sc.salt),
					      sc.n, sc.r, sc.p, sc.keyLength);
	    	callback(null, scrypt.to_hex(hash));
		}
	}

	self.compareStorageHash = function(args, _hash, callback) {
		var hash = decrypt(_hash, function(err, hash) {
			if(err)
				return callback(err);

			var parts = hash.split(':');
			if(parts.length != 5 || parts[0] != 'pbkdf2' || parseInt(parts[1]) != self.iterations)
				return callback({ error : "Wrong encoded hash parameters"})

			var iterations = parseInt(parts[1]);
			var keylength = parseInt(parts[2]);
			base58.decode(parts[4], function(err, salt) {
				if(err)
					return callback(err);

				self.generatePBKDF2(args.password, salt, iterations, keylength, function(err, key) {
					if(err)
						return callback(err);

					callback(null, hash === key);
				})
			});
		});
	}

	self.validateSignature = function(args, callback) {
		console.log("validateSignature",args);
		var sig = crypto.createHmac('sha256', new Buffer(args.auth, 'hex')).update(new Buffer(args.password, 'hex')).digest('hex');
		callback(null, args.sig == sig);
	}

	self.compare = function(args, storedHash, callback) {
		console.log("WARNGING! - Signature Validation is Disabled");
//		self.validateSignature(args, function(err, match) {
//			if(!match)
//				return callback({ error : "Wrong authentication signature"});
			self.compareStorageHash(args, storedHash, function(err, match) {
				if(err)
					return callback(err);
				if(!match)
					return callback({ error : "Unknown user name or password"})
				
				callback(null, true);
			})
//		})
	};

    self.generateTotpSecretKey = function(length) {
        length = length || 10;

        return crypto.randomBytes(length).toString('hex');
    };

    self.getTotpKeyForGoogleAuthenticator = function (key) {
        return base32.encode(key);
    };

    /*self.getBarcodeUrlPart = function (email, key) {
        return encodeURIComponent('otpauth://totp/' + email + '?secret=' + self.getTotpKeyForGoogleAuthenticator(key));
    };
    */
    self.getBarcodeUrlPart = function (email, key) {
        return 'otpauth://totp/' + email + '?secret=' + self.getTotpKeyForGoogleAuthenticator(key);
    };

    self.getBarcodeUrlForGoogleAuthenticator = function (email, key) {
        return 'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' + self.getBarcodeUrlPart(email, key)
    };

    self.getDataForGoogleAuthenticator = function (email, key) {
        if (!key) return {};
        return {
            totpKey: self.getTotpKeyForGoogleAuthenticator(key),
            barcodeUrl: self.getBarcodeUrlForGoogleAuthenticator(email, key),
            barcodeUrlPart: self.getBarcodeUrlPart(email, key)
        };
    }

    self.verifyTotpToken = function (token, key) {
        return notp.totp.verify(token, key, {});
    };
}
util.inherits(Authenticator, events.EventEmitter);

function BasicAuthenticator(core, options) {
	var self = this;
	Authenticator.apply(self, arguments);

	if(!options.users)
		throw new Error("BasicAuthenticator requires 'users' in options");

	self.authenticate = function(args, callback) {
		var username = args.username.toLowerCase();
        var password = options.users[username] ? options.users[username].password : null;
		if(!password)
			return callback(null, false);

		self.compare(args, password, function(err, match) {
            if(err || !match)
                return callback(err, match);

            if (options.users[username] && options.users[username].totp && options.users[username].totp.enabled) {
                if (!args.totpToken) {
                    return callback({request: 'TOTP'});
                }

                if (!self.verifyTotpToken(args.totpToken, options.users[username].totp.key)) {
                    return callback({error : "Wrong one time password"});
                }
            }

            callback(err, {
				username : username,
				success : true
			})	
		})
	}
}
util.inherits(BasicAuthenticator, Authenticator);

function MongoDbAuthenticator(core, options) {
	var self = this;
	Authenticator.apply(self, arguments);
	if(!options.collection)
		throw new Error("MongoDbAuthenticator requires 'collection' arguments.");

    self.users = {};
    self.cacheTime = 5; // 5 minutes

	var _username = options.username || 'email';
	var _password = options.password || 'password';

	self.authenticate = function(args, callback) {
        if (self.users[args.username]) {
            var user = self.users[args.username];
            self.compare(args, user[_password], function(err, match) {
                if(err || !match)
                    return callback(err, match);

                if (user.totp && user.totp.enabled) {
                    if (!args.totpToken) {
                        return callback({request: 'TOTP'});
                    }

                    if (!self.verifyTotpToken(args.totpToken, user.totp.key)) {
                        return callback({error : "Wrong one time password"});
                    } else {
                        delete self.users[args.username];
                    }
                }

                callback(err, user)
            });
        } else {
            var q = { }
            q[_username] = args.username;
            options.collection.findOne(q, function (err, user) {
                if (err || !user)
                    return callback({ error : 'Wrong user name or password' });

                self.compare(args, user[_password], function(err, match) {
                    if(err || !match)
                        return callback(err, match);

                    if (user.totp && user.totp.enabled) {
                        self.users[args.username] = user;
                        self.users[args.username].created = Date.now();

                        if (!args.totpToken) {
                            return callback({request: 'TOTP'});
                        }

                        if (!self.verifyTotpToken(args.totpToken, user.totp.key)) {
                            return callback({error : "Wrong one time password"});
                        } else {
                            delete self.users[args.username];
                        }
                    }

                    callback(err, user)
                })
            });
        }
	}

    // clean old user from memory
    setInterval(function() {
        _.each(self.users, function(user, i) {
            if (Date.now() - user.created > self.cacheTime * 1000 * 60) {
                delete self.users[i];
            }
        });
    }, 1000 * 60 * 5);

	self.on('user-login', function(user) {
		var conf = options.updateCollection;
		if (conf == false)
			return;

		var collection = options.collection, fieldName = 'last_login';
		if (_.isObject(conf)) {
			collection = conf.collection || collection;
			fieldName  = conf.fieldName || fieldName;
		}else if(_.isString(conf) ){
			fieldName = conf;
		}

		var q = { }, data = {};
		if (user[_username])
			q[_username] = user[_username];
		else if (user._id || user.id)
			q._id = user._id || user.id;
		else
			return;

		data[fieldName] = Date.now();
		collection.update(q, { $set : data}, {safe:true}, function(err) {
			//console.log('collection.update'.red, err)
		})
	});
}
util.inherits(MongoDbAuthenticator, Authenticator);

function ZettaRpcAuthenticator(core, options) {
	var self = this;
	Authenticator.apply(self, arguments);
	if(!options.rpc)
		throw new Error("ZettaRpcAuthenticator requires 'rpc' arguments.");
	var rpc = options.rpc;

	self.authenticate = function(args, callback) {

		rpc.dispatch({ op : 'user-auth'}, function(err, user) {
            if (err || !user)
                return callback({ error : 'Wrong user name or password' });

			self.compare(args, user.password, function(err, match) {
				if(err || !match)
					return callback(err, match);
			
				callback(err, user);
			})
		})
	}
}
util.inherits(ZettaRpcAuthenticator, Authenticator);


var Client = function() {
	var self = this;
	self.args = CLIENT_ARGS;
	self.path = CLIENT_PATH;

	function require(filename) {
		var script = document.createElement('script');
		script.setAttribute("type","text/javascript");
		script.setAttribute('src',filename);
		document.head.appendChild(script);
	}

	var files = [
		"/login/resources/hmac-sha256.js",
		"/login/resources/scrypt.js",
		"/login/resources/jquery.min.js"
	];

	function digest() {
		var file = files.shift();
		if(!file)
			return finish();
		var script = document.createElement('script');
		script.setAttribute("type","text/javascript");
		script.setAttribute('src',file);

		script.onload = function(){
        	setTimeout(digest);
    	};

		 /* for IE Browsers */
		 ieLoadBugFix(script, function(){
		     setTimeout(digest);
		 });

		function ieLoadBugFix(scriptElement, callback) {
        	if (scriptElement.readyState=='loaded' || scriptElement.readyState=='completed')
            	callback();
         	else 
            	setTimeout(function() { ieLoadBugFix(scriptElement, callback); }, 100);
		}

		document.head.appendChild(script);
	}

	function finish() {
		self.scrypt = scrypt_module_factory();
		self.onReady_ && self.onReady_.call(self, self);
	}

	self.ready = function(callback) {
		self.onReady_ = callback;
	};

	function hex2uint8array(hex) {
		var bytes = new Uint8Array(hex.length/2);
		for(var i=0; i< hex.length-1; i+=2){
		    bytes[i] = parseInt(hex.substr(i, 2), 16);
		}
		return bytes;
	}

	self.encrypt = function(username, password, salt, callback) {
		if(!username)
			return callback({ error : "Please supply username."});
		if(!password)
			return callback({ error : "Please supply password."});
		var hash = null;
		if(self.args.scrypt) {
			var ts = Date.now();
			var sc = self.args.scrypt;
	    	hash = self.scrypt.crypto_scrypt(self.scrypt.encode_utf8(password),
					      hex2uint8array(sc.salt),
					      sc.n, sc.r, sc.p, sc.keyLength);
	    	hash = self.scrypt.to_hex(hash);
		}
		else
		{
			hash = CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(password)).toString();
		}

		var sig = CryptoJS.HmacSHA256(CryptoJS.enc.Hex.parse(hash), CryptoJS.enc.Hex.parse(salt)).toString();
		callback(null, {
			username : username,
			password : hash,
			sig : sig
		});
	}

	function post(path, data, callback) {
	    $.ajax({
	        dataType: "json",
	        method : 'POST',
	        url: path,
	        data: data,
            error : function(err) {
                if(err.responseJSON) {
                    if (err.responseJSON.error)
                        callback(err.responseJSON);
                    else if (err.responseJSON.request) {
                        callback({ request : err.responseJSON.request });
                    }
                } else
                    callback({ error : err.statusText });
            },
            success: function(o) {
                callback(null, o);
            }
	    })
	}

	self.post = function(data, callback) {
		if(!data || !data.username || !data.password)
			return callback({ error : "Please enter user name and password"});

        var totpToken = data.totpToken;
		post(self.path+'/challenge', {}, function(err, challenge) {
			if(err)
				return callback(err);

			self.encrypt(data.username, data.password, challenge.auth, function(err, data) {
				if(err)
					return callback(err);

                data.totpToken = totpToken;

				post(self.path+'/login',data, function(err, resp) {
					callback(err, resp);
				})
			})
		})
	}

	digest();
}

module.exports = {
	Login : Login,
	Authenticator : Authenticator,
	BasicAuthenticator : BasicAuthenticator,
	MongoDbAuthenticator : MongoDbAuthenticator
}