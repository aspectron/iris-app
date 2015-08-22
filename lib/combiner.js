//
// -- Zetta Toolkit - Http request combiner
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
var path = require('path');
//var UUID = require("node-uuid");

function merge(dst, src) {
    _.each(src, function(v, k) {
        if(_.isArray(v)) { dst[k] = [ ]; merge(dst[k], v); }
        else if(_.isObject(v)) { if(!dst[k] || _.isString(dst[k]) || !_.isObject(dst[k])) dst[k] = { };  merge(dst[k], v); }
        else { if(_.isArray(src)) dst.push(v); else dst[k] = v; }
    })
}

function HttpCombiner(core, options){
	var self = this;
	//events.EventEmitter.call(self);

	self._options 	= options || {};
	var prefix 		= self._options.prefix || 'combine:';
	var spliter 	= self._options.spliter || ';';

	var cache = { };
	self._httpFolders = [];

	self.addHttpFolders = function(folders){
		if (_.isArray(folders)) {
			self._httpFolders = self._httpFolders.concat(folders);
		}else{
			self._httpFolders.push(folders);
		}
		self._httpFolders = _.uniq(self._httpFolders);
	}

	if (_.isArray(self._options.folders))
		self.addHttpFolders(self._options.folders);

	self.sendHashContent = function(args){
		var files 	= args._req.files;
		var type 	= args._req.type;
		var hash    = args._req.hash;
		var res 	= args.res;
		if (type == 'html'){
			res.setHeader('Content-Type', 'text/html');
		}else if(type == 'css'){
			res.setHeader('Content-Type', 'text/css');
		}else{
			res.setHeader('Content-Type', 'text/javascript');
		}
		res.end(cache[hash]);
	}

	self.parseRequest = function(req){
		var files 	= req.originalUrl.split('/'+prefix)[1];
		if (!files)
			return false;

		var r = {};
		r.files 		= files.split(spliter);
		var firstFile 	= r.files[0];
		if (!firstFile)
			return false;

		r.type 	= firstFile.toLowerCase().split('.').pop();
		if(!_.contains(['js', 'css', 'html'], r.type)){
			console.log("combine-js:".greenBG, "Invalid request type:"+r.type);
			return false;
		}

		r.hash 	= crypto.createHash('md5').update(req.originalUrl).digest('hex');
		return r;
	}

	self.initHttp = function(app) {

		app.get('/'+prefix+'*', function(req, res, next){
			var _req = self.parseRequest(req);
			if (!_req)
				return next();

			var data = [], folder;
			//console.log("scripts/combine".greenBG.bold, _req.hash, files, _req.files.length)
			if(cache[_req.hash])				
				return self.sendHashContent({req:req, res:res, next:next, _req:_req});

			core.asyncMap(_req.files, function(file, callback){
				if (!file)
					return callback();

				folder = _.find(self._httpFolders, function(_folder){
					//console.log("_folder+file".greenBG, _folder+file)
					return fs.existsSync(_folder+file);
				});
				if (!folder)
					return callback({error:file+": File not found"});
				if (file.indexOf('..') > -1)
					return callback({error: file+": is not valid name"})

				fs.readFile(folder+file, function(err, _data){
					if (err)
						return callback(err);

					data.push("\n\r/* ---["+file+"]---\*/\r\n"+_data);
					callback()
				});
			}, function(err){
				if (err) {
					next()
					return console.log("combine-js:1:".greenBG, err);
				}

				cache[_req.hash] = data.join("\n\r");
				self.sendHashContent({req:req, res:res, next:next, _req:_req});
			});
		});
	}	
	
}
//util.inherits(HttpCombiner, events.EventEmitter);

module.exports = HttpCombiner