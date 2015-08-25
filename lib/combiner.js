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
var ejs = require("ejs");

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
	self._httpFolderAlias = {};
	self._httpFolderAliasSorted = [];

	function log(){};
	if (options.debug){
		log = function () {
			var args = Array.prototype.slice.call(arguments, 0);
			args.unshift('HttpCombiner:'.greenBG);
			console.log.apply(console, args);
		}
	}

	self.addHttpFolders = function(folders){
		if (_.isArray(folders)) {
			self._httpFolders = self._httpFolders.concat(folders);
		}else{
			self._httpFolders.push(folders);
		}
		self._httpFolders = _.uniq(self._httpFolders);
		log("_httpFolders:", self._httpFolders)
	}
	self.addHttpFolderAlias = function(alias) {
		_.each(alias, function(_path, folder) {
			if (self._httpFolderAlias[folder]) {
				//throw error?
				return;
			};
			self._httpFolderAlias[folder] = _path;
			self._httpFolderAliasSorted.push({
				path: path.join(_path,""),
				folder: folder
			});
		});


		var c;
		self._httpFolderAliasSorted = _.sortBy(self._httpFolderAliasSorted, function(a, index, b) {
			
			c = a.path.split('/');
			c = _.filter(c, function (i) {
				return i.length;
			})
			//log("sorting", a.path, c.length)
			return -c.length;
		});

		//log("self._httpFolderAliasSorted", self._httpFolderAliasSorted);
	}

	if (_.isArray(self._options.folders))
		self.addHttpFolders(self._options.folders);

	self.sendHashContent = function(args){
		var files 	= args._req.files;
		var type 	= args._req.type;
		var hash    = args._req.hash;
		var res 	= args.res;
		var content	= cache[hash];
		if (type == 'html'){
			res.setHeader('Content-Type', 'text/html');
			content = self.renderFileContent({content: content, options: res.locals});
		}else if(type == 'css'){
			res.setHeader('Content-Type', 'text/css');
		}else{
			res.setHeader('Content-Type', 'text/javascript');
		}
		//log("content:options", _.extend({}, core.app.locals, res.locals))
		res.end(content);
	}

	self.parseRequest = function(req){
		var files 	= req.originalUrl.split('/'+prefix)[1];
		log("parseRequest:originalUrl,files:", req.originalUrl, files)
		if (!files)
			return false;

		var r = {};
		var typeNfiles 		= files.split(":");
		r.type 				= typeNfiles[0];
		if(_.contains(['js', 'css', 'html'], r.type)){
			typeNfiles.shift();
			r.files = typeNfiles.join(":").split(spliter);
			_.each(r.files, function (file, i) {
				r.files[i] += '.'+r.type;
			});
		}else{
			r.files 		= files.split(spliter);
			var firstFile 	= r.files[0];
			if (!firstFile)
				return false;

			r.type 	= firstFile.toLowerCase().split('.').pop();

			if(!_.contains(['js', 'css', 'html'], r.type)){
				log("Invalid request type:"+r.type);
				return false;
			}
		}

		r.hash 	= crypto.createHash('md5').update(req.originalUrl).digest('hex');
		r.components = {}//holder for loaded components
		return r;
	}

	self.parseFileContent = function (args) {
		var content = args.content;
		var folder  = args.folder;
		var result = {
			components:{},
			dependencies:[],
			content: content+''
		}

		var c = content+'', hasAlias, _file, _folder, _src;
		//log("before comments removal:", c);
		c = c.replace(/<!--([\s\S]*?)-->/mig, '');
		
		//get dependencies (html components) list
		var matches = c.match(/<link rel="import" href="([^"]*?)\.html"[^>]*>/mig);
		_.each(matches, function(tag) {
			d = tag.split('href')[1].split('"')[1];
			hasAlias = false;
			_.each(self._httpFolderAlias, function (path, f) {
				f = '/'+f+'/';
				if (d.indexOf(f) === 0){
					hasAlias = true;
					d = d.replace(f, path);
				}
			});

			if (!hasAlias)
				d = folder+d;

			d 			= d.split('/');
			_file  		= d.pop();
			_folder 	= d.join('/')+'/';
			result.dependencies.push({file:_file, folder:_folder, tag:tag});
		});


		//adjust script path
		var src, matches = c.match(/<script[^>]*src="[^"]*"[^>]*>/mig);
		//log("script-matches", matches)
		_.each(matches, function(tag) {
			src = tag.split('src')[1].split('"')[1];
			hasAlias = false;
			_.each(self._httpFolderAlias, function (path, f) {
				f = '/'+f+'/';
				if (src.indexOf(f) === 0){
					hasAlias = true;
				}
			});

			if (hasAlias)
				return;

			src = path.join(folder, src);
			log("src-hasAlias", src)

			_src 		= src.split('/');
			_file  		= _src.pop();
			_folder 	= _src.join('/')+'/';

			_.find(self._httpFolderAliasSorted, function (alias) {
				if (_folder.indexOf(alias.path) === 0 && fs.existsSync(src)){
					src = path.join('/'+alias.folder+'/', _folder.substr(alias.path.length), '/'+_file)
					result.content = result.content.replace(tag, '<script combiner-src-fixed src="'+src+'">');
					return true;
				}
			});
		});

		//inline the component style
		matches = c.match(/<link[^>]*href="([^"]*)\.css"[^>]*>/mig);
		var inlineCssContent;
		log("component-style-matches", matches)
		_.each(matches, function(tag) {
			src = tag.split('href')[1].split('"')[1];
			hasAlias = false;
			_.each(self._httpFolderAlias, function (path, f) {
				f = '/'+f+'/';
				if (src.indexOf(f) === 0){
					hasAlias = true;
				}
			});

			if (hasAlias)
				return;

			_src = path.join(folder, src);
			log("css-href-hasAlias", _src.greenBG)
			/*
			_src 		= src.split('/');
			_file  		= _src.pop();
			_folder 	= _src.join('/')+'/';
			
			_found = _.find(self._httpFolderAliasSorted, function (alias) {
				log("cssfolder: alias.path", alias.path,"," ,src)
				if (_folder.indexOf(alias.path) === 0 && fs.existsSync(src)){
					//src = path.join('/'+alias.folder+'/', _folder.substr(alias.path.length), '/'+_file)
					inlineCssContent = fs.readFileSync(src, {});
					result.content = result.content.replace(tag, '<style combiner-css-inline>'+inlineCssContent+'</style>');
					return true;
				}
			});
			*/
			if (fs.existsSync(_src)) {
				inlineCssContent = fs.readFileSync(_src, {});
				result.content = result.content.replace(tag, '<style combiner-css-href="'+src+'">'+inlineCssContent+'</style>');
			};
		});


		/* dont need this if we dont load any -min.html file
		var matches = c.match(/<dom-module[\s\S]*?id="([\s\S]*?)"[\s\S]*?>/mig);
		_.each(matches, function(d) {
			d = d.split('id')[1].split('"')[1];
			result.components[d] = 1;
		})
		*/
		return result;
	}

	self.renderFileContent = function (args) {
		var content = args.content;
		var data 	= _.extend({}, core.app.locals, args.options || {});
		return ejs.compile(content, {})(data);
	}

	self.readFile = function(args, callback) {
		var folder 	= args.folder;
		var file 	= args.file;
		var data    = args.data;
		var _req    = args._req;
		var type 	= _req.type;
		var commentsTpl = args.commentsTpl;
		var componentPath = path.join(folder, file);

		//log("folder,file", folder, ',', file);

		if (_req.components[componentPath])
			return callback();

		fs.readFile(componentPath, function(err, content){
			if (err)
				return callback(err);
			//log("file:", file)
			if (type == 'html'){
				var result = self.parseFileContent({content: content, folder: folder});
				content = result.content;

				//_req.components = _.extend(_req.components, result.components);
				_req.components[componentPath] = 1;
				//log("matches:".redBG, file.greenBG, result, _req.components);

				if (!result.dependencies.length){//no dependencies
					data.push(commentsTpl.replace('{file}', file)+content);
					callback();
					return;
				}

				core.asyncMap(result.dependencies, function(r, _callback){
					var componentPath 	= r.folder+r.file;
					var tag    			= r.tag;
					
					if (!componentPath)
						return _callback();

					if(_req.components[componentPath]){
						content = (content+'').replace(tag, tag.replace('<link', '<!--loaded-link')+' -->');
						return _callback();
					}

					
					self.readFile({file:r.file, folder:r.folder, data:data, _req:_req, commentsTpl:commentsTpl}, function (err) {
						if (err)
							return _callback(err);

						content = (content+'').replace(tag, tag.replace('<link', '<!--loaded-link')+' -->');
						_callback();
					});
				}, function (err) {
					if (err)
						return callback(err);

					data.push(commentsTpl.replace('{file}', file)+content);
					callback();
				});
				return;
			}

			data.push(commentsTpl.replace('{file}', file)+content);
			callback();
		});
	}

	self.initHttp = function(app) {

		app.get('/'+prefix+'*', function(req, res, next){
			var _req = self.parseRequest(req);
			if (!_req)
				return next();

			var data = [], folder, _file;
			//console.log("scripts/combine".greenBG.bold, _req.hash, files, _req.files.length)
			//while testing
			if(!options.debug && cache[_req.hash])				
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

				var commentsTpl = "\n\r/* ---[{file}]---\*/\r\n";
				if (_req.type=='html')
					commentsTpl = "\n\r<!----[{file}]--->\r\n";

				file = path.join(folder, file);

				_file 		= file.split('/');
				file  		= _file.pop();
				folder 		= _file.join('/')+'/';
				log("readFile:", "folder:", folder, "file:", file)
				self.readFile({file:file, folder:folder, data:data, _req:_req, commentsTpl:commentsTpl}, callback);
			}, function(err){
				if (err) {
					next()
					return console.log("combine-error:1:".greenBG, err);
				}

				cache[_req.hash] = data.join("\n\r");
				self.sendHashContent({req:req, res:res, next:next, _req:_req});
			});
		});
	}	
	
}
//util.inherits(HttpCombiner, events.EventEmitter);

module.exports = HttpCombiner