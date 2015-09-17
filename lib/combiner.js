//
// -- IRIS Toolkit - Http request combiner
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
		_.each(self._httpFolders, function(p, index){
			self._httpFolders[index] = path.normalize(p);
		})
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
		self._folderAliasSortedByPath = _.sortBy(self._httpFolderAliasSorted, function(a, index, b) {
			
			c = a.path.split(path.sep);
			c = _.filter(c, function (i) {
				return i.length;
			})
			log("sorting-by-path".greenBG, a.path, c.length)
			return -c.length;
		});
		self._folderAliasSortedByAlias = _.sortBy(self._httpFolderAliasSorted, function(a, index, b) {
			
			c = a.folder.split('/');
			c = _.filter(c, function (i) {
				return i.length;
			})
			log("sorting-by-alias".greenBG, a.folder, c.length)
			return -c.length;
		});

		log("self._folderAliasSortedByPath", self._folderAliasSortedByPath);
		log("self._folderAliasSortedByAlias", self._folderAliasSortedByAlias);
	}

	if (_.isArray(self._options.folders))
		self.addHttpFolders(self._options.folders);

	self.sendHashContent = function(args){
		var files 	= args._req.files;
		var type 	= args._req.type;
		var hash    = args._req.hash;
		var res 	= args.res;
		var _cache	= cache[hash];
		var content = _cache.content;
		if (type == 'html'){
			res.setHeader('Content-Type', 'text/html');
			res.locals.req = args.req;
			content = self.renderFileContent({content: content, options: res.locals});
		}else if(type == 'css'){
			res.setHeader('Content-Type', 'text/css');
		}else{
			res.setHeader('Content-Type', 'text/javascript');
		}
		//log("content:options", _.extend({}, core.app.locals, res.locals))
		if (_cache.scripts) {
			_.each(_cache.scripts, function (script) {
				content = content.replace(script.tag, '<script combiner-src="'+script.src+'">'+script.content);
			});
		};
		res.end(content);
	}

	self.parseRequest = function(req){
		var files 	= req.originalUrl.split('/'+prefix)[1].split('?')[0];
		log("parseRequest:originalUrl,files:", req.originalUrl, files)
		if (!files)
			return false;

		var r = {};
		var typeNfiles 		= files.split(":");
		r.type 				= typeNfiles[0];
		if(_.contains(['js', 'css', 'html'], r.type)){
			typeNfiles.shift();
			r.files = typeNfiles.join(":").replace(/:/g, '/').split(spliter);
			_.each(r.files, function (file, i) {
				if (path.extname(r.files[i]) == '.map') {
					return
				};
				r.files[i] += '.'+r.type;
			});
		}else{
			r.files 		= files.replace(/:/g, '/').split(spliter);
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
		var cache  	= args.cache;
		var result = {
			components:{},
			dependencies:[],
			content: content+''
		}

		var c = content+'', hasAlias, _file, _folder, _src, src, realpath, f;
		//log("before comments removal:", c);
		c = c.replace(/<!--([\s\S]*?)-->/mig, '');
		
		//get dependencies (html components) list
		var matches = c.match(/<link rel="import" href="([^"]*?)\.html"[^>]*>/mig);
		_.each(matches, function(tag) {
			src = tag.split('href')[1].split('"')[1];
			realpath = false;
			_.find(self._folderAliasSortedByAlias, function (alias) {
				f = '/'+alias.folder+'/';
				log(" Alias:".greenBG, f)
				log("\n"+"src:".greenBG, src)
				if (src.indexOf(f) === 0){
					realpath = src.replace(f, alias.path);
					return true;
				}
			});
			log("\n"+"realpath:".redBG, realpath)
			realpath = realpath || path.join(folder, src);

			_file  		= path.basename(realpath);
			_folder 	= path.dirname(realpath)+path.sep;
			result.dependencies.push({file:_file, folder:_folder, tag:tag});
		});


		//adjust script path or create inline script
		matches = c.match(/<script[^>]*src="[^"]*"[^>]*>/mig);
		//log("script-matches", matches)
		_.each(matches, function(tag) {
			src = tag.split('src')[1].split('"')[1];
			hasAlias = realpath = false;
			_.find(self._folderAliasSortedByAlias, function (alias) {
				f = '/'+alias.folder+'/';
				log("f:###########:"+f.greenBG)
				if (src.indexOf(f) === 0){
					hasAlias = true;
					realpath = src.replace(f, alias.path);
					return true;
				}
			});

			if (!self._options.inlineScript && hasAlias){
				return;
			}

			realpath = realpath || path.join(folder, src);
			log("script-src", src, 'realpath:'.blueBG.white, realpath)

			if (fs.existsSync(realpath)) {
				log("fileExits:", realpath)
				if (self._options.inlineScript) {
					log("inlineScript:".yellowBG, src, realpath)
					cache.scripts = cache.scripts || {};
					cache.scripts[src] = {tag: tag, src: src, content: fs.readFileSync(realpath, {})};
					//result.content = result.content.replace(tag, '<script combiner-src="'+_file+'">'+inlineScriptContent);
				}else{
					_file  		= path.basename(realpath);
					_folder 	= path.dirname(realpath)+'/';
					_.find(self._folderAliasSortedByPath, function (alias) {
						if (_folder.indexOf(alias.path) === 0){
							src = path.join('/'+alias.folder+'/', _folder.substr(alias.path.length), '/'+_file)
							result.content = result.content.replace(tag, '<script combiner-src-fixed src="'+src+'">');
							return true;
						}
					});
				}
			};
		});

		//inline the component style
		matches = c.match(/<link[^>]*href="([^">]*)\.css"[^>]*>/mig);
		var inlineCssContent;
		matches && log("component-style-matches", matches)
		_.each(matches, function(tag) {
			src = tag.split('href')[1].split('"')[1];
			hasAlias = realpath = false;
			_.find(self._folderAliasSortedByAlias, function (alias) {
				f = '/'+alias.folder+'/';
				log("f:###########:"+f.greenBG)
				if (src.indexOf(f) === 0){
					hasAlias = true;
					realpath = src.replace(f, alias.path);
					return true;
				}
			});

			if (!self._options.inlineCss && hasAlias){
				return;
			}

			realpath = realpath || path.join(folder, src);
			log("css-src", src, 'realpath:'.blueBG.white, realpath)

			if (fs.existsSync(realpath)) {
				if (self._options.inlineCss) {
					inlineCssContent = fs.readFileSync(realpath, {});
					result.content = result.content.replace(tag, '<style combiner-css-href="'+src+'">'+inlineCssContent+'</style>');
				}else{
					_file  		= path.basename(realpath);
					_folder 	= path.dirname(realpath)+'/';
					_.find(self._folderAliasSortedByPath, function (alias) {
						if (_folder.indexOf(alias.path) === 0){
							src = path.join('/'+alias.folder+'/', _folder.substr(alias.path.length), '/'+_file)
							result.content = result.content.replace(tag, '<link rel="import" type="css" combiner-src-fixed href="'+src+'" />');
							return true;
						}
					});
				}
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
		var cache   = args.cache;
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
				var result = self.parseFileContent({content: content, folder: folder, _req:_req, cache: cache});
				content = result.content;

				//_req.components = _.extend(_req.components, result.components);
				_req.components[componentPath] = 1;
				//log("matches:".redBG, file.greenBG, result, _req.components);

				if (!result.dependencies.length){//no dependencies
					data.push(commentsTpl.replace('{file}', file)+content);
					callback();
					return;
				}
				log("result.dependencies\n", result.dependencies)
				core.asyncMap(result.dependencies, function(r, _callback){
					var componentPath 	= r.folder+r.file;
					var tag    			= r.tag;
					
					if (!componentPath)
						return _callback();

					if(_req.components[componentPath]){
						content = (content+'').replace(tag, tag.replace('<link', '<!--loaded-link')+' -->');
						return _callback();
					}

					
					self.readFile({file:r.file, folder:r.folder, data:data, _req:_req, commentsTpl:commentsTpl, cache: cache}, function (err) {
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

			var doCache = !req.query || !req.query.cache;
			var data = [], folder, _file;
			//console.log("scripts/combine".greenBG.bold, _req.hash, files, _req.files.length)
			//while testing
			if(doCache && !options.skipCache && cache[_req.hash])				
				return self.sendHashContent({req:req, res:res, next:next, _req:_req});

			cache[_req.hash] = {
				ts: Date.now()
			};

			var _cache = cache[_req.hash];

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

				file        = path.join(folder, file);

				folder 	    = path.dirname(file)+path.sep;
				file  		= path.basename(file);

				log("readFile: folder:", folder, "file:", file)
				self.readFile({file:file, folder:folder, data:data, _req:_req, commentsTpl:commentsTpl, cache:_cache}, callback);
			}, function(err){
				if (err) {
					next()
					return console.log("combine-error:1:".greenBG, err);
				}

				_cache.content = data.join("\n\r");
				self.sendHashContent({req:req, res:res, next:next, _req:_req});
			});
		});

		app.get('/icons:*', function(req, res, next){
			var files = req.originalUrl.split('/icons:')[1], folder;
			if (!files)
				return next();

			var data = {};
			var hash = crypto.createHash('md5').update(files).digest('hex');
			if(cache[hash]) {
				res.setHeader('Content-Type', 'text/html');
				res.end(cache[hash]);
				return;
			}

			core.asyncMap(files.split(';'), function(ident, callback){
				if (!ident)
					return callback();

				var parts = ident.split(':');
				if(parts.length == 1) {
					var t = parts.shift().split('/');
					parts[1] = t.pop();
					parts[0] = t.join('/');
				}
				var ref = parts.shift();
				var file = ref+'.html';
				var category = ref.split('/').pop();
				var id = parts.shift();
				if(!data[category])
					data[category] = [ ]

				console.log('generating icon:'.green.bold, (ident+'').bold);

				folder = _.find(self._httpFolders, function(_folder){
					return fs.existsSync(path.join(_folder,file));
				});

				if (!folder)
					return callback({error:file+": File not found"});

				if (file.indexOf('..') > -1)
					return callback({error: file+": is not valid name"})

				fs.readFile(path.join(folder,file), function(err, _data){
					if (err)
						return callback(err);

					var regexpA = new RegExp("<g\\sid=\""+id+"\"><g>.*<\/g><\/g>","ig");
					var regexpB = new RegExp("<g\\sid=\""+id+"\">.*<\/g>","ig");
					var text = _data.toString();
					var icon = text.match(regexpA);
					if (!icon)
						icon = text.match(regexpB);
					if (!icon)
						return callback({error:ident+": Icon not found"});

					data[category].push(icon.shift());
					callback()
				});
			}, function(err){
				if (err) {
					next()
					return console.log("icons-js:1:".greenBG, err);
				}

				var text = '';

				_.each(data, function(g, category) {
					text += '<iron-iconset-svg name="'+category+'" size="50"><svg><defs>';
					_.each(g, function(g) {
						text += g;
					})
					text += '</defs></svg></icon-iconset-svg>';
				})

				cache[hash] = text;
				res.setHeader('Content-Type', 'text/html');
				res.end(text);
			});
		});
	}	
	
}
//util.inherits(HttpCombiner, events.EventEmitter);

module.exports = HttpCombiner