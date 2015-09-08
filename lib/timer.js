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

var _ = require('underscore');
var events = require('events');
var util = require('util');
var path = require('path');



function Timer(core, options){
	var self = this;
	events.EventEmitter.call(self);

	self._options 	= options || {};

	var time = 0, running = false, timeOutId=false;
	
	self.initHttp = function(app){

	}

	self.reset = function(){
		time = 0;
		self.stop();
		self.notify();
	}

	self.stop = function(){
		running = false;
	}

	self.start = function(seconds){
		seconds && self.setSeconds(seconds);
		running = true;
		if (timeOutId) {
			clearTimeout(timeOutId);
			timeOutId = false;
		};

		self._run();
	}

	self.setSeconds = function(seconds){
		time = seconds;
	}

	self._run = function(){
		if (!running || time < 0)
			return;

		self.notify();
		time--;
		if (time < 0)
			running = false;
		

		timeOutId = setTimeout(function(){
			self._run();
		}, 1000);
	}

	self.notify = function(){
		self.emit('tick', {seconds:time});
	}
}
util.inherits(Timer, events.EventEmitter);

module.exports = Timer