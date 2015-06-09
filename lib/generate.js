var crypto = require('crypto');
var login = require("./zetta-login")
var scrypt = require("./scrypt");

var authenticator = new login.BasicAuthenticator({ 


}, { 
	cipher : 'aes-256-cbc',
	key : 'd9a050dade41fe169d449d5d7f113173cbd6cc0a44c4c29d496547dcc3721612',
	client : {
		scrypt : {
			n : 16384,
			r : 4,
			p : 1,
			salt : 'd0b402c78c865309c594d24dc395f52ecc4cc9946f22f22ae19f46d9b13618da',
			keyLength : 256
		}
	},
	users : { } 
});
console.log(authenticator.options);
var args = process.argv.slice(2);
var pass = args.shift();
if(!pass)
	console.log("Please supply password as script argument");
else
	generate();

function generate() {

	var ts = Date.now();
	authenticator.generateExchangeHash(pass, function(err, exchangeHash) {
		console.log("EXCHANGE HASH:",arguments);
		ts = Date.now() - ts;
		console.log("ts:",ts);
		console.log('\nEXCHANGE:\n'+exchangeHash);
		ts = Date.now();
		authenticator.generateStorageHash(exchangeHash, function(err, storageHash) {
			ts = Date.now() - ts;
			console.log("ts:",ts);
			console.log('\nSTORAGE:\n'+storageHash);
		})
	})

}