var fs = require('fs');
var path = require('path');

eval(fs.readFileSync(path.join(__dirname,'scrypt_t.js'), { encoding : 'utf8' }));
var scrypt = scrypt_module_factory();
scrypt.encode = scrypt.crypto_scrypt;
module.exports = scrypt;