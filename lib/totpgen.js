var login = require("./zetta-login")

var authenticator = new login.Authenticator({}, {});
var args = process.argv.slice(2);
var username = args.shift() || 'fug';

generate();

function generate() {
    var totpSecretKey = authenticator.generateTotpSecretKey();
    console.log("TOTP secret code for config:", totpSecretKey, '\n\n');

    var googleAuthenticator = authenticator.getDataForGoogleAuthenticator(username, totpSecretKey);
    console.log("Google authenticator data: \n");
    console.log("Key:", googleAuthenticator.totpKey, '\n');
    console.log("Barcode url:", googleAuthenticator.barcodeUrl);
}