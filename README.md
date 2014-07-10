zetta-app
=========

Zetta Toolkit - Application Framework


Zetta-App was originally created to help multiple projects stay on top of latest express releases.  Zetta-App offers a base application class that contains a number of facilities that may be needed by the application.  These facilities can be activated by introducing appropriate configuration file objects.

For example, adding http object to the config file as follows:

```js
{
	http : {
		port : 8765		
	}
}
```

will automatically instantiate application's http server.

Following features are available:

- Config file loading
- Event notification during init stages
- Binding mongodb collections & indexes via config object
- HTTP server
- Login subsystem
- Custom Web Socket interface
- Translation interface
- Supervisor connectivity (RPC to a monitoring server)

Application object is reffered to as `core` and contains following:

Application.getConfig()
Application.readJSON()
Application.writeJSON()

### Functions
- **initBeforeHttp** - 
- **init** - 
- **restoreDefaultSettings** - set data from global settings file to 'settings' property
- **restoreSettings** - override global settings by local
- **storeSettings** - storing settings to local settings file
- **initTranslator** - initialize translator module
- **initCertificates** - initialize ssl certificates
- **initMonitoringInterfaces** - initialize stats, profiler, monitor
- **initMailer** - initialize mailer
- **initDatabaseConfig** - initialize DB
- **initDatabaseCollections** - initialize single connection???
- **getHttpSessionSecret** - get hashed session secret word
- **initExpressConfig** - initialize express application
- **initExpressHandlers** - initialize
- **handleHttpError** - express middleware for error handling
- **initHttpServer** - runs http server


- **initSupervisors** -
- **initWebsocket** -



- **initBeforeHttp** -
- **init** -
- **run** -



### Properties

- **uuid** - 
- **mac** -
- **macBytes** -
- **caption** - package name
- **config** -
- **settings** -
- **pingDataObject** - ?? used for supervisors {loadAvg, memory}
- **translator** - instance of translator module
- **verbose** - ?? for enabling certificates ??
- **certificates** - {key, cert, ca: []}
- **** - 
- **stats** - https://github.com/aspectron/zetta-stats
- **profiler** - https://github.com/aspectron/zetta-stats
- **monitor** - https://github.com/aspectron/zetta-stats

- **mailer** - instance of nodemailer @see https://github.com/andris9/Nodemailer

- **db** - list of collections
- **databases** - list of db connections

- **app** - instance of express

- **authenticator** - instance of Authentication class
- **login** - instance of Login class

- **io** - socketio
- **router** - ???

- **supervisor** -instance of zrpc.Client @see


- **webSocketMap** - array of
- **webSockets** -
- **login** -
- **login** -
- **login** -
- **login** -
- **login** -

### Events (sorted by happen )

1. **init::database** -
1. **init::build** -
1. **init::express** -
1. **init::express::error-handlers** -
1. **init::express::done** -
1. **init::websockets** -
1. **init::http::done** -
1. **init::http-server** -
1. **init::done** -

- **websocket::connect** - 
- **websocket::disconnect** -

```js
self.on('init::database', function(steps) {

        steps.push(function(callback) {
            self.db.clients.findOne({ email : 'fug' }, function(err, user) {
                if(!user) {
                    self.db.clients.insert({ email : 'user@example.com', password : '3yy7bTQ3yUyxMax1bZ1t8auAk5APwoB4' }, function() {
                        callback();
                    })
                }
                else
                    callback();
            })
        })
```



config file must place in 'config' directory of app root folder.
config file name - as package module name with 'conf' extension
for example:
- car-rental.conf - global config file
you can override global config own local files:
- car-rental.my-laptop.conf - local config file (use OS hostname)
- car-rental.local.conf - local config file



settings file must place in 'config' directory of app root folder.
- car-rental.my-laptop.settings - local settings file (use OS hostname)


```js
{
    maxHttpSockets
    translator
    certificates

    statsd
    monitor

    mailer: {
        pickup: true, //  for storing the e-mail in 'mailer' directory of root
        // or

    }

    mongodb : { main : "mongodb://localhost/dbname" },

    session.secret
    websocket
    websocket.path

    http {
        static // array or object/ for static content
        login
        ssl
}
```



```
    Project structure:
    -- config
    ---- app_name.conf
    ---- app_name.settings
    -- mailer
    -- views
```



Need in your app add
```
    self.puid = UUID.v1();

    self.databaseConfig = [
        {
            config: 'main',
            collections: [
                {collection: 'tokens', indexes: 'token->unique'},
                {collection: 'storage', indexes: 'name'},
                {collection: 'clients', indexes: 'email->unique;apikeys.id->unique'},
                {collection: 'accounts', indexes : 'client_id' },
                {collection: 'addresses', indexes : 'address->unique;account_id;type;currency;'},//, indexes: 'owner'},
                {collection: 'transactions', indexes: 'ts;type;txin;height,client_id;account_id'},
                {collection: 'invoices', indexes: 'tsInvoice;tsExpire;apikey;'}
            ]
        }
    ];
```

