## IRIS - SaaS / Web Application Foundation Framework

IRIS is a NodeJs foundation layer that allows creation of Web Applications 
by integrating layers of standard libraries while providing developers with full control
of the environment.

IRIS provides application structure by streamlining initialization of the following modules & features:

* Application-specific configuration files
* HTTP Certificate initialization
* Express & HTTP request routing
* Profiling execution by sampling into Graphite
* Support for NodeJs Clustering
* MongoDB Integration
* EJS (Main templating engine)
* Client-side (browser) WebSocket handling & user session identification (socket.io)

IRIS is not currently compatible with other templating engines such as JADE.

Web Application User Interface & SaaS Features

* [iris-i18n](https://github.com/aspectron/iris-i18n) - Multi-language content translation backend (allows manual site content translation into any language)
* [iris-login](https://github.com/aspectron/iris-login) - User authentication framework
* [iris-polymer](https://github.com/aspectron/iris-polymer) - Google Polymer components & content optimizers (Used for application development)
* [iris-mdl](https://github.com/aspectron/iris-mdl) - Google MDL components (Used for lightweight web site development)
* [iris-rpc](https://github.com/aspectron/iris-rpc) - Cross-process encrypted RPC communication (JSON over TLS)
* [iris-ha](https://github.com/aspectron/iris-ha) - High Availability functionality (UDP-broadcast driven master selection)
* [iris-stats](https://github.com/aspectron/iris-stats) - Tracking of basic server statistics (RAM, Bandwidth, DiskSpace) with Graphite Interface
* [iris-underscore](https://github.com/aspectron/iris-underscore) - Asynchronous extensions for the UnderscoreJS library
* [iris-twitter](https://github.com/aspectron/iris-twitter) - Helper library for fetching user tweets
* [iris-crypt](https://github.com/aspectron/iris-crypt) - Allows storing NodeJs modules in a single encrypted package file. (Allows to protect code with a per-user specific authentication key)
* [iris-express-helper](https://github.com/aspectron/iris-express-helper) - Functionality to help control EJS page rendering flow.




## Typicall use of IRIS

* Quick stand-alone NodeJS application with configuration files
* Scalable cluster of daemons with a central controller (or any custom communication logic)
* Simple web app
* Full-featured web application with web socket RPC
* Web application driven by Google Polymer with multi-lingual interface
* Complex scalable multi-module SaaS infrastructure

## Prerequisites

#### Linux
For linux you need to install following libraries:
* build-essential
* libkrb5-dev (required by `mongo-connect`)

In Ubuntu/Debian based systems you can run:
`apt-get install build-essential libkrb5-dev`

#### Windows
* Visual Studio Community (or any other edition) with C++ Compiler

#### Misc.

IRIS is typically ran along side of MongoDB.  If mongodb is configured, IRIS will use mongodb for HTTP session storage.  Otherwise it uses `ExpressSession.MemoryStore` memory storage (which is not persistent).

## Dependencies

IRIS depends on variety of modules,

## Folder Structure

IRIS imposes a specific file & folder structore for the web application as follows:

* `CONFIG/your-app.cfg` - main application configuration file
* `CERTIFICATES/your-app.key` - optional: SSL certificates
* `CERTIFICATES/your-app.crt` - optional: SSL certificates
* `DEPLOY/UPSTART/your-app.conf` - optional: deployment configuration scripts
* `HTTP/` - optional: all content served via HTTP typically in subfolders scripts/ images/ styles/ etc
* `LIB/` - recommended: various application related scripts
* `LOGS/` - application logs
* `VIEWS/` - EJS views
* `your-app.js` - main application script
* `run.js` - execution wrapper (application is typically ran as `node run your-app.js`)
* `package.json` - application package.json descriptor
* `.gitignore` - regular gitignore

## Logs

IRIS applications output logs to console.  IRIS framework does not use logging facilities such as winston, however you are welcome
to use that in your application.  Instead, when running iris based application, it should be executed using the `run.js` wrapper
as follows `node run your-app`.

`run.js` availables at https://github.com/aspectron/iris-app/blob/master/utils/run.js (just copy this file into your application folder)

`run.js` will spawn `your-app` as a child process and pipe the application console output into `/logs/your-app.log` as well as dump the output back to console.  At any point, this allows you to execute `tail -f logs/your-app.log` to see the application output.  If you frequently restart the application (for example during debugging) you can run `tail -F logs/you-app.log`.  `-F` will force `tail` to re-open the stream even if it has been truncated due to process termination.

The main benefit of this approach to logging is that in case you experience system errors (module buffer or stack overflow in NodeJs, you will be able to see the error dump, whereas an integrated logging system will not be able to record it as the message is typically displayed upon process termination.

Logs are rotated daily and logs from the previous day are compressed into a `L-<DATE>.tgz` archive.

*You must make sure that `your-app/logs` folder is present.*



## Setting up NodeJS on your system

We have done a number of nodejs deployments and each user has their own preference on how to handle things.  Node ecosystem has been evolving rapidly over years, as such we prefer not to install NodeJS onto the system but rather install it locally, in such way that it is available to run specific applications within a single user account (and another version can be available to run different applications in another user account).

(This is especially important to the Upstart structure described below.)

To download and install NodeJS on the system, you can do the following:

- Copy the download URL from http://nodejs.org (you should be runnign 64bit versions)
- `cd ~` (change to your home folder)
- `wget <link>` (download the link to your home folder, for example: `wget https://nodejs.org/dist/v4.4.5/node-v4.4.5-linux-x64.tar.xz`)
- `tar xf node-v4.4.5-linux-x64.tar.xz` (untar the file)
- `ln -s node-v4.4.5-linux-x64.tar.xz node` (create `~/node` symlink)

The last step is especially important as it allows you to have `node` folder (as a symlink) and if you update to future versions, you can simply re-create a symlink to a folder containing a different version of nodejs.  Also, in this setup, app your NPM activity (caches and globally installed modules will reside in `~/.npm`)

Last important step is to add node to your path.  Edit a startup file used by bash shell: `~/.profile` (`nano ~/.profile`) to contain the following at the last line:

```bash
PATH="$HOME/node/bin:$PATH"
```

In-house, we keep everything in `~/releases` folder so our path is actually `PATH="$HOME/releases/node/bin:$PATH"`.

Whatever is the path, it is important that upstart config (described below) can reference it via `../node`.

Once the path has been added, you must exit and re-login into the shell.

Once done, you can check if node is accessible by typing `node -v`.  If node runs and prints it's version number, you are all set.  You can now clone your repositories and do `npm install` in those folders.


## Deploying as Ubuntu Upstart service

There are multiple ways to run a process as a daemon in a linux system.  Our choice is upstart that comes with ubuntu.

To run an application using upstart, you need to create `your-app.conf` file containing upstart configuration and place it into `/etc/init/` folder.

Following this, you can manage the process (as a root) using `sudo start your-app`, `sudo stop your-app`, `sudo restart your-app`, where `your-app` is the name of your configuration file.

One of the issues we have encountered is that you must stop the process before making any changes to `/etc/init/your-app.conf`.  Otherwise `sudo stop your-app` may not work.

Once running, you can check the execution state by doing `ps ax | grep your-app` or `ps ax | grep node`.

When running as a daemon, you can monitor application output by tailing its logs (described in the Logs section above).

**NOTE on SECURITY:** remember, upstart runs your process as `root` user.  `root` user is necessary if you are opening ports below port 2000 (like http port 80).  If you want to open port 80 but run your process constrained to your user id, you must add `secureUnderUser : 'your-username'` in the `config/your-app.conf`.  This will start the process as a root, open up HTTP sockets below port 2000 and then downgrade process access rights to the username you have specified.

Here are the contents of the upstart `.conf` file:

```bash
# this should live in /etc/init
description "YOUR-APP"

# start process on system startup
start on filesystem
stop on shutdown

# Automatically Respawn:
respawn
respawn limit 20 5

script
cd /home/userfolder/releases/your-app-folder
exec ../node/bin/node run your-app
end script

```

## Using NGINX as a proxy

NGINX can help a NodeJs applications in a variety of ways.  One of the most important services it can provide FQDN-based routing for NodeJs HTTP servers - i.e. it can provide port 80 (HTTP) or 443 (HTTPS) connectivity and route/proxy to a different NodeJs application based on the domain name the IP is being accessed with.  This allows you to run server A on port 4001 with domain abc123x.com and server B on port 4002 with domain def456x.com, then configure NGINX to route port 80 to each of these servers respectfully based on the domain name the server being accessed with.

In addition, NGINX can offload NodeJs from serving static folders.

NGINX configuration files are located in `/etc/nginx/sites-available/<your-site>`. Once configured, to bring the site online you have to create a symlink in `/etc/nginx/sites-enabled/<your-site>`

Here is an example of a site configuration file. It forces all HTTP requests to be redirected to HTTPS and provides static access to some of the folders:

```

server {
        listen 80;
        server_name 	your-site.com www.your-site.com;
        return          301 https://your-site.com$request_uri;
}


server {
        listen 443 ssl;
        server_name www.your-site.com your-site.com;

        ssl_certificate "/home/user/releases/your-app/certificates/your-app.crt";
        ssl_certificate_key "/home/user/releases/your-app/certificates/your-app.key";

        # disallow request body size larger than 2mb (change this if your app supports file upload to maximum file size!)
        client_max_body_size 2m;

        # root folder where http content resides
        root /home/user/releases/your-app/http/;

        # static folders relative to the root folder        
        location /images/ { }
        location /scripts/ { }
        location /css/ { }

        location / {
                proxy_set_header X-Real-IP $remote_addr;
                # specify 127.0.0.1 ip and port of your application
                proxy_pass http://127.0.0.1:7676/;
        }

}

```


## Project Configuration

IRIS `.conf` configuration files are JSON objects (but for convenience read in as JavaScript files, thus allowing comments in the file syntax).  When using `getConfig()` function (used internally to retrieve main application config) IRIS looks for `.conf` files, loads it and then looks for `.local.conf` file.  If found, `.local.conf` file is overlapped on top of the loaded `.conf` file, effectively merging them: adding new sub-objects if missing in `.conf` and replacing entries that are re-defined in `.local.conf`.

This structure allows basic configuration files to be included in your repository, but security sensitive information or information specific to a deployment (dev, profuction etc.) to be created only in the local deployment.


CONFIGURATION OPTIONS - TBD


* `secureUnderUser : "<username>"` - 
* `certificates : "<folder>"` -  
* `mongodb : { main : "<url>"` - URL to the mongodb server, used for HTTP sessions as well as for generic MongoDb access.
* `statsd : "<fqdn or ip>"` - FQDN or IP of the StatsD server used by iris-stats (allows monitoring of host statistics such as RAM, disk space and network traffic)

```javascript
secureUnderUser : 'usern', 	// Lower process rights to this username 
							//	(secures the process to unix user rights when 
							//	starting up as root in order to open port 80 or 443)

certificates : "<path>",	//	Location of certificates folder containing `.crt` and `.key` 
							// files used by HTTPS server as well as iris-rpc

mongodb : {
	main : "<url>"			// url for main mongodb connection 
							// used for HTTP session storage (if available)
							// and default mongodb configuration
}

http : {
	redirectToSSL : false,	// force redirection to HTTPS from HTTP server
	port : 1234,			// HTTP/HTTPS server port
	ssl : false,			// Enable SSL on above given port or not
	engine : 'ejs',			// Use EJS content rendering engine (default)
							// Note: most iris modules are compatible only with EJS)
	session : {
		key: "your-app-name",
		secret: "your-random-string"
	},
	static : {				// list of static paths in order of access
		"/" : "http"		// URL path -> folder (relative to project root)
	}


}
```

## SSL Certificates

Just like with configuration files, SSL certificates can be installed (typically) in `certificates/` folder as either `.crt`, `.key` and `.ca` files or `.local.crt`, `.local.key` and `.local.ca` files.

If the system finds files with `.local` suffix, it will load these files instead of files that do not contain the suffix.  Just like with configuration files, this allows installation of certificates local in the deployment environment without keeping these files in git repository.

TBD



## Examples

TBD