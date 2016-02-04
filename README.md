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
* [iris-polymer](https://github.com/aspectron/iris-polymer) - Google Polymer components & content optimizers
* [iris-rpc](https://github.com/aspectron/iris-rpc) - Cross-process encrypted RPC communication (JSON over TLS)
* [iris-ha](https://github.com/aspectron/iris-ha) - High Availability functionality (UDP-broadcast driven master selection)
* [iris-stats](https://github.com/aspectron/iris-stats) - Tracking of basic server statistics (RAM, Bandwidth, DiskSpace) with Graphite Interface
* [iris-underscore](https://github.com/aspectron/iris-underscore) - Asynchronous extensions for the UnderscoreJS library
* [iris-twitter](https://github.com/aspectron/iris-twitter) - Helper library for fetching user tweets


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

#### Windows:
* Visual Studio Community (or any other edition) with C++ Compiler


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