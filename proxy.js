var http = require('http');
var url = require('url');
var async = require('async');
var configuration = require('./configuration');
var ldap = require('./authenticator.ldap');
var log = require('./accounter.log');

function isFunction(fun) { return typeof fun == "function";}

function tryAgain(context) {
  context.responseOut.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
  sendResponse(context, 401, 'Unauthorized');
}

/*
 * Default implementation of checkCredentials (with fixed login and password)
 * that can be replaced for various authentication formats and protocols.
 */
var dummy = function(context, settings, callback) {
  callback(context.login==settings.login && context.pw==settings.password);
}

function authenticate(context, callback, shouldNotCatch) {
  if (context.requestIn.headers.authorization) {
    var authenticators = configuration.sites[context.conf].authentication;
    async.detectSeries(authenticators, function(authenticator, callback) {
      if (authenticator.dn) {
        ldap(context, authenticator, callback);
      } else {
        dummy(context, authenticator, callback);
      }
    }, function(isAuthentified) {
      if (isAuthentified || shouldNotCatch) {
        callback(context);
      } else {
        tryAgain(context);
      }
    });
  } else {
    tryAgain(context);
  }
}

function sendResponse(context, statusCode, message) {
  context.responseOut.statusCode = statusCode;
  log(context, 'HTTP', statusCode);
  context.responseOut.end(message);
}

/**
 * Authorize access to specific resources.
 */
var AuthorizList =function (context, callback){
  var idDoc = context.requestIn.url.split('/')[3];
  var allowed_users = configuration.sites[context.conf].restricted[idDoc];
  if (allowed_users && allowed_users.indexOf(context.login) == -1) {
    tryAgain(context);
  } else {
    callback();
  }
}

function uCaseWord(word) {
  switch(word) {
    case 'etag':return 'ETag';
    default: return word.replace(/^./,function(l){return l.toUpperCase();});
  }
}

function uCaseHeader(headerName) {
  return headerName.replace(/\w*/g,uCaseWord);
}

//TODO replace with `.rawHeaders` when Node.js stable version is 0.11
function preserveHeadersCase(nodeHeaders) {
  var couchHeaders={};
  for (var i in nodeHeaders) {
    couchHeaders[uCaseHeader(i)]=nodeHeaders[i];
  }
  return couchHeaders;
}

// Main proxy function that forward the request and the related answers

var proxyWork = function(context) {
   if (!context.requestIn.readable) {
     if (context.options.body && typeof context.options.body =='string') context.options.headers['content-length']=context.options.body.length;
     else delete context.options.headers['content-length'];
   }
  var requestOut = http.request(context.options, function(responseIn) {
  var site = configuration.sites[context.conf];
  if (responseIn.headers.location && site.rewritePath.enable) {
      var splitHeaders = responseIn.headers.location.split('/');
      responseIn.headers.location = context.requestIn.headers.origin;
      for (var i = (3 + site.rewritePath.headersOffset); i < splitHeaders.length; i++) {
        responseIn.headers.location += '/' + splitHeaders[i];
      }
    }
    context.responseOut.writeHead(
      responseIn.statusCode,
      preserveHeadersCase(responseIn.headers)
    );
    log(context, 'HTTP', responseIn.statusCode);
    responseIn.on('data', function(chunkOrigin) {
      context.responseOut.write(chunkOrigin);
    });
    responseIn.on('end', function() {
      context.responseOut.end();
    });
  });

  requestOut.on('error', function(err){
    console.log('problem with the server: ' + JSON.stringify(err));
    sendResponse(context, 504, "Gateway Timeout");
  });

  if (context.requestIn.readable) {

  context.requestIn.on('data', function(chunkInit) {
    requestOut.write(chunkInit)
  });

  context.requestIn.on('error', function(err) {
    log(context, err, 0);
    console.log('problem with request: ' + err.message);
  });

  context.requestIn.on('end', function(){
    requestOut.end();
  });
  } else {
    if (context.options.body) requestOut.write(context.options.body);
    requestOut.end();
  }
}

// Function that allow to find the index of the requested server inside config.json

var matching = function(host){ 
  var verif = false;
  var i =0;
  while ((verif == false) && (i < configuration.sites.length)){
    var site_host = configuration.sites[i].hostProxy;
    var re = new RegExp(site_host, "i");
    verif = re.test(host);
    if (!verif) {
      re = new RegExp(site_host + ":" + configuration.port, "i");
      verif = re.test(host);
    }
    if (verif == false)i++;
  }
  if (verif == false ) i = -1;
  return i;
};

function parseHttpCredentials(context) {
  var authorization = context.requestIn.headers.authorization;
  if (authorization) {
    var token = authorization.split(" ");
    if (token[0]=='Basic') {
      var credentials = new Buffer(token[1], 'base64').toString().split(':');
      context.login = credentials[0];
      context.pw = credentials[1];
    }
  }
}

http.createServer(function(requestIn, responseOut) {
  var context = {
    requestIn: requestIn,
    responseOut: responseOut,
    date: new Date(),
    log: log,
    sendResponse: sendResponse,
    proxyWork: proxyWork,
    AuthorizList: AuthorizList,
    ldap: ldap,
    dummy: dummy
  };

  var domain=require("domain").create();
  domain.on("uncaughtException",function(err) {
    console.log("BIG UNCAUGHT EXCEPTION");
    console.log(err);
    console.log(err.stack);
    sendResponse(context, 500, "Server Exception");
  });
  domain.on("error",function(err) {
    console.log("BIG ERROR");
    console.log(err);
    console.log(err.stack);
    sendResponse(context, 500, "Server Error");
  });

  domain.add(requestIn);
  domain.add(responseOut);

  domain.run(function() {

  var index = matching(requestIn.headers.host);
  if(index == -1){
    sendResponse(context, 404, "Not Found");
  }else{
  	context.conf = index;
    var site = configuration.sites[index];
    context.options = {
      host: site.host,
      port: site.port || 80,
      path: (site.path || '') + url.parse(requestIn.url).path,
      method: requestIn.method,
      headers: preserveHeadersCase(requestIn.headers),
      agent: false
    };
    if (!site.preserveCredentials) delete context.options.headers.Authorization;
    parseHttpCredentials(context);
    var i=0;
    var found=false;
    while(i<site.rules.length && !found){
      try {
        var rule = site.rules[i];
        var control = rule.control;
        var action = rule.action;
	var test=false;
	if(isFunction(control)) test=control(context);
	else if (typeof control == "string") test=eval(control);
	if (test) {
	  context.ruleNo=i;
	  if (isFunction(action)){
	    action(context);
	  } else {
	    eval(action);
	  }
	  if (rule.final) {
	    found = true;
	  }
	}
      } catch(e) {
        console.log(e.stack);
        sendResponse(context, 500, "Server Exception " + index + "/" + i);
        found = true;
      }
      i++;
    }
    proxyWork(context); //Fallback rule
  }
  });
}).listen(configuration.port);
console.log('Server running port ' + configuration.port);
