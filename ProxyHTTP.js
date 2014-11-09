var http = require('http');
var fs = require('fs');
var url = require('url');
var configuration = require('./configuration');
var ldap = require('./authenticator.ldap');

function isFunction(fun) { return typeof fun == "function";}

// Function that write the log inside the file related to right server

var log = function (context, err, code){
  var remoteIP=context.req.headers["x-forwarded-for"] || context.req.connection.remoteAddress;;
  var rule='??';
  var logFile="ProxyHTTP.log";
  if ('conf' in context) {
    var site = configuration.sites[context.conf];
    if ('logFile' in site) logFile = site.logFile;
    rule=context.conf+'/';
    if ('ruleNo' in context) {
      rule+=context.ruleNo;
    } else {
      rule+='##';
    }
  }
  rule='['+rule+']';
    if (err == "HTTP" && context.login)var data = "" + context.date + "\t" + remoteIP + "\t" + context.login + "\t" + context.req.method + "\t" + context.req.url + "\t" + code +"\t"+rule;

    else if (context.restricted) var data = "" + context.date + "\t" + remoteIP + "\t" + err;
    else if (err == "HTTP")var data = "" + context.date + "\t" + remoteIP + "\t" + context.req.method + "\t" + context.req.headers.host + context.req.url + "\t" + code +"\t"+rule;
  
  if (data){
    console.log(data);
    if (logFile) fs.appendFileSync(logFile, data+"\n");
    //else fs.appendFileSync("ProxyHTTP.log", data+"\n"); //change the name of the proxy log file inside the code
  };
};

function tryAgain(context) {
  context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
  context.res.statusCode = 401;
  context.res.end();
  log(context, 'HTTP', 401);
};

/*
 * Default implementation of checkCredentials (with fixed login and password)
 * that can be replaced for various authentication formats and protocols.
 */
var dummy = function(context, callback) {
    var site_auth = configuration.sites[context.conf].authData;
    callback(context.login==site_auth.login && context.pw==site_auth.pw);
}

function authenticate(checkCredentials, context, callback, shouldNotCatch) {
  context.restricted = true;
  if (context.req.headers.authorization) {
    checkCredentials(context, function(isAuthentified) {
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

function sendResponse(context,statusCode,message) {
  context.res.statusCode = statusCode;
  log(context, "HTTP", statusCode);
  context.res.end(message);
}

/**
 * Authorize access to specific resources.
 */
var AuthorizList =function (context, callback){

  context.restricted = true;

  var idDoc = context.req.url.split('/')[3];
  var allowed_users = configuration.sites[context.conf].restricted[idDoc];
  if (allowed_users && allowed_users.indexOf(context.login) == -1) {
    sendResponse(context, 403, 'Forbidden');
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

function couchDBHeaders(nodeHeaders) {
  var couchHeaders={};
  for (var i in nodeHeaders) {
    couchHeaders[uCaseHeader(i)]=nodeHeaders[i];
  }
  return couchHeaders;
}

// Main proxy function that forward the request and the related answers

var proxyWork = function(context, callback){
   if (!context.req.readable) {
     if (context.options.body && typeof context.options.body =='string') context.options.headers['content-length']=context.options.body.length;
     else delete context.options.headers['content-length'];
   }
   var proxyReq = http.request(context.options, function (res){
  var site = configuration.sites[context.conf];
  if (res.headers.location && site.rewritePath.enable){
      var splitHeaders = res.headers.location.split('/');
      res.headers.location = context.req.headers.origin;
      for (var i = (3 + sites.rewritePath.headersOffset); i < splitHeaders.length; i++) {
        res.headers.location = res.headers.location +'/'+ splitHeaders[i];
      }
    }

    var headers=res.headers;
    if ('rawHeaders' in res) { //this is true for node.js >=0.11.6
      headers=res.rawHeaders;
    } else if (site.couchDBCompat) {
      headers=couchDBHeaders(headers);
    }

    context.res.writeHead(res.statusCode, headers);
    log(context, "HTTP", res.statusCode);
    res.on('data',function(chunkOrigin) {
        context.res.write(chunkOrigin);
    });
    res.on('end', function(){
      context.res.end();
      isFunction(callback) && callback();
    });
  });

  proxyReq.on('error', function(err){
    console.log('problem with the server: ' + JSON.stringify(err));
    sendResponse(context,504,"Gateway Timeout");
  });

  if (context.req.readable) {

  context.req.on('data', function(chunkInit){
    proxyReq.write(chunkInit)
  });

  context.req.on('error', function(err) {
    log(context, err, 0);
    console.log('problem with request: ' + err.message);
  });

  context.req.on('end', function(){
    proxyReq.end();
  });
  } else {
    if (context.options.body) proxyReq.write(context.options.body);
    proxyReq.end();
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
  };
  if (verif == false ) i = -1;
  return i;
};

function parseHttpCredentials(context) {
  var authorization = context.req.headers.authorization;
  if (authorization) {
    var token = authorization.split(" ");
    if (token[0]=='Basic') {
      var credentials = new Buffer(token[1], 'base64').toString().split(':');
      context.login = credentials[0];
      context.pw = credentials[1];
    }
  }
}

http.createServer(function (request, response){
  var context = {
    req: request,
    res: response,
    date: new Date(),
    log: log,
    sendResponse: sendResponse,
    proxyWork: proxyWork,
    AuthorizList: AuthorizList,
    ldap: ldap,
    dummy: dummy,
    couchDBHeaders: couchDBHeaders
  };

  var domain=require("domain").create();
  domain.on("uncaughtException",function(err) {
    console.log("BIG UNCAUGHT EXCEPTION");
    console.log(err);
    console.log(err.stack);
    sendResponse(context,500,"Server Exception ");
  });
  domain.on("error",function(err) {
    console.log("BIG ERROR");
    console.log(err);
    console.log(err.stack);
    sendResponse(context,500,"Server Error ");
  });

  domain.add(request);
  domain.add(response);

  domain.run(function() {

  var index = matching(request.headers.host);
  if(index == -1){
    sendResponse(context,404,"Not Found");
  }else{
  	context.conf = index;
    var site = configuration.sites[index];
    var head = JSON.parse(JSON.stringify(request.headers)); 
    if (request.headers.authorization && site.hideAuth) delete head.authorization;
    if (!site.preserveHost) delete head.host;
    context.options = {
      host: site.host,
      port: site.port,
      path: site.path + url.parse(request.url).path,
      method: request.method,
      headers: head,
      agent: false
    };
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
	sendResponse(context,500,"Server Exception "+index+"/"+i);
	found=true;
      }
      i++;
    }
    if (!found) {
      proxyWork(context);
    }
  }
  });
}).listen(configuration.port);
console.log('Server running port ' + configuration.port);
