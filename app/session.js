var configuration = require('./configuration');
var authCookie=require('./authenticator.cookie');
var log = require('./accounter.log');

function parseBody(context,sessionHandler) {
  var post=require("querystring").parse(context.options.body);
  var userfield=sessionHandler.userfield || "username";
  var passfield=sessionHandler.passfield || "password";
  context.login=post[userfield] || "";
  context.pw=post[passfield] || "";
};

function handleSessionRequest(sessionHandler) {
  var $=this;
  var context=this.context;
  switch (this.method) {
    case "POST":
      this.readBody(this.context,function(body) {
        parseBody($.context,sessionHandler);
        authCookie.ignore($.context,sessionHandler);
	$.authenticate($.context,function(authenticator) {
	  if (authenticator) {
	    authCookie.set($.context,sessionHandler);
	    if (sessionHandler.forward) {
	      delete context.options.body;
	      $.context.options.method="GET";
	      $.proxyWork($.context);
	    } else {
	      $.sendResponse($.context, 200, 'Authentified');
	    }
	  } else {
	    delete $.context.login;
	    authCookie.set($.context,sessionHandler);
	    if(sessionHandler.forward) {
	      $.proxyWork($.context);
	    } else {
	      $.sendResponse($.context, 401, 'Unauthorized');
	    }
	  }
	},true);
      });
      break;
    case "DELETE":
      $.context.login=null;
      authCookie.set($.context,sessionHandler);
      if (sessionHandler.forward) {
        $.proxyWork($.context);
      } else {
        $.sendResponse($.context, 200, 'Logged out');
      }
      break;
    case "GET":
      $.authenticate($.context,function(authenticator) {
        if(authenticator) {
	}
        var session={
	  name:$.context.login || null,
	  authenticator:authenticator
	}
	if (sessionHandler.forward) {
	  $.proxyWork($.context);
	} else {
	  $.sendResponse($.context, 200, JSON.stringify(session));
	}
      },true);
      break;
    default:
      if (sessionHandler.forward) {
        $.authenticate($.context,function() {
	  proxyWork($.context);
	},true);
      } else {
        $.sendResponse($.context, 405, 'Method not allowed');
      }
  }
}

function addSessionRule(site) {
  if (site.sessionHandler) {
    if (!site.sessionHandler.hasOwnProperty("forward")) {
      site.sessionHandler.forward=site.preserveCredentials;
    }
    var rule={};
    rule.control=function() {
      var active=true;
      if (!site.sessionHandler.path) {
        console.log("session handler with no Path defined");
        return false;
      } else if (!/^\//.test(site.sessionHandler.path)) {
	site.sessionHandler.path = "/" +site.sessionHandler.path;
      }
      return new RegExp("^"+site.sessionHandler.path).test(this.path);
    };
    rule.action=function() {
      handleSessionRequest.call(this,site.sessionHandler);
    };
    site.rules.unshift(rule);

    var authenticator={
      cookieName:site.sessionHandler.cookieName||null,
    };
    site.authentication=site.authentication || [];
    site.authentication.unshift(authenticator);
  }
}

module.exports={
  manage:addSessionRule
}
