var crypto=require('crypto');
var Cookies=require('cookies');

var saved_cookies={};
const default_cookie_auth_name='AAAforRest-auth';
var defaultExpiryTime=600000;

function checkAuthCookie(context,authenticator,callback) {
  var currcookie;
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  var expiryTime=authenticator.sessionLength || defaultExpiryTime;
  var cookies=new Cookies(context.requestIn,context.responseOut);
  if (currcookie=cookies.get(authenticator.cookieName)) {
    var auth_info;
    if (auth_info=saved_cookies[currcookie]) {
      if (auth_info.timestamp<new Date().getTime()+expiryTime && auth_info.login) {
        auth_info.timestamp=new Date();
        context.login=auth_info.login;
        callback(true);
      } else {
        console.log("expired");
        delete saved_cookies[currcookie];
      }
    } else {
      console.log("cookie does not exist");
    }
  }
  callback(false);
}

function setAuthCookie(context,authenticator) {
  var currcookie;
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  var expiryTime=authenticator.sessionLength || defaultExpiryTime;
  var cookies=new Cookies(context.requestIn,context.responseOut);
  if (currcookie=cookies.get(authenticator.cookieName)) {
    if (auth_info=saved_cookies[currcookie]) {
      if (context.login && auth_info.login!=context.login) {
	console.log("switching authentication from "+auth_info.login
	    +" to "+context.login);
      }
    } else {
      auth_info={};
    }
    auth_info.timestamp=new Date().getTime();
  } else {
    var ok=false;
    while (!ok) {
      currcookie=crypto.createHash('sha1').update(authenticator.cookieName).update("plipplop"+new Date().getTime()).digest('hex');
      console.log(currcookie);
      if (!saved_cookies[currcookie]) ok=true;
    }
    console.log("new session "+currcookie);
    auth_info={timestamp:new Date().getTime()}
  }
  if (context.login) {
    console.log("authenticating "+context.login);
    auth_info.login=context.login;
    saved_cookies[currcookie]=auth_info;
  } else {
    delete saved_cookies[currcookie];
    currcookie=null;
  }
  console.log("setting cookie "+currcookie);
  cookies.set(authenticator.cookieName,currcookie,{overwrite:true});
}  

module.exports={
  check: checkAuthCookie,
  set: setAuthCookie
}

