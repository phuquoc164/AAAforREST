var crypto=require('crypto');
var Cookies=require('cookies');

var saved_cookies={};
const default_cookie_auth_name='AAAforRest-auth';
var defaultExpiryTime=600000;

function ignoreCookie(context,authenticator) {
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  context.cookie=context.cookie||{};
  context.cookie.ignore=context.cookie.ignore || [];
  context.cookie.ignore.push(authenticator.cookieName);
}

function checkAuthCookie(context,authenticator,callback) {
  var currcookie;
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  if (context.login || context.cookie && context.cookie.ignore
    && context.cookie.ignore.indexOf(authenticator.cookieName) !=-1) {
    return callback(false);
  }
  var expiryTime=authenticator.sessionLength || defaultExpiryTime;
  var cookies=new Cookies(context.requestIn,context.responseOut);
  if (currcookie=cookies.get(authenticator.cookieName)) {
    var auth_info;
    if (auth_info=saved_cookies[currcookie]) {
      if (auth_info.timestamp<new Date().getTime()+expiryTime && auth_info.login) {
        auth_info.timestamp=new Date();
        context.login=auth_info.login;
        console.log("authenticating "+context.login+" through cookie "+currcookie);
        return callback(true);
      } else {
        console.log("expired");
        delete saved_cookies[currcookie];
      }
    } else {
      console.log("cookie does not exist");
      cookies.set(authenticator.cookieName,null,{overwrite:true});
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
  } else if (context.login) {
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
    if (currcookie) {
      delete saved_cookies[currcookie];
      currcookie=null;
    } else {
      return;
    }
  }
  console.log("setting cookie "+currcookie);
  cookies.set(authenticator.cookieName,currcookie,{overwrite:true});
}

module.exports={
  check: checkAuthCookie,
  set: setAuthCookie,
  ignore: ignoreCookie
}

