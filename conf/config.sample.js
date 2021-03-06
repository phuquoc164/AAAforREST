/**
 * Configuration file to be copied as `config.js` and edited to fit your needs.
 * Note: This can be replaced with a JSON file of the same structure
 * (`config.json`) especially when the settings are generated by a program.
 */
module.exports = {

  /**
   * Port number of the reverse proxy.
   */
  //port: 80,

  /**
   * CouchDB service hosting _users database.
   */
  //users: 'localhost:5984',

  sites: [{

    /**
     * Exact name or regular expression that matches
     * the host name of the virtual server.
     * If multiple sites match, the first site on the list wins.
     */
    hostProxy: "shop.acme.com",

    /**
     * Hostname of the upstream server.
     */
    //host: "localhost",

    /**
     * Port number of the upstream server.
     */
    //port: 80,

    /**
     * Base path of the upstream server.
     */
    //path: '',

    /**
     * Should HTTP credentials be handled by the upstream server?
     */
    //preserveCredentials: false,

    /**
     * Number of URI segments to remove from the Location header.
     */
    //hideLocationParts: 0,

    /**
     * Handle session with cookies,
     * create with POST /_session -d'userfield=username&passfield=password'
     * get with GET /_session
     * destroy with DELETE /_session
     */
    /*sessionHandler: {
      cookieName:"AAAforRest-auth",
      sessionLength:600000, //10 minutes inactivity
      userfield:"username",
      passfield:"password",
      path:"/_session",
      preserveCredentials:false, //if authentication fails, transmit to upstream ?
        //defaults to site.preserveCredentials
      forward:false //forward the request to the upstream server for display ?
        //defaults to sessionHandler.preserveCredentials
    },*/

    authentication: [

      /**
       * LDAP binding settings.
       */
      {url: "ldap://ldap.acme.org", id: "cn", dn: "dc=acme,dc=org"},
      {url: "ldap://ldap.acme.com", id: "uid", dn: "ou=People,dc=acme,dc=com"},

      /**
       * HTTP service with basic authentication.
       */
      {url: "http://auth.acme.com:5984/"},

      /**
       * Fixed credentials.
       */
      {login: "roadrunner", password: "bipbip"}
    ],

    /**
     * Header in which the authenticated user login will be forwarded to the
     * upstream server.
     */
     //forwardedLoginHeader: null,

    /**
     * Use of protected CouchDB proxy auth X-Auth-CouchDB-*
     * The secret must be configured on the server
     * http://127.0.0.1:5984/_config/couch_httpd_auth/secret
     * and 127.0.0.1:5984/_config/couch_httpd_auth/proxy_use_secret to true
     * forwardedLoginRoles is optional
     */
     //forwardedLoginSecret: 'saltcommon',
     //forwardedLoginRoles: 'comma,separated,list,or,roles'

     restricted: {

      /**
       * Restricted resources patterns and authorized users.
       */
      "rocket": ["will.coyote"],
      "magnet": ["will.coyote"],
      "false hole": ["will.coyote"],
      "rifle": ["elmer.fudd"],
      "ammo": ["elmer.fudd"]
    },

    /**
     * Rules defining the `action` to be taken
     * when `control` is true.
     * Note: A fallback rule is always on. It is defined as:
     * `control: "true"` and `action: "proxyWork(context)"`.
     */
    rules: [{
      control: function() {
        return this.method != 'GET';
      },
      action: function() {
        var $ = this;
        $.authenticate($.context, function() {
          $.authorize($.context, function() {
            $.proxyWork($.context);
          });
        });
      }
    }]
  }]
};
