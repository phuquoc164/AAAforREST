AAAforREST
==========

An HTTP reverse proxy to bring authentication, authorization and accounting to RESTful applications (see "[features](https://github.com/Hypertopic/AAAforREST/issues?q=)").

License: [BSD revised](http://opensource.org/licenses/BSD-3-Clause)

Contact: aurelien.benel@utt.fr

Home page: https://github.com/Hypertopic/AAAforREST

Installation requirements
-------------------------

* Git client
* [Node.js](http://nodejs.org/)

Installation procedure
----------------------

    sudo npm install forever -g

* In any folder:

        git clone https://github.com/Hypertopic/AAAforREST.git
        cd AAAforREST
        npm install
        cp config.sample.js config.js

* Change settings in `config.js`.
* Test the settings (`sudo` is required for port 80):

        sudo node proxy.js

* Exit the program (`CTRL`+`C`) and start it as a service:

        sudo forever start proxy.js

* The service can be stopped with:

        sudo forever stop proxy.js
