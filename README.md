External OAuth Authentication for CouchDB
=========================================

This is a rewrite of the couchdb-facebook authentication module in a more generic manner allowing other systems (e.g. Twitter) to be easily added. In addition the code is designed to utilise the _\_users_ database in a similar manner to the CouchDB 1.2 OAuth code allowing a single user to be authenticated in a number of different ways. Because of this change, this code is NOT COMPATIBLE with the couchdb-facebook code.

This version has been tested against CouchDB 1.3.0. This version will not work with earlier versions

This version supports authenticating users using:
 
- [Facebook API](http://developers.Facebook.com/docs/authentication/ ) 

- [Twitter API](https://dev.twitter.com/docs/auth/using-oauth/ ) 

It consists of a CouchDB httpd\_global\_handlers that responds to http GET requests and processes the appropriate login sequence. Once authenticated by the external system the handler requests an access code and retrieves profile information which is used to retrieve the CouchDB users document from the authentication_db. If there isn't a matching user record then one is created using the ID provided by the external system

An error during login will return HTTP 403 to the original caller. 

Example Facebook Authentication Flow of Control
---------------------------
 
For our example we assume the app is hosted at my_site.com

1. The browser requests the link:
   https://www.facebook.com/dialog/oauth?client_id=249348058430770&scope=user_about_me&redirect_uri=http:%2F%2Fmy_site.com:5984%2F_fb
2. The user logs into Facebook (if not already logged in) and approves the app (if
not already approved). NOTE: If the user was already logged in and has already approved the app then
they will be redirected back without needing to type anything.
4. The browser arrives back at the _\_fb with a code that allows this module
to contact Facebook via the API and request an Access Code. No user interaction
required.
5. Once the Access Code is granted it allows the module to retrieve the users ID and other details from 
Facebook. A couchDB username is created and the ID along with the access token is stored. Storing
the access token allows server components to access Facebook on the user's behalf.
6. When the couch session expires (the app will have to catch this) you simply
need to send the user to the URL in (1) again and, because they've already gone thru this
route, it should get you all the way back to _\_fb without any user
interaction needed.
7. The final act is to redirect the user to into the app, a location that is
a combination of _client\_app\_uri_ config directive and the _clientapptoken_
param to _\_fb_.


Example Twitter Authentication Flow of Control
---------------------------
 
For our example we assume the app is hosted at my_site.com

1. The browser requests the link:
   https://my_site.com:5984%2F_twitter
2. The user logs into Twitter (if not already logged in) and approves the app (if
not already approved). NOTE: If the user was already logged in and has already approved the app then
they will be redirected back without needing to type anything.
4. The browser arrives back at _\_twitter with a code that allows the module
to contact Twitter and request an Access Code. 
5. When the Access Code is returned the user's Twitter screen name and ID are also returned. A couchDB username is created 
and the ID along with the access token & secret are optionally stored. Storing
the access token and secret allows server components to access Twitter on the user's behalf.
6. The final act is to redirect the user to the url configured by the  _client\_app\_uri_ config entry


Build
--------------------

This project uses Rebar (https://github.com/basho/rebar) as a build tool. Please refer to https://github.com/basho/rebar/wiki for more information. There is also a Makefile that is 
based on rebar. To build the application, type:

$ make

Installation
-------------------

You need to:

* Copy or symlink the application to your couchdb erlang installation, e.g. couchdb/erlang/lib/ depending on where/how you've installed couch. CouchDB will pick up all the applications in the lib directory.

* Optionally create a [Facebook app](See http://developer.facebook.com)

* Optionally create a [Twitter app](See http://dev.twitter.com)


Facebook Configuration
--------------------
To add Facebook authentication the following entries are required in the xo_auth.ini file

          [httpd_global_handlers]
          _fb = {xo_auth_fb, handle_fb_req}
 
          [fb]
          client_id=1234567890
          store_access_token=true
          redirect_uri=http://my_awesome_app.com/_fb
          client_secret=1234567890ABCDEF123456789
          client_app_uri=http://my_awesome_app.com/home?


**\_fb**  
  This is the couch location for the code that redirects the user to Facebook.
  Pass in a param called _clientapptoken_ if you want something added to the
  client app redirect at the end of the auth process (for when control is
  returned to your app).

  NOTE: Facebook requires that your site is public. The 'Site URL' setting of
        the Facebook app needs to be set to your site.
        
**client\_id**  
  The App ID of your Facebook app

**store\_access\_token**
  This defaults to false. Setting it to true means that the user's Access Token will be saved in
  the \_user database allowing server components to access the user's external account
  
**redirect\_uri**  
  This is the location that Facebook will be told to return the user to when
  Facebook login is complete. This MUST start with the same location that you set
  for Site URL in the Facebook app

**client\_secret**  
  DO NOT PUBLISH THIS! It is the _App Secret_ from your Facebook app.
  It is used behind the scenes to contact Facebook. If anyone gets hold
  of this they can pretend to be your app. Beware!

**client\_app\_uri**  
  Once the Facebook and CouchDB login have completed this is the URL that the initial call
  will be redirected to. Any value passed to the initial _\_fb__ call param _clientapptoken_ will be
  appended to this URL.

Twitter Configuration
--------------------

To add Twitter authentication the following entries are required in the xo_auth.ini file

          [httpd_global_handlers]
          _twitter = {xo_auth_twitter, handle_twitter_req}
 
          [twitter]
          client_id=1234567890
          store_access_token=true
          redirect_uri=http://my_awesome_app.com/_twitter
          client_secret=1234567890ABCDEF123456789
          client_app_uri=http://my_awesome_app.com/home?

          [blowfish]
          key=D67051C4C560B93818091AC4C461375B
          ivec=BC7FB2B980470D69


**\_twitter**  
  This is the CouchDB location for the code that handles Twitter Authentication.
        
**client\_id**  
  The _Consumer Key_ of your Twitter app

**client\_secret**  
  DO NOT PUBLISH THIS! It is the _Consumer Secret_ from your Twitter app.
  It is used behind the scenes to contact Twitter. If anyone gets hold
  of this they can pretend to be your app. Beware!

**store\_access\_token**
  This defaults to false. Setting it to true means that the user's Access Token & Secret will be saved in
  the \_user database allowing server components to access the user's external account
  
**redirect_uri**  
  This is the same as the _Callback URL_ configured for the Twitter App 

**client\_app\_uri**  
  Once the Twitter and CouchDB login have completed this is the URL that the initial call
  will be redirected to. 


**blowfish** The Twitter Authentication module uses Blowfish to encrypt a temporary cookie. Blowfish was chosen over AES
because the Erlang crypto module in Ubuntu 10.04 doesn't support AES. _key_ is an arbitaty value upto 56 bytes in length, but must also be a multiple of 8 bytes, _ivec_ is an arbitary 64 bit value (8 bytes)

Notes
---------------

The users ID on the external system and the access token are stored in the user document in the authentication database as follows:

    {
       "_id": "org.couchdb.user:michaelcollins14795",
       "_rev": "1-2eb00e9f166c13d63a6479144a3f565e",
       "salt": "421209aaee82b479d5799ca2a51d2ff4",
       "facebook": {
           "id": "555366654",
           "access_token": "AAABriRugmO4BAONugCLvNsaV3JN5OwZB5Aw85S5OEHLlYkC8taqFtVM0ZABSvrFZA0u3h1Jd0sGq3ybITF3wXkfMffppsEZD"
       },
       "name": "michaelcollins14795",
       "roles": [
       ],
       "type": "user"
    }

Adding a section to an existing user document that contains the *facebook* section with the ID and a blank access_token would allow that user to be authenticated via Facebook.


License
---------------

  CouchDB:XO\_Auth is licensed under: Apache License Version 2.0, January 2004 http://www.apache.org/licenses/

  Copyright (c) 2012 Ocasta Labs Ltd.

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

