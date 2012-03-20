External OAuth Authentication for CouchDB
=========================================

This is a rewrite of the couchdb-facebook authentication module in a more generic manner allowing other systems (e.g. Twitter) to be easily added. In addition the code is designed to utilise the _\_users_ database in a similar manner to the CouchDB 1.2 OAuth code allowing a single user to be authenticated in a number of different ways. Because of this change, this code is NOT COMPATIBLE with the couchdb-facebook code.

This version has been tested against CouchDB 1.2.x

This initial implementation adds a Facebook authentication module that uses the
[Facebook authentication API](http://developers.Facebook.com/docs/authentication/ ) to log people in.

It consists of a CouchDB httpd\_global\_handler that responds to http GET requests and
processes the Facebook login sequence. Once logged in, the handler requests an access
code and retrieves the Facebook profile information via https://graph.Facebook.com/me. The user's Facebook ID can
then be used to retrieve the CouchDB users document from the authentication_db to create the CouchDB session. The access code is stored
in the user record. If there isn't a matching user record then one is created using the Facebook ID as the username

An error during Facebook login will return HTTP 403 to the original caller. 

Example Flow of Control
---------------------------
 
For our example we assume the app is hosted at my_site.com

1. The browser requests the link:
   https://www.facebook.com/dialog/oauth?client_id=249348058430770&scope=user_about_me&redirect_uri=http:%2F%2Fmy_site.com:5984%2F_fb
2. The user logs into Facebook (if not already logged in) and approves the app (if
not already approved). NOTE: If the user was already logged in and has already approved the app then
they will be redirected back to your app without needing to type anything.
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


Build
--------------------

There is an unsophisticated Makefile with targets _compile_ and _install_. 

In order to compile and install this module you might have to edit the Makefile and change one or more of _COUCH\_ROOT_, _\_COUCHDB\_ERLANG\_LIB_, _COUCHDB\_LOCALD_ and _COUCHDB\_INIT\_SCRIPT_ values to point to the appropriate directories and file within your couchdb installation.


Installation
-------------------

You need to:

* Copy the beam files to somewhere where couch can find it. That location could be something like couchdb/erlang/lib/couch-1.2/ebin/ depending on where/how you've installed couch.

* Create a [Facebook app](See http://developer.Facebook.com)

Configuration
--------------------
You'll need to add an ini file or ini entries in couch config to use this module.

          [httpd_global_handlers]
          _fb = {fb_auth, handle_fb_req}
 
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
        
**client_id**  
  The App ID of your Facebook app

**store_access_token**
  This defaults to false. Setting it to true means that the user's Access Token will be saved in
  the \_user database allowing server components to access the user's external account
  
**redirect_uri**  
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

Notes
---------------

The users ID on the external system and the access token are stored in the user document in the authenticatio database as follows:

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

