-module(xo_auth_twitter).
-export([handle_twitter_req/1, create_or_update_user/2]).
-include_lib("couch/include/couch_db.hrl").

%% This module handles Twitter signin and _user document creation.
%% The handle_twitter_req should be configured to a URI that is passed to Twitter as the
%% oauth_callback parmeter on the initial request to https://api.twitter.com/oauth/request_token
%%

-define(COOKIE_NAME, "xo_tracker").
  
%% Exported functions
handle_twitter_req(#httpd{method='GET'}=Req) ->

    try 
        %% Did we get a 'code' or 'error' back from twitter?
        case couch_httpd:qs_value(Req, "oauth_token") of
            undefined ->
                case couch_httpd:qs_value(Req, "denied") of
                    undefined ->
                        %% If there's no token and no denied value then assume this is the inital request
                        request_twitter_request_token(Req);
                    _ ->
                        couch_httpd:send_json(Req, 403, [], {[{error, <<"User denied Needz access to Twitter account">>}]})
                end;

            RequestToken -> 
                %% If there's a token and verifier then Twitter has authenticated the user
                case couch_httpd:qs_value(Req, "oauth_verifier") of
                    undefined ->
                        ?LOG_DEBUG("No verifier found on Twitter callback: ~p", [Req]),
                        couch_httpd:send_json(Req, 403, [], {[{error, <<"No code supplied">>}]});
                    Verifier -> 
                        handle_twitter_callback(Req, RequestToken, Verifier)
                end
        end
    catch 
        throw:could_not_create_user_skeleton ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not create user skeleton">>}]});
        throw:account_already_associated_with_another_user ->
            couch_httpd:send_json(Req, 400, [], {[{error, <<"Twitter account registered with another user">>}]});
        throw:non_200_response_from_twitter ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not get access token from Twitter">>}]});
        throw:no_document_for_user ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"No user exists for auth session cookie">>}]});
        throw:document_not_found_for_user ->
            couch_httpd:send_json(Req, 500, [], {[{error, <<"Document not found for user">>}]})
    end;
handle_twitter_req(Req) ->
    couch_httpd:send_method_not_allowed(Req, "GET").


request_twitter_request_token(Req) ->
    %% Extract required values from config ini
    [CallbackUrl, ConsumerKey, ConsumerSecret] = 
        xo_auth:extract_config_values("twitter", ["redirect_uri", "consumer_key", "consumer_secret"]),
    
    Url = "https://api.twitter.com/oauth/request_token",
    SignedParams = oauth:signed_params("GET", Url, [{"oauth_callback", CallbackUrl}], {ConsumerKey, ConsumerSecret, hmac_sha1}, "", ""),     
    OAuthUrl = oauth:uri(Url, SignedParams),
    Resp = ibrowse:send_req(OAuthUrl, [], get, []),

    {ok, RedirectURL, Headers} = process_request_token_response(Req, Resp),
    couch_httpd:send_json(Req, 302, [{"Location", RedirectURL}] ++ Headers, {[]}).

process_request_token_response(Req, Response) ->
    %% Extract Request Token from body and generate authenticate URL
    case Response of 
        {ok, "200", _, Body} ->
            RequestParams = mochiweb_util:parse_qs(Body),
            RequestToken = oauth:token(RequestParams),
            RequestSecret = oauth:token_secret(RequestParams),
            
            AuthenticateUrl = "https://api.twitter.com/oauth/authenticate?oauth_token=" ++ RequestToken,
            ?LOG_DEBUG("obtain_twitter_request_token - redirecting to ~p", [AuthenticateUrl]),
            
            %% Redirect the client to the Twitter Oauth page
            %% We will need the token secret twitter just gave us when
            %% trying to get an access_token so we need to put it
            %% in a cookie.
            {ok, AuthenticateUrl, [token_cookie(Req, RequestSecret)]};
        
        _ ->
            ?LOG_ERROR("process_twitter_request_token: non 200 response of: ~p", [Response]),
            throw(non_200_response_from_twitter)
    end.
    

handle_twitter_callback(Req, RequestToken, Verifier) ->
    %% Extract required values from config ini
    [ConsumerKey, ConsumerSecret] = 
        xo_auth:extract_config_values("twitter", ["consumer_key", "consumer_secret"]),
    
    RequestTokenSecret = get_token_secret_from_cookie(Req),
    ?LOG_DEBUG("Requesting Access Token with Token: ~p  TokenSecret: ~p", [RequestToken, RequestTokenSecret]),
    ?LOG_DEBUG("Requesting Access Token with ConsumerKey: ~p  ConsumerSecret: ~p", [ConsumerKey, ConsumerSecret]),
    
    URL="https://api.twitter.com/oauth/access_token",
    SignedParams = oauth:signed_params("GET", URL, [{"oauth_verifier", Verifier}], {ConsumerKey, ConsumerSecret, hmac_sha1}, RequestToken, RequestTokenSecret),     
    OAuthUrl = oauth:uri(URL, SignedParams),
    Resp=ibrowse:send_req(OAuthUrl, [], get, []),

    AccessTokenResponse = process_twitter_access_token_response(Resp),
    create_or_update_user(Req, AccessTokenResponse).

create_or_update_user(Req, {ok, AccessToken, AccessTokenSecret, TwitterUsername, TwitterUserID}) ->
    Username = xo_auth:determine_username(Req, "twitter", TwitterUserID, TwitterUsername),
    ok = case couch_config:get("twitter", "store_access_token", "false") of
             "true" ->
                 xo_auth:update_service_details(Username, "twitter", TwitterUserID, AccessToken, AccessTokenSecret);
             _ ->
                 xo_auth:update_service_details(Username, "twitter", TwitterUserID)
         end,
    
    RedirectUri = couch_config:get("twitter", "client_app_uri", nil),
    xo_auth:generate_cookied_response_json(?l2b(Username), Req, RedirectUri).


get_token_secret_from_cookie(#httpd{mochi_req=MochiReq}=Req) ->
    case MochiReq:get_cookie_value(?COOKIE_NAME) of
        undefined -> Req;
            [] -> Req;
        Cookie ->
            Hash = try
                couch_util:decodeBase64Url(Cookie)
            catch
                _:_Error ->
                    Reason = <<"Malformed XO_Auth cookie. Please clear your cookies.">>,
                    throw({bad_request, Reason})
            end,
            decrypt(Hash)
    end.   
    
process_twitter_access_token_response(Response) ->
    %% The response should contain everything we need
    %% access_token, access_token_secret, user_id and screen name
    case Response of 
        {ok, "200", _, Body} ->
            RequestParams =  mochiweb_util:parse_qs(Body),
            AccessToken = oauth:token(RequestParams),
            AccessTokenSecret = oauth:token_secret(RequestParams),
            ScreenName = screen_name(RequestParams),
            UserID = user_id(RequestParams),
            {ok, AccessToken, AccessTokenSecret, ScreenName, UserID};
                
        _ ->
            ?LOG_ERROR("process_twitter_request_token: non 200 response of: ~p", [Response]),
            throw(non_200_response_from_twitter)
    end.
   
screen_name(Params) ->
    proplists:get_value("screen_name", Params).

user_id(Params) ->
      proplists:get_value("user_id", Params).
 

%% Cookie functions borrowed from couch_httpd_auth.erl as they aren't exported     
token_cookie(Req, Value) ->
    Hash = encrypt(Value),
    mochiweb_cookies:cookie(?COOKIE_NAME,
        couch_util:encodeBase64Url(?b2l(Hash)),
        [{path, "/"}] ++ cookie_scheme(Req) ++ max_age()).


cookie_scheme(#httpd{mochi_req=MochiReq}) ->
    [{http_only, true}] ++
    case MochiReq:get(scheme) of
        http -> [];
        https -> [{secure, true}]
    end.

max_age() ->
    case couch_config:get("couch_httpd_auth", "allow_persistent_cookies", "false") of
        "false" ->
            [];
        "true" ->
            Timeout = list_to_integer(
                couch_config:get("couch_httpd_auth", "timeout", "60")),
            [{max_age, Timeout}]
    end.

%% Functions to encode and decode cookie value

encrypt(Value) ->
    [Key, IV] =  xo_auth:extract_config_values("blowfish", ["key", "ivec"]),
    
    ?LOG_DEBUG("AES Key: ~p  IVec= ~p", [Key, IV]),
    
    BinaryKey = hexstr2bin(Key),
    BinaryIV = hexstr2bin(IV),
    crypto:blowfish_cfb64_encrypt(BinaryKey, BinaryIV, Value).

decrypt(Value) ->
    [Key, IV] =  xo_auth:extract_config_values("blowfish", ["key", "ivec"]),
    
    BinaryKey = hexstr2bin(Key),
    BinaryIV = hexstr2bin(IV),
    ?b2l(crypto:blowfish_cfb64_decrypt(BinaryKey, BinaryIV, Value)).
  
%% hexstr2bin from crypto test suites
hexstr2bin(S) ->
  list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
  [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
  [].

mkint(C) when $0 =< C, C =< $9 ->
  C - $0;
mkint(C) when $A =< C, C =< $F ->
  C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
  C - $a + 10.

  
