-module(twitter_auth).

-export([handle_twitter_req/1]).

-include("couch_db.hrl").

%% This module handles Twitter signin and _user document creation.
%% The handle_twitter_req should be configured to a URI that is passed to Twitter as the
%% oauth_callback parmeter on the initial request to https://api.twitter.com/oauth/request_token
%%

-define(COOKIE_NAME, "xo_tracker").
  
%% Exported functions
handle_twitter_req(#httpd{method='GET'}=Req) ->
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
                Verifier -> handle_twitter_callback(Req, RequestToken, Verifier)
            end
    end;

handle_twitter_req(Req) ->
    couch_httpd:send_method_not_allowed(Req, "GET").


request_twitter_request_token(Req) ->
    %% Extract required values from config ini
    [CallbackUrl, ConsumerKey, ConsumerSecret] = lists:map(fun(K) ->
                                      case couch_config:get("twitter", K, undefined) of
                                          undefined -> throw({missing_config_value, "Cannot find key '"++K++"' in [twitter] section of config"});
                                          V -> V
                                      end
                                  end, ["redirect_uri", "consumer_key", "consumer_secret"]),
    
    Url="https://api.twitter.com/oauth/request_token",
    SignedParams = oauth:signed_params("GET", Url, [{"oauth_callback", CallbackUrl}], {ConsumerKey, ConsumerSecret, hmac_sha1}, "", ""),     
    OAuthUrl = oauth:uri(Url, SignedParams),
    Resp=ibrowse:send_req(OAuthUrl, [], get, []),

    case process_request_token_response(Req, Resp) of   
        {ok, RedirectURL, Headers} ->
            couch_httpd:send_json(Req, 302, [{"Location", RedirectURL}] ++ Headers, {[]});
                
        Error ->
            ?LOG_DEBUG("Non-success from request_twitter_request_token call: ~p", [Error]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not get access token">>}]})

    end.

process_request_token_response(Req, Response) ->
    %% Extract Request Token from body and generate authenticate URL
    case Response of 
        {ok, "200", _, Body} ->
            RequestParams = uri_params_decode(Body),
            RequestToken = oauth:token(RequestParams),
            RequestSecret = oauth:token_secret(RequestParams),
                
            AuthenticateUrl = "https://api.twitter.com/oauth/authenticate?oauth_token="++RequestToken,
            ?LOG_DEBUG("obtain_twitter_request_token - redirecting to ~p", [AuthenticateUrl]),

            %% Redirect the client to the Twitter Oauth page
            %% We will need the token secret twitter just gave us when
            %% trying to get an access_token so we need to put it
            %% in a cookie.
            {ok, AuthenticateUrl, [token_cookie(Req, RequestSecret)]};
                
    _ ->
        ?LOG_DEBUG("process_twitter_request_token: non 200 response of: ~p", [Response]),
        {error, "Non 200 response from Twitter"}
    end.
    

handle_twitter_callback(Req, RequestToken, Verifier) ->
    %% Extract required values from config ini
    [ConsumerKey, ConsumerSecret] = lists:map(fun(K) ->
                                      case couch_config:get("twitter", K, undefined) of
                                          undefined -> throw({missing_config_value, "Cannot find key '"++K++"' in [twitter] section of config"});
                                          V -> V
                                      end
                                  end, ["consumer_key", "consumer_secret"]),
    
    RequestTokenSecret = get_token_secret_from_cookie(Req),
    ?LOG_DEBUG("Requesting Access Token with Token: ~p  TokenSecret: ~p", [RequestToken, RequestTokenSecret]),
    
    URL="https://api.twitter.com/oauth/access_token",
    SignedParams = oauth:signed_params("GET", URL, [{"oauth_verifier", Verifier}], {ConsumerKey, ConsumerSecret, hmac_sha1}, RequestToken, RequestTokenSecret),     
    OAuthUrl = oauth:uri(URL, SignedParams),
    Resp=ibrowse:send_req(OAuthUrl, [], get, []),

    case process_twitter_access_token_response(Resp) of   
        {ok, AccessToken, AccessTokenSecret, ScreenName, UserID} ->
            RedirectUri = couch_config:get("twitter", "client_app_uri", nil),
            
            case xo_auth:check_user_database(<<"twitter">>, ?l2b(UserID)) of
                nil ->
                    ?LOG_DEBUG("Nothing found for Twitter ID: ~p", [UserID]),
                    case c1ouch_config:get("twitter", "store_access_token", "false") of
                        "false" ->
                            xo_auth:create_user_doc_response(
                              Req, UserID, "Twitter", RedirectUri, 
                              xo_auth:create_user_doc(ScreenName, <<"twitter">>, ?l2b(UserID)));
                        _ ->    
                            xo_auth:create_user_doc_response(
                              Req, UserID, "Twitter", RedirectUri,
                              xo_auth:create_user_doc(ScreenName, <<"twitter">>, ?l2b(UserID), AccessToken, AccessTokenSecret))
                    end;
                    
                {Result} ->
                    ?LOG_DEBUG("View result is ~p", [Result]),
                    DocID = couch_util:get_value(<<"user_id">>, Result, []),
                    Name = couch_util:get_value(<<"name">>, Result, []),
                    
                    case couch_config:get("twitter", "store_access_token", "false") of
                        "false" ->
                            xo_auth:generate_cookied_response_json(Name, Req, RedirectUri);
                        _ ->
                            OldAccessToken = couch_util:get_value(<<"access_token">>, Result, []),
                            xo_auth:update_access_token(DocID, <<"facebook">>, OldAccessToken, ?l2b(AccessToken), ?l2b(AccessTokenSecret)),
                            xo_auth:generate_cookied_response_json(Name, Req, RedirectUri)
                    end;
                    
                {error, Reason} ->
                    couch_httpd:send_json(Req, 403, [], {[{<<"xo_auth">>, Reason}]})
            end;
                
        Error ->
            ?LOG_DEBUG("Non-success from request_twitter_access_token call: ~p", [Error]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not get access token">>}]})
    end.

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
            RequestParams = uri_params_decode(Body),
            AccessToken = oauth:token(RequestParams),
            AccessTokenSecret = oauth:token_secret(RequestParams),
            ScreenName = screen_name(RequestParams),
            UserID = user_id(RequestParams),
            {ok, AccessToken, AccessTokenSecret, ScreenName, UserID};
                
        _ ->
            ?LOG_DEBUG("process_twitter_request_token: non 200 response of: ~p", [Response]),
            {error, "Non 200 response from Twitter"}
    end.
   
screen_name(Params) ->
    proplists:get_value("screen_name", Params).

user_id(Params) ->
      proplists:get_value("user_id", Params).
 
%% Param handling functions from erlang_oauth but either not exported or not in 
%% the CouchDB version
uri_params_decode(String) ->
    [uri_param_decode(Substring) || Substring <- string:tokens(String, "&")].

uri_param_decode(String) ->
    [Key, Value] = string:tokens(String, "="),
    {uri_decode(Key), uri_decode(Value)}.

uri_decode(Str) when is_list(Str) ->
    uri_decode(Str, []).

uri_decode([$%, A, B | T], Acc) ->
    uri_decode(T, [(hex2dec(A) bsl 4) + hex2dec(B) | Acc]);
uri_decode([X | T], Acc) ->
    uri_decode(T, [X | Acc]);
uri_decode([], Acc) ->
    lists:reverse(Acc, []).

hex2dec(C) when C >= $A andalso C =< $F ->
  C - $A + 10;
hex2dec(C) when C >= $0 andalso C =< $9 ->
  C - $0.

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
    %% Extract required values from config ini
    [Key, IV] = lists:map(fun(K) ->
                      case couch_config:get("blowfish", K, undefined) of
                          undefined -> throw({missing_config_value, "Cannot find key '"++K++"' in [aes] section of config"});
                          V -> V
                      end
                  end, ["key", "ivec"]),
    
    ?LOG_DEBUG("AES Key: ~p  IVec= ~p", [Key, IV]),
    
    BinaryKey = hexstr2bin(Key),
    BinaryIV = hexstr2bin(IV),
    crypto:blowfish_cfb64_encrypt(BinaryKey, BinaryIV, Value).

decrypt(Value) ->
    [Key, IV] = lists:map(fun(K) ->
                      case couch_config:get("blowfish", K, undefined) of
                          undefined -> throw({missing_config_value, "Cannot find key '"++K++"' in [aes] section of config"});
                          V -> V
                      end
                  end, ["key", "ivec"]),
    
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
  
