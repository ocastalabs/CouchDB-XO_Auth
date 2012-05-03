-module(xo_auth_fb).
-export([handle_fb_req/1]).
-include_lib("couch/include/couch_db.hrl").

%% This module handles Facebook signin and _user document creation.
%% The handle_fb_req should be configured to a URI that is passed to Facebook as the
%% redirect_uri parmeter on the initial request to www.facebook.com/dialog/oauth
%%

%% Exported functions
handle_fb_req(#httpd{method='GET'}=Req) ->
    %% Did we get a 'code' or 'error' back from facebook?
    case couch_httpd:qs_value(Req, "code") of
        undefined ->
            ?LOG_DEBUG("Facebook responded with something other than a code: ~p", [Req]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"No code supplied">>}]});
        Code -> handle_fb_code(Req, Code)
    end;
handle_fb_req(Req) ->
    couch_httpd:send_method_not_allowed(Req, "GET").


handle_fb_code(Req, FBCode) ->
    %% Extract required values from config ini
    [RedirectURI, ClientID, ClientSecret] = 
        xo_auth:extract_config_values("fb", ["redirect_uri", "client_id", "client_secret"]),
    
    %% if the client passed in a client app token then facebook should have passed it back to us,
    %% so extract it.
    ClientAppToken = case couch_httpd:qs_value(Req, "clientapptoken") of
        undefined -> "";
        Cat -> couch_util:url_encode(Cat)
    end,
    
    %% Get an access token from Facebook
    case request_facebook_access_token(ClientAppToken, RedirectURI, ClientID, ClientSecret, FBCode) of
        {ok, AccessToken} ->
            handle_facebook_access_token(Req, ClientID, ClientSecret, AccessToken);
        Error ->
            ?LOG_DEBUG("Non-success from request_facebook_access_token call: ~p", [Error]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not get access token">>}]})
    end.


handle_facebook_access_token(Req, ClientID, ClientSecret, AccessToken) ->
    %% Retrieve info from the graph/me API call
    case request_facebook_graphme_info(AccessToken) of
        {ok, ID, FBUsername} ->
            RedirectUri = couch_config:get("fb", "client_app_uri", nil),
            
            case xo_auth:check_user_database(<<"facebook">>, ID) of
                nil ->
                    ?LOG_DEBUG("Nothing found for facebook ID: ~p", [ID]),
                    case couch_config:get("fb", "store_access_token", "false") of
                        "false" ->
                            xo_auth:create_user_doc_response(
                              Req, RedirectUri,
                              xo_auth:create_user_doc(FBUsername, <<"facebook">>, ID));
                        
                        _ ->
                            %% Because of the deprecation of offlineAccess we now ask for
                            %% an extension.
                            ExtensionResult = 
                                request_access_token_extension(ClientID, ClientSecret, AccessToken),
                            case ExtensionResult of
                                {ok, NewToken} ->
                                    ?LOG_DEBUG("Extended access token. New token: ~p", [NewToken]),
                                    xo_auth:create_user_doc_response(
                                      Req, RedirectUri,
                                      xo_auth:create_user_doc(FBUsername, <<"facebook">>, ID, NewToken, []));
                                Error ->
                                    ?LOG_INFO("Failed to extend expiration of token: ~p", [Error]),
                                    couch_httpd:send_json(Req, 403, [], {[{error, <<"Failed to extend expiration of token">>}]})
                            end
                                
                    end;
                    
                    
                {Result} ->
                    ?LOG_DEBUG("View result is ~p", [Result]),
                    DocID = couch_util:get_value(<<"user_id">>, Result, []),
                    Name = couch_util:get_value(<<"name">>, Result, []),
                    
                    case couch_config:get("fb", "store_access_token", "false") of
                        "false" ->
                            xo_auth:generate_cookied_response_json(Name, Req, RedirectUri);
                            
                        _ ->
                            OldAccessToken = couch_util:get_value(<<"access_token">>, Result, []),
                            case request_access_token_extension(ClientID, ClientSecret, AccessToken) of
                                {ok, ExtendedToken} ->
                                    xo_auth:update_access_token(DocID, <<"facebook">>, OldAccessToken, ?l2b(ExtendedToken)),
                                    xo_auth:generate_cookied_response_json(Name, Req, RedirectUri);
                                Error ->
                                    ?LOG_INFO("Failed to extend token: ~p", [Error]),
                                    couch_httpd:send_json(Req, 403, [], {[{error, <<"Failed to extend expiration of token">>}]})
                            end
                    end;
                    
                {error, Reason} ->
                    couch_httpd:send_json(Req, 403, [], {[{<<"xo_auth">>, Reason}]})
            end;
                        
        Error ->
            ?LOG_DEBUG("Non-success from request_facebook_graphme_info call: ~p", [Error]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Failed graphme request">>}]})
    end.

request_facebook_graphme_info(AccessToken) ->
    %% Construct the URL to access the graph API's /me page
    Url="https://graph.facebook.com/me?fields=id,username&access_token="++AccessToken,
    ?LOG_DEBUG("Url=~p",[Url]),

    %% Request the page
    Resp=ibrowse:send_req(Url, [], get, []),
    ?LOG_DEBUG("request_facebook_graphme_info response=~p",[Resp]),

    process_facebook_graphme_response(Resp).

process_facebook_graphme_response(Resp) ->
    %% Extract user facebook id from the body
    case Resp of 
        {ok, "200", _, Body} ->
            %% Decode the facebook response body, extracting the
            %% ID and the complete response.
            {FBInfo}=?JSON_DECODE(Body),
            ID=couch_util:get_value(<<"id">>, FBInfo),
            FBUsername=couch_util:get_value(<<"username">>, FBInfo),
            {ok, ID, FBUsername};
        _ ->
            {error, "Non 200 response from facebook"}
    end.

request_facebook_access_token(ClientAppToken, RedirectURI, ClientID, ClientSecret, FBCode) ->
    %% Construct the access token request URL.
    %% NOTE: We do not use type=client_type because if we do then we don't get a
    %% session access code back, and without that we are unable to use the /me
    %% alias of the graph API. The redirect_uri is ignored by us, but mandated
    %% by the API.

    FullRedirectUrl = case ClientAppToken of
        "" ->
            couch_util:url_encode(RedirectURI);
        CAT ->
            couch_util:url_encode(RedirectURI++"?clientapptoken="++CAT)
    end,
    Url="https://graph.facebook.com/oauth/access_token?client_id="++ClientID++"&client_secret="++ClientSecret++"&code="++FBCode++"&redirect_uri="++FullRedirectUrl,
    ?LOG_DEBUG("request_facebook_access_token: requesting using URL - ~p", [Url]),

    %% Request the page
    Resp=ibrowse:send_req(Url, [], get, []),
    ?LOG_DEBUG("Full response from Facebook: ~p", [Resp]),

    process_facebook_access_token(Resp).

process_facebook_access_token(Resp) ->
    %% Extract the info we need
    case Resp of 
        {ok, "200", _, Body} ->
            Props = mochiweb_util:parse_qs(Body),
            case lists:keyfind("access_token", 1, Props) of
                {_, AccessToken} ->
                    ?LOG_DEBUG("process_facebook_access_token: access_token=~p",[AccessToken]),
                    {ok, AccessToken};
                _ ->
                    ?LOG_DEBUG("process_facebook_access_token: unexpected response: ~p", [Body]),
                    {error, "Unexpected body response from facebook"}
            end;
        _ ->
            ?LOG_DEBUG("process_facebook_access_token: non 200 response of: ~p", [Resp]),
            {error, "Non 200 response from facebook"}
    end.

request_access_token_extension(ClientID, ClientSecret, Token) ->
    %% Construct the request URL.
    Url="https://graph.facebook.com/oauth/access_token?client_id="++ClientID++"&client_secret="++ClientSecret++"&grant_type=fb_exchange_token&fb_exchange_token="++Token,
    ?LOG_DEBUG("request_access_token_extension: requesting using URL - ~p", [Url]),

    %% Request the page
    Resp=ibrowse:send_req(Url, [], get, []),
    ?LOG_DEBUG("Full response from Facebook: ~p", [Resp]),

    process_access_token_extension(Resp).

    
process_access_token_extension(Resp) ->
    %% Extract the info we need
    case Resp of 
        {ok, "200", _, Body} ->
            Props = mochiweb_util:parse_qs(Body),
            case lists:keyfind("access_token", 1, Props) of
                {_, NewAccessToken} ->
                    ?LOG_DEBUG("process_access_token_extension: access_token=~p",[NewAccessToken]),
                    {ok, NewAccessToken};
                _ ->
                    ?LOG_DEBUG("process_access_token_extension: unexpected response: ~p", [Body]),
                    {error, "Unexpected body response from facebook"}
            end;
        _ ->
            ?LOG_DEBUG("process_access_token_extension: non 200 response of: ~p", [Resp]),
            {error, "Non 200 response from facebook"}
    end.

