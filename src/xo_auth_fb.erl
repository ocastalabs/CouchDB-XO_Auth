-module(xo_auth_fb).
-export([handle_fb_req/1]).
-export([convert_name_to_username/1]).
-include_lib("couch/include/couch_db.hrl").

%% This module handles Facebook signin and _user document creation.
%% The handle_fb_req should be configured to a URI that is passed to Facebook as the
%% redirect_uri parmeter on the initial request to www.facebook.com/dialog/oauth
%%

%% Exported functions
handle_fb_req(#httpd{method='GET'}=Req) ->
    try 
        %% Did we get a 'code' or 'error' back from facebook?
        case couch_httpd:qs_value(Req, "code") of
            undefined ->
                case couch_httpd:qs_value(Req, "accessToken") of
                    undefined ->
                        ?LOG_DEBUG("Facebook responded with something other than a code: ~p", [Req]),
                        couch_httpd:send_json(Req, 403, [], {[{error, <<"No code supplied">>}]});
                    AccessToken ->
                        [RedirectURI, ClientID, ClientSecret] = 
                            xo_auth:extract_config_values("fb", ["redirect_uri", "client_id", "client_secret"]),

                        GraphmeResponse = request_facebook_graphme_info(AccessToken),
                        create_or_update_user(Req, ClientID, ClientSecret, AccessToken, GraphmeResponse);
                end;
            Code -> 
                handle_fb_code(Req, Code)
        end
    catch
        throw:could_not_create_user_skeleton ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not create user skeleton">>}]});
        throw:account_already_associated_with_another_user ->
            couch_httpd:send_json(Req, 400, [], {[{error, <<"Facebook account registered with another user">>}]});
        throw:could_not_extend_token ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Failed to extend expiration of token">>}]});
        throw:non_200_from_graphme ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Non 200 response from graphme">>}]});
        throw:no_document_for_user ->
            couch_httpd:send_json(Req, 403, [], {[{error, <<"No user exists for auth session cookie">>}]});
        throw:document_not_found_for_user ->
            couch_httpd:send_json(Req, 500, [], {[{error, <<"Document not found for user">>}]})
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
            %% Retrieve info from the graph/me API call
            GraphmeResponse = request_facebook_graphme_info(AccessToken),
            create_or_update_user(Req, ClientID, ClientSecret, AccessToken, GraphmeResponse);
        Error ->
            ?LOG_DEBUG("Non-success from request_facebook_access_token call: ~p", [Error]),
            couch_httpd:send_json(Req, 403, [], {[{error, <<"Could not get access token">>}]})
    end.

create_or_update_user(Req, ClientID, ClientSecret, AccessToken, {ok, FacebookUserID, FBUsername}) ->
    Username = xo_auth:determine_username(Req, "facebook", FacebookUserID, FBUsername),

    %% Extend the token if its will be stored
    ok = case couch_config:get("fb", "store_access_token", "false") of
             "true" ->
                 {ok, NewToken} = request_access_token_extension(ClientID, ClientSecret, AccessToken),
                 xo_auth:update_service_details(Username, "facebook", FacebookUserID, NewToken);
             _ ->
                 xo_auth:update_service_details(Username, "facebook", FacebookUserID, [])
         end,
                 
    RedirectUri = couch_config:get("fb", "client_app_uri", nil),
    xo_auth:generate_cookied_response_json(Username, Req, RedirectUri).

request_facebook_graphme_info(AccessToken) ->
    %% Construct the URL to access the graph API's /me page
    Url="https://graph.facebook.com/me?fields=id,name&access_token="++AccessToken,
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
            ID = ?b2l(couch_util:get_value(<<"id">>, FBInfo)),
            Username = case couch_util:get_value(<<"username">>, FBInfo) of
                           undefined ->
                               convert_name_to_username(?b2l(couch_util:get_value(<<"name">>, FBInfo)));
                           FBUsername ->
                               ?b2l(FBUsername)
                       end,
            WithRestrictions = xo_auth:apply_username_restrictions(Username),
            {ok, ID, WithRestrictions};
        _ ->
            throw(non_200_from_graphme)
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
    Url="https://graph.facebook.com/oauth/access_token?client_id=" ++ 
        ClientID ++ 
        "&client_secret=" ++ 
        ClientSecret ++
        "&grant_type=fb_exchange_token&fb_exchange_token=" ++ 
        Token,
    ?LOG_DEBUG("request_access_token_extension: requesting using URL - ~p", [Url]),

    %% Request the page
    Resp=ibrowse:send_req(Url, [], get, []),
    ?LOG_DEBUG("Full response from Facebook: ~p", [Resp]),

    case Resp of 
        {ok, "200", _, Body} ->
            Props = mochiweb_util:parse_qs(Body),
            case lists:keyfind("access_token", 1, Props) of
                {_, NewAccessToken} ->
                    ?LOG_DEBUG("process_access_token_extension: access_token=~p",[NewAccessToken]),
                    {ok, NewAccessToken};
                _ ->
                    ?LOG_DEBUG("process_access_token_extension: unexpected response: ~p", [Body]),
                    throw(could_not_extend_token)
            end;
        _ ->
            ?LOG_DEBUG("process_access_token_extension: non 200 response of: ~p", [Resp]),
            throw(could_not_extend_token)
    end.
    
-define(INVALID_CHARS, "&%+,./:;=?@ <>#%|\\[]{}~^`'").

convert_name_to_username(Name) ->
    Trimmed = lists:foldr(fun(Char, Acc) ->
                                  case lists:member(Char, ?INVALID_CHARS) of
                                      true ->
                                          Acc;
                                      false ->
                                          [Char|Acc]
                                  end
                          end,
                          "",
                          string:to_lower(Name)),
    case Trimmed of 
        "" -> throw({no_username_possible_from_name, Name});
        Valid -> Valid
    end.
             
        
                             
