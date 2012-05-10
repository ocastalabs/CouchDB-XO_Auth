-module(xo_auth).

-export([generate_cookied_response_json/3]).
-export([determine_username/4]).
-export([update_service_details/3, 
         update_service_details/4, 
         update_service_details/5]).
-export([extract_config_values/2]).
-export([apply_username_restrictions/1]).

-include_lib("couch/include/couch_db.hrl").
-include("xo_auth.hrl").

-define(XO_DDOC_ID, <<"_design/xo_auth">>).
-define(XREF_VIEW_NAME, <<"xrefbyid">>).
-define(ACCESS_TOKEN, <<"access_token">>).
-define(ACCESS_TOKEN_SECRET, <<"access_token_secret">>).
-define(replace(L, K, V), lists:keystore(K, 1, L, {K, V})).

%% Exported functions
generate_cookied_response_json(Name, Req, RedirectUri) ->
    %% Create an auth cookie in the same way that couch_httpd_auth.erl does.
    %% NOTE: This could be fragile! If couch_httpd_auth.erl changes the way it handles
    %%       auth cookie then this code will break. However, couch_httpd_auth.erl doesn't
    %%       seem to expose enough method for us to make it do all the work.
    User = case couch_auth_cache:get_user_creds(?l2b(Name)) of
        nil -> [];
        Result -> Result
    end,
    UserSalt = couch_util:get_value(<<"salt">>, User, <<>>),
    Secret=?l2b( case couch_config:get("couch_httpd_auth", "secret", nil) of
        nil ->
            NewSecret = ?b2l(couch_uuids:random()),
            couch_config:set("couch_httpd_auth", "secret", NewSecret),
            NewSecret;
        Sec -> Sec
    end ),

    %% Create a json response containing some useful info and the AuthSession
    %% cookie.
    Cookie = couch_httpd_auth:cookie_auth_header(Req#httpd{user_ctx=#user_ctx{name=?l2b(Name)},auth={<<Secret/binary,UserSalt/binary>>,true}},[]),
    couch_httpd:send_json(Req, 302, [{"Location", RedirectUri}] ++ Cookie, nil).

check_user_database(ServiceName, ID) ->
    %% Check the Auth database for a user document containg this ID
    %% for the supplied service name
    AuthDb = open_auth_db(),
    {ok, Db} = ensure_xo_views_exist(AuthDb),
    try 

        case query_xref_view(Db, [ServiceName, ID], [ServiceName, ID, <<"{}">>]) of
            [] ->
                nil;
            [Row] ->
                Row;
            [_ | _] ->
                Reason = iolist_to_binary(
                           io_lib:format("Found multiple matching entries for ~p ID: ~p", [ServiceName, ID])),
                {error, {<<"oauth_token_consumer_key_pair">>, Reason}}
        end
    after
        couch_db:close(Db)
    end.


%%
%% Determine the username from the request and the token response.
%% If there is an authenticated session user, that user is used. If the
%% user is new, the username will be determined from the username of the
%% service.
%%
determine_username(Req, Provider, ProviderID, ProviderUsername) ->
    case get_username_from_request(Req) of
        undefined -> 
            %% No other account may be associated already
            case check_user_database(?l2b(Provider), ?l2b(ProviderID)) of
                {Result} ->
                    ?b2l(couch_util:get_value(<<"name">>, Result, []));
                _ ->
                    ?LOG_DEBUG("Not an existing user - creating new account", []),
                    {ok, _DocID, NewUsername} = create_user_skeleton(ProviderUsername),
                    NewUsername
            end;
        
        ExistingUsername ->
            ?LOG_DEBUG("Auth session found. Adding service to user: ~p", [ExistingUsername]),

            %% If there is already a account registered with this username, 
            %% it must be this user (otherwise multiple users could register with the
            %% same provider ID).
            case check_user_database(?l2b(Provider), ?l2b(ProviderID)) of
                {Result} ->
                    case ?b2l(couch_util:get_value(<<"name">>, Result, [])) of
                        ExistingUsername ->
                            ExistingUsername;
                        _ ->
                            throw(account_already_associated_with_another_user)
                    end;
                _ ->
                    ExistingUsername
            end
    end.

create_user_skeleton(UsernamePrototype) ->

    %% Create user auth doc with access token
    TrimmedName = re:replace(UsernamePrototype, "[^A-Za-z0-9_-]", "", [global, {return, list}]),
    ?LOG_DEBUG("Trimmed name is ~p", [TrimmedName]),
    Db = open_auth_db(),
    try 

        Username = get_unused_name(Db, TrimmedName),
        ?LOG_DEBUG("Creating user skeleton for username ~p", [Username]),

        DocID=?l2b("org.couchdb.user:"++Username),
        Salt=couch_uuids:random(),
        NewDoc = #doc{
          id=DocID,
          body={[
                 {<<"_id">>, DocID},
                 {<<"salt">>, Salt},
                 {<<"name">>, ?l2b(Username)},
                 {<<"roles">>, []},
                 {<<"type">>, <<"user">>}
                ]}
         },

        DbWithoutValidationFunc = Db#db{ validate_doc_funs=[] },
        case couch_db:update_doc(DbWithoutValidationFunc, NewDoc, []) of
            {ok, _} ->
                ?LOG_DEBUG("User doc created for ~p:~p", [Username, DocID]),
                {ok, DocID, Username};
            Error ->
                ?LOG_ERROR("Could not create user doc for ~p:~p Reason:", [Username, DocID, Error]),
                throw(could_not_create_user_skeleton)
        end
    after
        couch_db:close(Db)
    end.

update_service_details(Username, ServiceName, ServiceUserID) ->
    update_service_details(Username, ServiceName, ServiceUserID, [], []).

update_service_details(Username, ServiceName, ServiceUserID, AccessToken) ->
    update_service_details(Username, ServiceName, ServiceUserID, AccessToken, []).

update_service_details(Username, ServiceName, ServiceUserID, AccessToken, AccessTokenSecret) ->
    Db = open_auth_db(),
    DocID = "org.couchdb.user:" ++ Username,

    %% Update a _users record with a new access key
    try
        case (catch couch_db:open_doc(Db, ?l2b(DocID), [ejson_body])) of
            {ok, Doc} ->
                {DocBody} = Doc#doc.body,
                ?LOG_DEBUG("User doc before update: ~p", [DocBody]),

                %% Update values that are not empty
                ServiceDetails = [{<<"id">>, ?l2b(ServiceUserID)}],
                ServiceDetails1 = {lists:foldl(fun({_Key, <<>>}, Acc) ->
                                                       Acc;
                                                  ({Key, Value}, Acc) ->
                                                       ?replace(Acc, Key, Value)
                                               end,
                                               ServiceDetails,
                                               [{?ACCESS_TOKEN, ?l2b(AccessToken)},
                                                {?ACCESS_TOKEN_SECRET, ?l2b(AccessTokenSecret)}])},

                NewDocBody = ?replace(DocBody, ?l2b(ServiceName), ServiceDetails1),
                ?LOG_DEBUG("Updated Body: ~p", [NewDocBody]),
                
                %% To prevent the validation functions for the db taking umbrage at our
                %% behind the scenes twiddling, we blank them out.
                %% NOTE: Potentially fragile. Possibly dangerous?
                DbWithoutValidationFunc = Db#db{ validate_doc_funs=[] },
                {ok, _} = couch_db:update_doc(DbWithoutValidationFunc, Doc#doc{body = {NewDocBody}}, []),
                ok;
            _ ->
                ?LOG_ERROR("No doc found for Doc ID ~p.", [DocID]),
                throw(document_not_found_for_user)
        end
    catch throw:conflict ->
            %% Shouldn't happen but you can never be too careful
            ?LOG_ERROR("Conflict error when updating user document ~p.", [DocID])
    after
        couch_db:close(Db)
    end.

open_auth_db() ->
    DbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
    DbOptions = [{user_ctx, #user_ctx{roles = [<<"_admin">>]}}],
    {ok, AuthDb} = couch_db:open_int(DbName, DbOptions),
    AuthDb.

get_unused_name(AuthDB, Name) ->
    FullID=?l2b("org.couchdb.user:"++Name),
    ?LOG_DEBUG("Checking for existence of ~p", [FullID]),
    
    case (catch couch_db:open_doc_int(AuthDB, FullID, [])) of
        {ok, _} ->
            get_unused_name(AuthDB, lists:concat([Name, random:uniform(9)]));
        _ -> 
            Name
    end.    

ensure_xo_views_exist(AuthDb) ->
    case couch_db:open_doc(AuthDb, ?XO_DDOC_ID, []) of
        {ok, _DDoc} ->
            {ok, AuthDb};
        _ ->
            {ok, DDoc} = get_xo_ddoc(),
            {ok, _Rev} = couch_db:update_doc(AuthDb, DDoc, []),
            {ok, _AuthDb2} = couch_db:reopen(AuthDb)
    end.

get_xo_ddoc() ->
    Json = {[
             {<<"_id">>, ?XO_DDOC_ID},
             {<<"language">>, <<"javascript">>},
             {<<"views">>,
              {[
                {?XREF_VIEW_NAME,
                 {[
                   {<<"map">>, ?XREFBYID_MAP_FUN}
                  ]}
                }
               ]}
             }
            ]},
    {ok, couch_doc:from_json_obj(Json)}.

query_xref_view(Db, StartKey, EndKey) ->
    {ok, View, _} = couch_view:get_map_view(Db, ?XO_DDOC_ID, ?XREF_VIEW_NAME, nil),
    FoldlFun = fun({_Key_DocId, Value}, _, Acc) ->
                       {ok, [Value | Acc]}
               end,
    ViewOptions = [
                   {start_key, {StartKey, ?MIN_STR}},
                   {end_key, {EndKey, ?MAX_STR}}
                  ],

    {ok, _, Result} = couch_view:fold(View, FoldlFun, [], ViewOptions),
    Result.


extract_config_values(Category, Keys) ->
    lists:map(fun(K) ->
                      case couch_config:get(Category, K, undefined) of
                          undefined -> throw({missing_config_value, 
                                              "Cannot find key '" ++ K ++ "' in [" ++ Category  ++ "] section of config"});
                          V -> V
                      end
              end, Keys).

get_username_from_request(#httpd{ user_ctx=UserCtx }) ->
    case UserCtx of
        #user_ctx{name=Username} when Username =/= null -> 
            ?b2l(Username);
        _ ->
            undefined
    end.

apply_username_restrictions(Username) ->
    case {couch_config:get("xo_auth", "illegal_username_prefixes"),
          couch_config:get("xo_auth", "illegal_username_prepend")} of
        {undefined, undefined} ->
            Username;
        {_, undefined} ->
            throw(illegal_prefixes_specified_but_no_prepend);
        {Prefixes, Prepend} ->
            case lists:any(fun(Prefix) ->
                                   string:str(Username, Prefix) =:= 1
                           end,
                           Prefixes) of
                true ->
                    Prepend ++ Username;
                false ->
                    Username
            end
    end.
