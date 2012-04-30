-module(xo_auth).

-export([generate_cookied_response_json/3]).
-export([check_user_database/2]).
-export([create_user_doc/3]).
-export([create_user_doc/5]).
-export([update_access_token/3]).
-export([update_access_token/4]).

-include("couch_db.hrl").
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
    User = case couch_auth_cache:get_user_creds(Name) of
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
    Cookie = couch_httpd_auth:cookie_auth_header(Req#httpd{user_ctx=#user_ctx{name=Name},auth={<<Secret/binary,UserSalt/binary>>,true}},[]),
    couch_httpd:send_json(Req, 302, [{"Location", RedirectUri}] ++ Cookie, nil).

check_user_database(ServiceName, ID) ->
    %% Check the Auth database for a user document containg this ID
    %% for the supplied service name
    AuthDb = open_auth_db(),
    {ok, Db} = ensure_xo_views_exist(AuthDb),

    Result = 
        case query_xref_view(Db, [ServiceName, ID], [ServiceName, ID, <<"{}">>]) of
            [] ->
                nil;
            [Row] ->
                Row;
            [_ | _] ->
            Reason = iolist_to_binary(
                       io_lib:format("Found multiple matching entries for ~p ID: ~p", [ServiceName, ID])),
                {error, {<<"oauth_token_consumer_key_pair">>, Reason}}
        end,
    couch_db:close(Db),
    Result.

create_user_doc(Username, ServiceName, ServiceID) ->
    create_user_doc(Username, ServiceName, ServiceID, [], []).

create_user_doc(Username, ServiceName, ServiceID, AccessToken, AccessTokenSecret) ->

    %% Create user auth doc with access token
    TrimmedName = re:replace(Username, "[^A-Za-z0-9_-]", "", [global, {return, list}]),
    ?LOG_DEBUG("Trimmed name is ~p", [TrimmedName]),
    Db = open_auth_db(),

    {Name} = get_unused_name(Db, TrimmedName),
    ?LOG_DEBUG("Proceeding with name ~p", [Name]),
    %% Generate a _users record with the appropriate
    %% Service Record eg:
    %% "facebook" : {"id" : "123456"", "access_token": "ABDE485864030DF73277E"}
    FullID=?l2b("org.couchdb.user:"++Name),
    ServiceDetails = case AccessTokenSecret of
                         [] ->
                             {[
                               {?l2b("id"), ServiceID},
                               {?l2b("access_token"), ?l2b(AccessToken)}]};

                         Secret ->
                             {[
                               {?l2b("id"), ServiceID},
                               {?l2b("access_token"), ?l2b(AccessToken)},
                               {?l2b("access_token_secret"), ?l2b(Secret)}]}
                     end,

    Salt=couch_uuids:random(),
    NewDoc = #doc{
      id=FullID,
      body={[
             {?l2b("_id"), FullID},
             {?l2b("salt"), Salt},
             {ServiceName, ServiceDetails},
             {?l2b("name"), ?l2b(Name)},
             {?l2b("roles"), []},
             {?l2b("type"), ?l2b("user")}
            ]}
     },
    %% See above for Validation reasoning
    DbWithoutValidationFunc = Db#db{ validate_doc_funs=[] },
    Result = case couch_db:update_doc(DbWithoutValidationFunc, NewDoc, []) of
                 {ok, _} ->
                     {ok, Name};
                 Error ->
                     Error
             end,
    couch_db:close(Db),
    Result.

update_access_token(DocID, ServiceName, AccessToken) ->
    ServiceDetailsUpdater =
        fun(ServiceDetails) ->
                ?replace(ServiceDetails, ?ACCESS_TOKEN, ?l2b(AccessToken))
        end,
    update_access_token_with_details(DocID, ServiceName, ServiceDetailsUpdater).

update_access_token(DocID, ServiceName, AccessToken, AccessTokenSecret) ->
    ServiceDetailsUpdater = 
        fun(ServiceDetails) ->
                ServiceDetails1 = ?replace(ServiceDetails, ?ACCESS_TOKEN, ?l2b(AccessToken)),
                ?replace(ServiceDetails1, ?ACCESS_TOKEN_SECRET, ?l2b(AccessTokenSecret))
        end,
    update_access_token_with_details(DocID, ServiceName, ServiceDetailsUpdater).

update_access_token_with_details(DocID, ServiceName, ServiceDetailsUpdater) ->
    Db = open_auth_db(),

    %% Update a _users record with a new access key
    try
        case (catch couch_db:open_doc(Db, DocID, [ejson_body])) of
            {ok, Doc} ->
                {DocBody} = Doc#doc.body,
                ?LOG_DEBUG("User doc ~p exists.", [DocID]),
                {ServiceDetails} = couch_util:get_value(ServiceName, DocBody, []),
                ?LOG_DEBUG("Extracted Service Details ~p", [ServiceDetails]),

                ServiceDetails1 = {ServiceDetailsUpdater(ServiceDetails)},
                ?LOG_DEBUG("Updated Service Details ~p", [ServiceDetails1]),

                NewDocBody = ?replace(DocBody, ServiceName, ServiceDetails1),
                ?LOG_DEBUG("Updated Body ~p", [NewDocBody]),
                
                %% To prevent the validation functions for the db taking umbrage at our
                %% behind the scenes twiddling, we blank them out.
                %% NOTE: Potentially fragile. Possibly dangerous?
                DbWithoutValidationFunc = Db#db{ validate_doc_funs=[] },
                couch_db:update_doc(DbWithoutValidationFunc, Doc#doc{body = {NewDocBody}}, []);
            _ ->
                ?LOG_DEBUG("No doc found for Doc ID ~p.", [DocID]),
                nil
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

        _ -> {Name}
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

