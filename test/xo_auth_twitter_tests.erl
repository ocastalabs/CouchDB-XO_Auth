-module(xo_auth_twitter_tests).
-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

create_test_() ->
    Req = request,
    {setup,
     fun() -> 
             %% Mock the couch config and logging system
             meck:new(couch_config),
             meck:expect(couch_config, get, 
                         fun("twitter", "client_app_uri", nil) ->  
                                 "http://APP_URI";
                            ("twitter", "store_access_token", "false") -> 
                                 "true" 
                         end),

             meck:new(couch_log),
             meck:expect(couch_log, debug_on, fun() -> false end),

             %% Mock the common layer
             meck:new(xo_auth),
             meck:expect(xo_auth, check_user_database, 
                         fun(<<"twitter">>, <<"userid">>) -> 
                                 nil
                         end),
             meck:expect(xo_auth, create_user_doc, 
                         fun("screenname", <<"twitter">>, <<"userid">>, "TOKEN", "SECRET") ->
                                 created
                         end),
             meck:expect(xo_auth, create_user_doc_response,
                         fun(_Req, "http://APP_URI", created) ->
                                 response
                         end),

             ok
     end,
     fun(_) ->
             meck:unload(xo_auth),
             meck:unload(couch_config),
             meck:unload(couch_log),
             ok
     end,
     fun(_) ->
             [
              ?_assertEqual(response,
                            xo_auth_twitter:create_or_update_user(Req, {ok, "TOKEN", "SECRET", "screenname", "userid"})),
              ?_assert(meck:validate(xo_auth)),
              ?_assert(meck:validate(couch_config))
             ]
     end}.

update_test_() ->
    Req = request,
    {setup,
     fun() -> 
             %% Mock the couch config and logging system
             meck:new(couch_config),
             meck:expect(couch_config, get, 
                         fun("twitter", "client_app_uri", nil) ->  
                                 "http://APP_URI";
                            ("twitter", "store_access_token", "false") -> 
                                 "true" 
                         end),

             meck:new(couch_log),
             meck:expect(couch_log, debug_on, fun() -> false end),

             %% Mock the common layer
             meck:new(xo_auth),
             meck:expect(xo_auth, check_user_database, 
                         fun(<<"twitter">>, <<"userid">>) -> 
                                 {[{<<"user_id">>, <<"userid">>},
                                   {<<"name">>, <<"screenname">>},
                                   {<<"access_token">>, <<"OLD_TOKEN">>}]}
                         end),
             meck:expect(xo_auth, update_access_token, 
                         fun(<<"userid">>, <<"twitter">>, <<"OLD_TOKEN">>, <<"TOKEN">>, <<"SECRET">>) ->
                                 created
                         end),
             meck:expect(xo_auth, generate_cookied_response_json,
                         fun(<<"screenname">>, _Req, "http://APP_URI") ->
                                 response
                         end),

             ok
     end,
     fun(_) ->
             meck:unload(xo_auth),
             meck:unload(couch_config),
             meck:unload(couch_log),
             ok
     end,
     fun(_) ->
             [
              ?_assertEqual(response,
                            xo_auth_twitter:create_or_update_user(Req, {ok, "TOKEN", "SECRET", "screenname", "userid"})),
              ?_assert(meck:validate(xo_auth)),
              ?_assert(meck:validate(couch_config))
             ]
     end}.

-endif.






