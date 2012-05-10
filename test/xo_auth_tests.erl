-module(xo_auth_tests).
-include_lib("eunit/include/eunit.hrl").

illegal_prefix_test_() ->
    {setup,
     fun() -> 
             meck:new(couch_config, []),
             meck:expect(couch_config, get, fun("xo_auth", "illegal_username_prefixes") ->
                                                    ["foo", "bar"];
                                               ("xo_auth", "illegal_username_prepend") ->
                                                    "prep_"
                                            end)
     end,
     fun(_) -> 
             meck:unload(couch_config)
     end,
     fun(_) ->
             [
              ?_assertEqual("ben", xo_auth:apply_username_restrictions("ben")),
              ?_assertEqual("prep_fooben", xo_auth:apply_username_restrictions("fooben")),
              ?_assertEqual("prep_barben", xo_auth:apply_username_restrictions("barben")),
              ?_assert(meck:validate(couch_config))
             ]
     end}.

no_illegal_prefix_test_() ->
    {setup,
     fun() -> 
             meck:new(couch_config, []),
             meck:expect(couch_config, get, fun("xo_auth", "illegal_username_prefixes") ->
                                                    undefined;
                                               ("xo_auth", "illegal_username_prepend") ->
                                                    undefined
                                            end)
     end,
     fun(_) -> 
             meck:unload(couch_config)
     end,
     fun(_) ->
             [
              ?_assertEqual("ben", xo_auth:apply_username_restrictions("ben")),
              ?_assertEqual("fooben", xo_auth:apply_username_restrictions("fooben"))
             ]
     end}.

missing_config_test_() ->
    {setup,
     fun() -> 
             meck:new(couch_config, []),
             meck:expect(couch_config, get, fun("xo_auth", "illegal_username_prefixes") ->
                                                    ["foo"];
                                               ("xo_auth", "illegal_username_prepend") ->
                                                    undefined
                                            end)
     end,
     fun(_) -> 
             meck:unload(couch_config)
     end,
     fun(_) ->
             [
              ?_assertException(throw, illegal_prefixes_specified_but_no_prepend,  
                                xo_auth:apply_username_restrictions("ben"))
             ]
     end}.
                 







