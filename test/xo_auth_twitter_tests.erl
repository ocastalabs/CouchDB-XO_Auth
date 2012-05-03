-module(xo_auth_twitter_tests).
-include_lib("eunit/include/eunit.hrl").

%% twitter_callback_test_() ->
%%     {setup,
%%      fun() -> 
%%              meck:new(my_library_module),
%%              meck:expect(my_library_module, fib, fun(8) -> 21 end),
%%      end,
%%      fun(_) -> 
%%              meck:unload(my_library_module).
%%      end,
%%      [
%%       ?assertEqual(21, code_under_test:run(fib, 8)),
%%       ?assert(meck:validate(my_library_module)),
      
%%      ]}.


uri_params_decode_test_() ->
    [
     ?_assertEqual([{"a", "b"}], mochiweb_util:parse_qs("a=b")),
     ?_assertEqual([{"a", "1"}, {"b", "2"}], mochiweb_util:parse_qs("a=1&b=2")),
     ?_assertEqual([{"A", "B"}], mochiweb_util:parse_qs("%41=%42"))
    ].
