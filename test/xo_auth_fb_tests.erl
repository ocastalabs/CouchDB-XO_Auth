-module(xo_auth_fb_tests).
-include_lib("eunit/include/eunit.hrl").

convert_name_to_username_test_() ->
    [
     ?_assertEqual("ben", xo_auth_fb:convert_name_to_username("Ben")),
     ?_assertEqual("bennortier", xo_auth_fb:convert_name_to_username("Ben Nortier")),
     ?_assertEqual("bn", xo_auth_fb:convert_name_to_username("B&n")),
     ?_assertException(throw, {no_username_possible_from_name, ">#%|\\"},  xo_auth_fb:convert_name_to_username(">#%|\\"))
    ].







