-define(XREFBYID_MAP_FUN, <<"
function(doc) {
    if (doc.type === 'user')
       if (doc.facebook)
        if (doc.facebook) {
            obj = {
                'user_id' : doc._id,
                'access_token' : doc.facebook.access_token,
                'name' : doc.name
            }
            emit(['facebook', doc.facebook.id], obj);
        }
        if (doc.twitter) {
            obj = {
                'user_id' : doc._id,
                'access_token' : doc.twitter.access_token,
                'name' : doc.name
            }
            emit(['twitter', doc.twitter.id], obj);
        }
}
">>).
