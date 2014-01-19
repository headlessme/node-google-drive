
//     node-google-drive
//     Copyright (c) 2012- Nick Baugh <niftylettuce@gmail.com> (http://niftylettuce.com)
//     MIT Licensed

// Open source node.js module for accessing Google Drive's API:
// <https://developers.google.com/drive/v1/reference/>

// * Author: [@niftylettuce](https://twitter.com/#!/niftylettuce)
// * Source: <https://github.com/niftylettuce/node-google-drive>

// # node-google-drive

var base_uri = 'https://www.googleapis.com/drive/v2'
  , request = require('request')


function extend(a,b) {
  for (var x in b) a[x] = b[x];
  return a;
}

var client_id, client_secret;

module.exports = function(access_token, refresh_token, onTokenUpdate) {

  var defaults = {
    headers: {
      Authorization: "Bearer " + access_token
    },
    qs: {}
  }

  function make_request(method, url, p, multipart) {
    if (arguments.callee.length == 3) multipart = true;
    var options = defaults;
    options.qs = extend(options.qs, p.params);
    options.uri = url;
    options.method = method;
    if (multipart && p.meta) {
      options.multipart = [{
        'content-type': 'application/json',
        body: JSON.stringify(p.meta)
      }];
    } else  {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(p.meta);
    }
    return request.defaults(options);
  }

  function extract_params(meta, params, cb) {
    if ((!cb) && (!params) && (typeof meta === 'function' ))
      return {meta:{}, params: {}, cb: meta};
    else if ((!cb) && (typeof params === 'function' ))
      return {meta:meta, params: {}, cb: params};
    else return {meta: meta, params:params, cb: cb};
  }

  function update_token (callback) {
   request({
      method: 'POST',
      url: 'https://accounts.google.com/o/oauth2/token',
      'content-type': 'application/x-www-form-urlencoded',
      form: {
        refresh_token: refresh_token,
        client_id: client_id,
        client_secret: client_secret,
        grant_type: 'refresh_token'
      }
    }, function(err, response, body){
      if (err) {
        callback(new Error('failed to refresh token'));
      } else {
        var body = JSON.parse(body);
        if (!body.access_token)
          return callback(new Error('access token missing from response statusCode='+response.statusCode));
        else return callback(false, body.access_token);
      }
    });
  }

  function refresh_on_401(req, callback) {
    req({}, function(err, response, body){
      if (response && (response.statusCode == 401)) {
        update_token(function(err, new_access_token) {
          if (err) return callback(err);
          if(onTokenUpdate) onTokenUpdate(new_access_token);
          req({headers:{
            Authorization: 'Bearer ' + new_access_token
          }}, callback);
        });
      } else {
        return callback(err, response, body);
      }
    })
  }

  var resources = {}

  resources.files = function(fileId) {

    return {
      list: function(params, cb) {
        var p = extract_params(undefined, params, cb);
        var req = make_request('GET', base_uri + '/files', p);
        return refresh_on_401(req, p.cb);
      },
      insert: function(meta, params, cb) {
        var p = extract_params(meta, params, cb);
        var req = make_request('POST', base_uri + '/files', p);
        return refresh_on_401(req, p.cb);
      },
      get: function(params, cb) {
        var p = extract_params(undefined, params, cb);
        var req = make_request('GET', base_uri + '/files/' + fileId, p);
        return refresh_on_401(req, p.cb);
      },
      patch: function(meta, params, cb) {
        var p = extract_params(meta, params, cb);
        var req = make_request('PATCH', base_uri + '/files/' + fileId, p);
        return refresh_on_401(req, p.cb);
      },
      update: function(meta, params, cb) {
        var p = extract_params(meta, params, cb);
        var req = make_request('PUT', base_uri + '/files/' + fileId, p);
        return refresh_on_401(req, p.cb);
      },
      copy: function(meta, params, cb) {
        var p = extract_params(meta, params, cb);
        var req = make_request('POST', base_uri + '/files/' + fileId + '/copy', p);
        return refresh_on_401(req, p.cb);
      },
      del: function(cb) {
        var p = extract_params(undefined, undefined, cb);
        var req = make_request('DELETE', base_uri + '/files/' + fileId, p);
        return refresh_on_401(req, p.cb);
      },
      touch: function(cb) {
        var p = extract_params(undefined, undefined, cb);
        var req = make_request('POST', base_uri + '/files/' + fileId, p);
        return refresh_on_401(req, p.cb);
      },
      trash: function(cb) {
        var p = extract_params(undefined, undefined, cb);
        var req = make_request('POST', base_uri + '/files/' + fileId + '/trash', p);
        return refresh_on_401(req, p.cb);
      },
      untrash: function(cb) {
        var p = extract_params(undefined, undefined, cb);
        var req = make_request('POST', base_uri + '/files/' + fileId + '/untrash', p);
        return refresh_on_401(req, p.cb);
      },

      permissions: function(permId) {
        return {
          list: function(params, cb) {
            var p = extract_params(undefined, params, cb);
            var req = make_request('GET', base_uri + '/files/' + fileId + '/permissions', p);
            return refresh_on_401(req, p.cb);
          },
          patch: function(meta, params, cb) {
            var p = extract_params(meta, params, cb);
            var req = make_request('PATCH', base_uri + '/files/' + fileId + '/permissions/' + permId, p);
            return refresh_on_401(req, p.cb);
          },
          update: function(meta, params, cb) {
            var p = extract_params(meta, params, cb);
            var req = make_request('PUT', base_uri + '/files/' + fileId + '/permissions/' + permId, p);
            return refresh_on_401(req, p.cb);
          },
          del: function(cb) {
            var p = extract_params(undefined, undefined, cb);
            var req = make_request('DELETE', base_uri + '/files/' + fileId + '/permissions/' + permId, p);
            return refresh_on_401(req, p.cb);
          },
          insert: function(meta, params, cb) {
            var p = extract_params(meta, params, cb);
            var req = make_request('POST', base_uri + '/files/' + fileId + '/permissions', p);
            return refresh_on_401(req, p.cb);
          },
          getIdForEmail: function(email, params, cb) {
            var p = extract_params(undefined, params, cb);
            var req = make_request('GET', base_uri + '/permissionIds/' + email, p);
            return refresh_on_401(req, p.cb);
          }
        }
      }
    }
  }
  
  /*
    Changes
    For Changes Resource details, see below about Resource representations.
    Method  HTTP request  Description
    URIs relative to https://www.googleapis.com/drive/v2, unless otherwise noted
    get   GET  /changes/changeId    Gets a specific change.
    list  GET  /changes       Lists the changes for a user.
    
    Resource representations
    Representation of a change to a file.
    {
      "kind": "drive#change",
      "id": long,
      "fileId": string,
      "selfLink": string,
      "deleted": boolean,
      "file": files Resource
    }
    Property name Value     Description Notes
    kind      string      This is always drive#change.  
    id        long      The ID of the change. 
    fileId      string      The ID of the file associated with this change. 
    selfLink    string      A link back to this change. 
    deleted     boolean     Whether the file has been deleted.  
    file      nested object The updated state of the file. Present if the file has not been deleted.
  */
  
  resources.changes = function(changeId) {
    return {
      list: function(params, cb) {
        var p = extract_params(undefined, params, cb);
        var req = make_request('GET', base_uri + '/changes', p);
        return refresh_on_401(req, p.cb);
      },
      get: function(params, cb) {
        var p = extract_params(undefined, params, cb);
        var req = make_request('GET', base_uri + '/changes/' + changeId, p);
        return refresh_on_401(req, p.cb);
      }
    }
  }
  
  resources.changes.watch = function(channel_id, callback_address, token, ttl, params, cb) {
    var body = {
      id: channel_id,
      type: "web_hook",
      address: callback_address,
      token:token,
      params:{
        ttl: ttl
      }
    }
    var p = extract_params(body, params, cb);
    var req = make_request('POST', base_uri + '/changes/watch', p);
    return refresh_on_401(req, p.cb);
  }

  return resources;
}

module.exports.auth = function(clientId, clientSecret) {
  client_id = clientId;
  client_secret = clientSecret;
}
