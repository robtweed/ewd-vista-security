/*

 ----------------------------------------------------------------------------
 | ewd-vista-security.js:                                                   |
 |  EWD.js REST Interface for VistA: Security / Authentication Layer        |
 |                                                                          |
 | Copyright (c) 2016 M/Gateway Developments Ltd,                           |
 | Reigate, Surrey UK.                                                      |
 | All rights reserved.                                                     |
 |                                                                          |
 | http://www.mgateway.com                                                  |
 | Email: rtweed@mgateway.com                                               |
 |                                                                          |
 |                                                                          |
 | Licensed under the Apache License, Version 2.0 (the "License");          |
 | you may not use this file except in compliance with the License.         |
 | You may obtain a copy of the License at                                  |
 |                                                                          |
 |     http://www.apache.org/licenses/LICENSE-2.0                           |
 |                                                                          |
 | Unless required by applicable law or agreed to in writing, software      |
 | distributed under the License is distributed on an "AS IS" BASIS,        |
 | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
 | See the License for the specific language governing permissions and      |
 |  limitations under the License.                                          |
 ----------------------------------------------------------------------------

  25 January 2016

*/

var vistaRPC = require('ewd-vista-rpc');

// Crypto functions

var crypto = require('crypto');

function avEncrypt(ac, vc, key, iv) {
  var text = 'accessCode:' + ac + ';verifyCode:' + vc;
  var textBuf = new Buffer(text); 
  var algorithm1 = 'aes-256-cbc';
  var cipher = crypto.createCipheriv(algorithm1, key, iv.toString());
  var crypted = cipher.update(textBuf,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}

var avDecrypt = function(encrypted, key, iv) {
  try {
    var algorithm = 'aes-256-cbc';
    var decipher = crypto.createDecipheriv(algorithm, key, iv.toString());
    var dec = decipher.update(encrypted, 'hex', 'utf8');
    dec += decipher.final('utf8');
    var str = dec.split('accessCode:')[1];
    var pieces = str.split(';verifyCode:');
    return {
      accessCode: pieces[0],
      verifyCode: pieces[1]
    };
  }
  catch(err) {
    return {
      error: 'Invalid credentials value'
    };    
  }
}

var errorResponse = function(error, statusCode) {
  var message = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found'
  }
  return {
    error: {
      text: error,
      statusCode: statusCode,
      statusMessage: message[statusCode] || 'Bad Request'
    }
  }; 
};

module.exports = {

  errorResponse: errorResponse,

  avEncrypt: avEncrypt,
    
  authenticate: function(ewd) {
    var statusCode = 401;
    token = ewd.headers.authorization;
    if (!token) {
      // no token supplied
      return errorResponse('Failed authentication (1)', statusCode);
    }
    else if (token === '') {
      // token supplied was empty string
      return errorResponse('Failed authentication (2)', statusCode);
    }
    else {
      var session = ewd.util.getSession(token);
      if (session === '') {
        // token wasn't recognised or session timed out
        console.log('**** failed authentication - token = ' + token);
        var xsessid = ewd.util.getSessid(token);
        console.log('  sessid filed against this token: ' + xsessid);
        if (xsessid !== '') {
          var xnode = {global: ewd.map.global.session, subscripts: ['session', xsessid, 'ewd_sessionExpiry']}; 
          var xexpiry = +ewd.db.get(xnode).data;
          console.log('  expiry = ' + xexpiry);
          console.log('  now = ' + Math.floor(new Date().getTime()/1000));
        }
        console.log('***********');
        return errorResponse('Failed authentication (3)', statusCode);
      }
      else {
        ewd.util.updateSessionExpiry({
          sessid: session.$('ewd_sessid')._value
        });
        return {
          ok: true,
          session: session
        }
      }
    }
  },

  initiate: function(appName, ewd) {
    var session = ewd.util.createNewSession(appName, 300);
    var token = session.$('ewd_token')._value;
    var key;
    var iv;
    if (ewdChild.Custom && ewdChild.Custom.encryptAVCode) {
      key = ewd.util.createToken().replace(/-/g, '');
      var cipher = session.$('cipher');
      cipher.$('key')._value = key;
      var low = 1000000000000000;
      var high = 9999999999999999;
      iv = Math.floor(Math.random() * (high - low) + low);
      cipher.$('iv')._value = iv;
    }
    var params = {
      rpcName: 'XUS SIGNON SETUP'
    };
    var response = vistaRPC.run(params, session, ewd);
    return {
      Authorization: token,
      key: key,
      iv: iv
    };
  },

  login: function(ewd, session) {
    var sessid = session.sessid;
    var errorStatusCode = 400;
    var credentials;
    var cipher;
    if (ewdChild.Custom && ewdChild.Custom.encryptAVCode) {
      cipher = session.$('cipher');
      var key = cipher.$('key')._value;
      if (key === '') {
        ewd.util.deleteSession(sessid);
        return errorResponse('No key available', errorStatusCode);
      }
      var iv = cipher.$('iv')._value;
      if (iv === '') {
        ewd.util.deleteSession(sessid);
        return errorResponse('No initialization vector available', errorStatusCode);
      }
      credentials = avDecrypt(ewd.query.credentials, key, iv);
      //console.log('credentials: ' + JSON.stringify(credentials));
      if (credentials.error) {
        ewd.util.deleteSession(sessid);
        return errorResponse(credentials.error, errorStatusCode);
      }
    }
    else {
      // no encryption of access code & verify code needed
      credentials = {
        accessCode: ewd.query.accessCode,
        verifyCode: ewd.query.verifyCode
      };
    }
    if (!credentials.accessCode || credentials.accessCode === '') {
      ewd.util.deleteSession(sessid);
      return errorResponse('Missing Access Code', errorStatusCode);
    }
    if (!credentials.verifyCode || credentials.verifyCode === '') {
      ewd.util.deleteSession(sessid);
      return errorResponse('Missing Verify Code', errorStatusCode);
    }

    var params = {
      rpcName: 'XUS AV CODE',
      rpcArgs: [{
        type: 'LITERAL',
        value: credentials.accessCode + ';' + credentials.verifyCode
      }],
    };
    var results = vistaRPC.run(params, session, ewd);

    var values = results.value;
    var duz = values[0];
    var error = values[3]
    if (duz === '0' && error !== '') {
      // Failed to log in - invalid access code / verify code
      ewd.util.deleteSession(sessid);
      return errorResponse(error, 401);
    }
    else {
      // logged in successfully
      // reset timeout to standard 1 hour
      session.$('ewd_sessionTimeout')._value = 3600;
      if (typeof cipher !== 'undefined') cipher._delete();
      var greeting = values[7];
      var pieces = greeting.split(' ');
      pieces = pieces.splice(2, pieces.length);
      var displayName = pieces.join(' ');
      return {
        displayName: displayName,
        greeting: greeting,
        lastSignon: values[8],
        messages: values.splice(8, values.length)
      };
    }
    /*
       results will look like this for an error:

      results: {"type":"ARRAY","value":[
        "0",
        "0",
        "0",
        "Not a valid ACCESS CODE/VERIFY CODE pair.",
        "0",
        "0"
      ]}

       and this for success

      results: {"type":"ARRAY","value":[
        "1",
        "0",
        "0",
        "",
        "0",
        "0",
        "",
        "Good afternoon PROGRAMMER,ONE",
        "     You last signed on today at 14:43",
        "You have 98 new messages. (98 in the 'IN' basket)",
        "",
        "Enter '^NML' to read your new messages.",
        "You've got PRIORITY mail!"
      ]}
     */
  },
};
