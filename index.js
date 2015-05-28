/**
 * @module Auth
 * @author crossjs <liwenfu@crossjs.com>
 * @create 2015-04-14 13:54:53
 */

'use strict';

var Storage = require('nd-storage');
var Sha = require('nd-sha');
var datetime = require('nd-datetime');

var storage = new Storage();

function nonce() {
  function rnd(min, max) {
    var arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

    var range = max ? max - min : min,
      str = '',
      i,
      length = arr.length - 1;

    for (i = 0; i < range; i++) {
      str += arr[Math.round(Math.random() * length)];
    }

    return str;
  }

  return new Date().getTime() + ':' + rnd(8);
}

module.exports = {

  tokenKey: 'UC_TOKENS',

  tokens: null,

  isAuthed: function() {
    return !!this.getTokens();
  },

  getTokens: function(key) {
    var tokens = this.tokens;

    if (!tokens) {
      // 本地存储
      tokens = storage.get(this.tokenKey);
    }

    if (tokens) {
      // 失效判断
      if (datetime(tokens['expires_at']).toNumber() <= datetime().toNumber()) {
        tokens = null;
        this.setTokens(tokens);
      }
    }

    if (tokens) {
      this.tokens = tokens;
    }

    if (key && tokens) {
      return tokens[key];
    }

    return tokens;
  },

  /**
   * 设置或清除 tokens
   * @param {object} tokens token值
   */
  setTokens: function(tokens) {
    this.tokens = tokens;

    if (tokens === null) {
      storage.remove(this.tokenKey);
    } else {
      storage.set(this.tokenKey, tokens);
    }
  },

  _getAccessToken: function() {
    return this.getTokens('access_token');
  },

  _getMacContent: function(method, url, host) {
    return [this.nonce, method, url, host, ''].join('\n');
  },

  _getMac: function(method, url, host) {
    return new Sha(this._getMacContent(method, url, host), 'TEXT')
          .getHMAC(this.getTokens('mac_key'), 'TEXT', 'SHA-256', 'B64');
  },

  _getNonce: function() {
    this.nonce = nonce();
    return this.nonce;
  },

  getAuthentization: function(method, url, host) {
    return ['MAC id="' + this._getAccessToken() + '"',
            'nonce="' + this._getNonce() + '"',
            'mac="' + this._getMac(method, url, host) + '"'].join(',');
  }

};
