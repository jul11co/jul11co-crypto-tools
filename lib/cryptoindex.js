// lib/cryptoindex.js

var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var utils = require('./utils');
var cryptor = require('./cryptor');

var CryptoIndex = function(index_path, enc_key, options) {
  if (typeof index_path == 'object') {
    this._options = index_path;
    this._path = this._options['path'] || this._options['index_path'];
    this._encrypt_key = this._options['encrypt_key'];
  } else {
    this._path = index_path;
  }
  if (typeof enc_key == 'object') {
    this._options = enc_key;
    this._encrypt_key = this._options['encrypt_key'];
  } else {
    this._encrypt_key = enc_key;
  }

  this._loaded = false;

  this._options = this._options || options || {};
  this._files_map = {};
  this._verify_string = 'jul11co-crypto-index';

  this._obfuscate = false;

  var obfuscate_file = path.join(path.dirname(this._path), 'OBFUSCATE');
  if (utils.fileExists(obfuscate_file)) {
    try {
      var obfuscate = fs.readFileSync(obfuscate_file, {encoding: 'utf8'});
      if (obfuscate == 'true') {
        this._obfuscate = true;
      }
    } catch(e) {
      console.log(e);
    }
  } else if (this._options['obfuscate']) {
    this._obfuscate = true;
    fs.writeFileSync(obfuscate_file, this._obfuscate, {encoding: 'utf8'});
  }

  var version_file = path.join(path.dirname(this._path), 'VERSION');
  if (utils.fileExists(version_file)) {
    try {
      this._version = fs.readFileSync(version_file, {encoding: 'utf8'});
    } catch(e) {
      console.log(e);
    }
  } else {
    this._version = cryptor.VERSION;
    fs.writeFileSync(version_file, this._version, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype.obfuscate = function() {
  return this._obfuscate;
}

CryptoIndex.prototype.version = function() {
  return this._version;
}

CryptoIndex.prototype._encryptIndexFile = function(done) {
  var self = this;
  var tmp_file = path.join(path.dirname(self._path), 
    (self._options.debug) ? 'index-debug-unload.json' : 'index.json');
  utils.saveToJsonFile(self._files_map, tmp_file);
  self._files_map = {};
  cryptor.encryptFile(tmp_file, self._path, self._encrypt_key, function(err) {
    if (err) {
      return done(err);
    } else {
      if (!self._options.debug) fse.removeSync(tmp_file);
      done();
    }
  });
}

CryptoIndex.prototype._decryptIndexFile = function(done) {
  var self = this;
  var tmp_file = path.join(path.dirname(self._path), 
    (self._options.debug) ? 'index-debug-load.json' :'index.json');
  cryptor.decryptFile(self._path, tmp_file, self._encrypt_key, function(err) {
    if (err) {
      return done(err);
    } else {
      self._files_map = utils.loadFromJsonFile(tmp_file);
      if (!self._options.debug) fse.removeSync(tmp_file);
      done();
    }
  });
}

CryptoIndex.prototype.verify = function(done) {
  var self = this;
  var verify_file = path.join(path.dirname(self._path), 'VERIFY');
  if (utils.fileExists(verify_file)) {
    try {
      var encrypted_verify_string = fs.readFileSync(verify_file, {encoding: 'utf8'});
      var verify_string = cryptor.decryptString(encrypted_verify_string, self._encrypt_key);
      if (self._verify_string != verify_string) {
        return done(new Error('Invalid encryption key!'));
      }
      return done();
    } catch(e) {
      console.log('Verify failed! ' + e.message);
      return done(e);
    }
  } else {
    done();
  }
}

CryptoIndex.prototype.load = function(done) {
  var self = this;
  self.verify(function(err) {
    if (err) return done(err);
    if (utils.fileExists(self._path)) {
      // console.log('Load:', self._path);
      self._decryptIndexFile(function(err) {
        if (err) return done(err);
        self._loaded = true;
        done();
      });
    } else {
      self._loaded = true;
      self._files_map = {};
      done();
    }
  });
}

CryptoIndex.prototype.loaded = function(done) {
  return this._loaded;
}

CryptoIndex.prototype.unload = function(done) {
  var self = this;
  if (self._options.read_only) {
    self._files_map = {};
    return done();
  }
  var verify_file = path.join(path.dirname(self._path), 'VERIFY');
  if (!utils.fileExists(verify_file)) {
    var encrypted_verify_string = cryptor.encryptString(this._verify_string, this._encrypt_key);
    fs.writeFileSync(verify_file, encrypted_verify_string, {encoding: 'utf8'});
  }
  // console.log('Unload:', self._path);
  self._encryptIndexFile(function(err) {
    if (err) return done(err);
    self._loaded = false;
    done();
  });
}

CryptoIndex.prototype.map = function() {
  return this._files_map;
}

CryptoIndex.prototype.put = function(key, value) {
  this._files_map[key] = value;
}

CryptoIndex.prototype.get = function(key) {
  return this._files_map[key];
}

CryptoIndex.prototype.hasKey = function(key) {
  return (typeof this._files_map[key] != 'undefined');
}

CryptoIndex.prototype.remove = function(key) {
  delete this._files_map[key];
}

module.exports = CryptoIndex;

