// lib/crypto-index.js

var fs = require('fs');
var path = require('path');
var util = require('util');
var crypto = require('crypto');

var async = require('async');
var fse = require('fs-extra');
var chalk = require('chalk');
var bytes = require('bytes');

var sqlite3 = require('sqlite3');
var semver = require('semver');

var utils = require('./utils');
var cryptor = require('./cryptor');

var crypto_config_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools');
var crypto_tmp_dir = path.join(crypto_config_dir, 'tmp');
// fse.ensureDirSync(crypto_tmp_dir);

var CryptoIndex = function(index_path, enc_key, options) {
  if (typeof index_path == 'object') {
    options = index_path;
    this._path = options['path'] || options['index_path'];
    this._encrypt_key = options['encrypt_key'];
  } else {
    this._path = index_path;
  }
  if (typeof enc_key == 'object') {
    options = enc_key;
    this._encrypt_key = options['encrypt_key'];
  } else {
    this._encrypt_key = enc_key;
  }

  this._tmp_dir = path.join(crypto_tmp_dir, utils.md5Hash(this._path));

  this._loaded = false;
  
  this._files_map = {};
  this._folders_map = {};

  this._verify_string = options.verify_string || 'jul11co-crypto-index';
  this._obfuscate = options.obfuscate;

  this._debug = options.debug;
  this._read_only = options.read_only;

  this._version = cryptor.VERSION;
}

CryptoIndex.prototype.version = function() {
  return this._version;
}
CryptoIndex.prototype.getVersion = function() {
  return this._version;
}

CryptoIndex.prototype._loadVersionFile = function() {
  var version_file = path.join(path.dirname(this._path), 'VERSION');
  if (utils.fileExists(version_file)) {
    try {
      this._version = fs.readFileSync(version_file, {encoding: 'utf8'});
      if (!this._version) this._version = cryptor.VERSION;
    } catch(e) {
      console.log(e);
    }
  }
}

CryptoIndex.prototype._writeVersionFile = function() {
  var version_file = path.join(path.dirname(this._path), 'VERSION');
  if (!utils.fileExists(version_file)) { // Do not alter existing VERSION file
    fs.writeFileSync(version_file, this._version, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype.obfuscate = function() {
  return this._obfuscate;
}
CryptoIndex.prototype.isObfuscated = function() {
  return this._obfuscate;
}

CryptoIndex.prototype._loadObfuscateFile = function() {
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
  }
}

CryptoIndex.prototype._writeObfuscateFile = function() {
  var obfuscate_file = path.join(path.dirname(this._path), 'OBFUSCATE');
  if (!utils.fileExists(obfuscate_file) && this._obfuscate) { // Do not alter existing OBFUSCATE file
    fs.writeFileSync(obfuscate_file, this._obfuscate, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype.getVerifyString = function() {
  return this._verify_string;
}

CryptoIndex.prototype._loadVerifyFile = function() {
  var verify_file = path.join(path.dirname(this._path), 'VERIFY');
  if (utils.fileExists(verify_file)) {
    this._verify_file_exists = true;
    this._encrypted_verify_string = fs.readFileSync(verify_file, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype._writeVerifyFile = function() {
  var verify_file = path.join(path.dirname(this._path), 'VERIFY');
  if (!utils.fileExists(verify_file)) { // Do not alter existing VERIFY file
    var encrypted_verify_string = cryptor.encryptString(this._verify_string, this._encrypt_key);
    fs.writeFileSync(verify_file, encrypted_verify_string, {encoding: 'utf8'});
  }
}

CryptoIndex.prototype._loadJSONIndexFile = function(tmp_index_file, done) {
  var self = this;

  var tmp_decrypted_file_name = (self._debug) ? 'index-debug-load.json' : 'index.json';
  var tmp_decrypted_index_file = path.join(self._tmp_dir, tmp_decrypted_file_name);

  if (utils.fileExists(self._path)) {
    fse.copy(self._path, tmp_index_file, {
      overwrite: true,
      preserveTimestamps: true
    }, function(err) {
      if (err) {
        return done(err);
      }

      cryptor.decryptFile(tmp_index_file, tmp_decrypted_index_file, self._encrypt_key, function(err) {
        if (err) {
          return done(err);
        }

        self._files_map = utils.loadFromJsonFile(tmp_decrypted_index_file);
        if (!self._debug) fse.removeSync(tmp_decrypted_index_file);

        return done();
      });
    });
  } else {
    self._files_map = {};
    return done();
  }
}

CryptoIndex.prototype._loadSQLite3IndexFile = function(tmp_index_file, done) {
  var self = this;

  var tmp_decrypted_file_name = (self._debug) ? 'index-debug.sqlite3' : 'index.sqlite3';
  var tmp_decrypted_index_file = path.join(self._tmp_dir, tmp_decrypted_file_name);

  var __loadSQLite3IndexFile = function() {
    self._indexdb = null;
    self._indexdb_file = tmp_decrypted_index_file;

    self._loadIndexDb(function(err) {
      if (err) {
        return done(err);
      }

      return done();
    });
  }

  if (utils.fileExists(self._path)) {
    fse.copy(self._path, tmp_index_file, {
      overwrite: true,
      preserveTimestamps: true
    }, function(err) {
      if (err) {
        return done(err);
      }

      cryptor.decryptFile(tmp_index_file, tmp_decrypted_index_file, self._encrypt_key, function(err) {
        if (err) {
          return done(err);
        }

        return __loadSQLite3IndexFile();
      });
    });
  } else {
    return __loadSQLite3IndexFile();
  }
}

CryptoIndex.prototype._loadIndexFile = function(done) {
  var self = this;
  if (self._debug) console.log('CryptoIndex:', '_loadIndexFile:', self._path);

  var time = (new Date()).getTime();
  var tmp_index_file = path.join(self._tmp_dir, 'INDEX-'+time);

  if (semver.lt(self._version, '0.0.5')) { // version < 0.0.5
    // Index in JSON file
    return self._loadJSONIndexFile(tmp_index_file, done);
  } else { // version >= 0.0.5
    // Index in SQLite3 file
    return self._loadSQLite3IndexFile(tmp_index_file, done);
  }
}

CryptoIndex.prototype._unloadJSONIndexFile = function(tmp_index_file, done) {
  var self = this;

  var tmp_uncrypted_file_name = (self._debug) ? 'index-debug-unload.json' : 'index.json';
  var tmp_uncrypted_file = path.join(self._tmp_dir, tmp_uncrypted_file_name);

  utils.saveToJsonFile(self._files_map, tmp_uncrypted_file);

  cryptor.encryptFile(tmp_uncrypted_file, tmp_index_file, self._encrypt_key, function(err) {
    if (err) {
      return done(err);
    }

    fse.copy(tmp_index_file, self._path, {
      overwrite: true,
      preserveTimestamps: true
    }, function(err) {
      if (!self._debug) fse.removeSync(tmp_uncrypted_file);
      return done();
    });
  });
}

CryptoIndex.prototype._unloadSQLite3IndexFile = function(tmp_index_file, done) {
  var self = this;

  var tmp_uncrypted_file_name = (self._debug) ? 'index-debug.sqlite3' : 'index.sqlite3';
  var tmp_uncrypted_file = path.join(self._tmp_dir, tmp_uncrypted_file_name);

  self._unloadIndexDb(function(err) {
    if (err) {
      return done(err);
    }

    cryptor.encryptFile(tmp_uncrypted_file, tmp_index_file, self._encrypt_key, function(err) {
      if (err) {
        return done(err);
      }

      fse.copy(tmp_index_file, self._path, {
        overwrite: true,
        preserveTimestamps: true
      }, function(err) {
        if (!self._debug) fse.removeSync(tmp_uncrypted_file);
        return done();
      });
    });
  });
}

CryptoIndex.prototype._unloadIndexFile = function(done) {
  var self = this;
  if (self._debug) console.log('CryptoIndex:', '_unloadIndexFile:', self._path);

  var tmp_index_file = path.join(self._tmp_dir, 'INDEX');

  if (semver.lt(self._version, '0.0.5')) { // version < 0.0.5
    // Index in JSON file
    return self._unloadJSONIndexFile(tmp_index_file, done);
  } else { // version >= 0.0.5
    // Index in SQLite3 file
    return self._unloadSQLite3IndexFile(tmp_index_file, done);
  }
}

CryptoIndex.prototype.verify = function(done) {
  var self = this;

  self._loadVerifyFile();

  if (self._encrypted_verify_string) {
    try {
      var verify_string = cryptor.decryptString(self._encrypted_verify_string, self._encrypt_key);
      if (self._verify_string != verify_string) {
        return done(new Error('Invalid encryption key!'));
      }
    } catch(e) {
      // console.log('Verify failed! ' + e.message);
      return done(e);
    }
  } else if (this._verify_file_exists) {
    return done(new Error('Missing verify string, unable to verify encryption key!'));
  }
  
  return done();
}

CryptoIndex.prototype.load = function(done) {
  var self = this;

  if (self._loaded) {
    return done();
  }

  fse.ensureDirSync(this._tmp_dir);

  self._loadVersionFile();
  self._loadObfuscateFile();

  self._files_map = {};

  self.verify(function(err) {
    if (err) return done(err);

    self._loadIndexFile(function(err) {
      if (err) return done(err);
      self._loaded = true;
      return done();
    });
  });
}

CryptoIndex.prototype.loaded = function(done) {
  return this._loaded;
}
CryptoIndex.prototype.isLoaded = function(done) {
  return this._loaded;
}

CryptoIndex.prototype.unload = function(done) {
  var self = this;

  if (!self._loaded) {
    return done();
  }

  if (self._read_only) {
    self._loaded = false;
    self._files_map = {}; // clear files map
    return done();
  }

  self._writeVersionFile();
  self._writeObfuscateFile();

  self._writeVerifyFile();

  self._unloadIndexFile(function(err) {
    if (err) return done(err);
    self._loaded = false;
    self._files_map = {}; // clear files map
    return done();
  });
}

// DO NOT USE
// CryptoIndex.prototype.map = function() {
//   return this._files_map;
// }

// DO NOT USE
// CryptoIndex.prototype.put = function(key, value) {
//   this._files_map[key] = value;
// }

// DO NOT USE
// CryptoIndex.prototype.get = function(key) {
//   return this._files_map[key];
// }

// DO NOT USE
// CryptoIndex.prototype.hasKey = function(key) {
//   return (typeof this._files_map[key] != 'undefined');
// }

// DO NOT USE
// CryptoIndex.prototype.remove = function(key) {
//   delete this._files_map[key];
// }

CryptoIndex.prototype.putFile = function(file_path, file_info, callback) {
  var file_hash = utils.md5Hash(file_path);
  var file_exists = !(typeof this._files_map[file_hash] == 'undefined');

  if (!file_info.path) file_info.path = file_path;
  if (!file_info.hash) file_info.hash = file_hash;

  this._files_map[file_hash] = {
    p: file_info.path,                  // path
    s: file_info.size,                  // size
    m: file_info.mode,                  // mode
    at: file_info.atime,                // atime
    mt: file_info.mtime,                // mtime
    ct: file_info.ctime,                // ctime
    bt: file_info.birthtime,            // birthtime
    ep: file_info.encrypted_path,       // encrypted file path (relative)
    et: file_info.encrypted_time,       // encrypted time
  };

  if (this._indexdb) {
    if (file_exists) {
      return this._dbUpdateFile(file_path, file_info, callback);
    } else {
      return this._dbInsertFile(file_info, callback);
    }
  }

  return callback();
}

CryptoIndex.prototype.getFile = function(file_path, callback) {
  var file_hash = utils.md5Hash(file_path);

  if (this._files_map[file_hash]) {
    var entry = this._files_map[file_hash];
    var file_info = {
      hash: file_hash,                      
      path: entry.p,                        // path
      name: path.basename(entry.p),
      size: entry.s,                        // size
      mode: entry.m,                        // mode
      atime: entry.at,                      // atime
      mtime: entry.mt,                      // mtime
      ctime: entry.ct,                      // ctime
      birthtime: entry.bt,                  // birthtime
      encrypted_path: entry.ep,             // encrypted file path (relative)
      encrypted_time: entry.et              // encrypted time
    };

    return callback(null, file_info);
  } else if (this._indexdb) {
    var self = this;

    self._dbGetFile(file_path, function(err, file_info) {
      if (err) return callback(err);
      if (file_info) {
        file_info.path = file_info.path || file_path;
        file_info.hash = file_info.hash || file_hash;

        self._files_map[file_hash] = {
          p: file_info.path,                  // path
          s: file_info.size,                  // size
          m: file_info.mode,                  // mode
          at: file_info.atime,                // atime
          mt: file_info.mtime,                // mtime
          ct: file_info.ctime,                // ctime
          bt: file_info.birthtime,            // birthtime
          ep: file_info.encrypted_path,       // encrypted file path (relative)
          et: file_info.encrypted_time,       // encrypted time
        };
      }
      return callback(null, file_info);
    });
  } else {
    return callback(null, null);
  }
}

CryptoIndex.prototype.removeFile = function(file_path, callback) {
  var file_hash = utils.md5Hash(file_path);

  if (this._files_map[file_hash]) {
    delete this._files_map[file_hash];
  }

  if (this._indexdb) {
    return this._dbRemoveFile(file_path, function(err) {
      if (err) return callback(err);
      return callback();
    });
  }

  return callback();
}

CryptoIndex.prototype.getFileList = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  if (!self._indexdb) { // version < 0.0.5
    var files = [];
    for (var file_hash in self._files_map) {
      var entry = self._files_map[file_hash];
      var file_info = {
        hash: file_hash,
        path: entry.p,
        name: path.basename(entry.p),
        size: entry.s,
        mode: entry.m,
        atime: entry.at,
        mtime: entry.mt,
        ctime: entry.ct,
        birthtime: entry.bt,
        encrypted_path: entry.ep,
        encrypted_time: entry.et
      };
      files.push(file_info);
    }

    return callback(null, files);
  } else { // version >= 0.0.5
    // return callback(new Error('This function is not implemented.'));
    self._dbGetFiles(opts, function(err, files) {
      return callback(err, files);
    });
  }
}

////

// SQLite3 index file

var escapeSQL = function(str) {
  if (!str || str == '') return '';
  str = utils.replaceAll(str, "'", "''");
  return str;
}

var unescapeSQL = function(str) {
  if (!str || str == '') return '';
  str = utils.replaceAll(str, "''", "'");
  return str;
}

CryptoIndex.prototype._loadIndexDb = function(done) {
  var self = this;

  if (self._debug) console.log('CryptoIndex:', '_loadIndexDb');

  self._indexdb = new sqlite3.Database(self._indexdb_file, function(err) {
    if (err) {
      console.log('CryptoIndex:','Open database failed!', self._indexdb_file);
      return done(err);
    }

    var create_folders_table_stm = 
      "CREATE TABLE IF NOT EXISTS folders(" +
        "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
        "path TEXT NOT NULL UNIQUE," +
        "name TEXT NOT NULL" +
      ");"
      ;

    var create_files_table_stm = 
      "CREATE TABLE IF NOT EXISTS files(" +
        "_id INTEGER PRIMARY KEY AUTOINCREMENT," +
        "folder INTEGER," +
        "name TEXT NOT NULL," +
        "hash TEXT NOT NULL," +
        "size INTEGER DEFAULT 0," +
        "mode INTEGER DEFAULT 0," +
        "mtime INTEGER DEFAULT 0," +
        "atime INTEGER DEFAULT 0," +
        "ctime INTEGER DEFAULT 0," +
        "birthtime INTEGER DEFAULT 0," +
        "encrypted_path TEXT," +
        "encrypted_time INTEGER DEFAULT 0," +
        "FOREIGN KEY(folder) REFERENCES folders(_id)" +
      ");"
      ;

    self._indexdb.run(create_files_table_stm, function(err) {
      if (err) {
        console.log('CryptoIndex:','Create table "files" failed!');
        return done(err);
      }

      self._indexdb.run(create_folders_table_stm, function(err) {
        if (err) {
          console.log('CryptoIndex:','Create table "folders" failed!');
        }
        return done(err);
      });
    });
  });
}

CryptoIndex.prototype._unloadIndexDb = function(done) {

  if (this._debug) console.log('CryptoIndex:', '_unloadIndexDb');

  if (this._indexdb) {
    this._indexdb.close();
    this._indexdb = null;
  }

  return done();
}

var folderFromRow = function(row) {
  if (!row) return {};
  
  var folder = {};

  for (var field in row) {
    var value = row[field];
    
    if (typeof value == 'string') {
      folder[field] = unescapeSQL(value);
    } else {
      folder[field] = value;
    }
  }

  return folder;
}

var fileFromRow = function(row) {
  if (!row) return {};
  
  var file = {};

  for (var field in row) {
    var value = row[field];

    if (['atime','mtime','ctime','birthtime','encrypted_time'].indexOf(field) != -1) {
      if (value != 0) {
        var date = new Date();
        date.setTime(value);
        file[field] = date;
      } else {
        file[field] = 0;
      }
    }
    else if (typeof value == 'string') {
      file[field] = unescapeSQL(value);
    } else {
      file[field] = value;
    }
  }

  return file;
}

CryptoIndex.prototype._dbGetFolder = function(folder_path, done) {
  if (this._folders_map[folder_path]) {
    return done(null, this._folders_map[folder_path]);
  }

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  var self = this;

  var query = "SELECT * FROM folders WHERE path = ?";
  self._indexdb.get(query, [escapeSQL(folder_path)], function(err, row) {
    if (err) {
      console.log('CryptoIndex:', 'Get folder failed!');
      return done(err);
    } else if (row) {
      // Return the folder info
      var folder = folderFromRow(row);
      self._folders_map[folder_path] = folder;
      return done(null, folder);
    } else {
      // Insert new folder
      self._indexdb.run("INSERT INTO folders (path,name) VALUES (?,?)", [
        escapeSQL(folder_path),
        escapeSQL(path.basename(folder_path))
      ],
      function(err) {
        if (err || !this.lastID) {
          console.log('CryptoIndex:', 'Insert folder failed!');
          return done(err);
        } else if (!this.lastID) {
          console.log('CryptoIndex:', 'Insert folder failed!');
          return done(new Error('lastID not found!'));
        }

        var folder = {
          _id: this.lastID,
          path: folder_path,
          name: path.basename(folder_path)
        };

        self._folders_map[folder_path] = folder;

        return done(null, folder);
      });
    }
  });
}

CryptoIndex.prototype._dbGetFiles = function(opts, done) {
  if (typeof opts == 'function') {
    done = opts;
    opts = {};
  }

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  if (opts.debug || this._debug) console.log('CryptoIndex:', '_dbGetFiles');

  // var query = "SELECT * FROM files";
  var query = 
    "SELECT files.*, folders.path AS folder_path " + 
    "FROM files " + 
    "INNER JOIN folders ON folders._id = files.folder"
    ;

  if (opts.sort) {
    for (var sort_field in opts.sort) {
      if (opts.sort[sort_field] == 1) {
        query += " ORDER BY " + sort_field + " ASC";
      } else {
        query += " ORDER BY " + sort_field + " DESC";
      }
    }
  }
  if (opts.limit) {
    query += " LIMIT " + opts.limit;
  }
  if (opts.skip) {
    query += " OFFSET " + opts.skip;
  }

  this._indexdb.all(query, function(err, rows) {
    if (err) {
      console.log('CryptoIndex:','Get files failed!');
      return done(err);
    } else if (rows && rows.length) {
      var files = rows.map(function(row) {
        var file_info = fileFromRow(row);
        if (file_info.folder_path) {
          file_info.path = path.join(file_info.folder_path, file_info.name);
        }
        return file_info;
      });
      return done(null, files);
    } else {
      return done(null, []);
    }
  });
}

CryptoIndex.prototype._dbInsertFile = function(file_info, opts, done) {
  if (typeof opts == 'function') {
    done = opts;
    opts = {};
  }

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  if (opts.debug || this._debug) console.log('CryptoIndex:', '_dbInsertFile', file_info.path);

  if (!file_info.hash) {
    file_info.hash = utils.md5Hash(file_info.path);
  }
  if (!file_info.name) {
    file_info.name = path.basename(file_info.path);
  }

  var field_names = [];
  var field_values = [];

  for (var field in file_info) {
    if (field == 'path') continue;

    field_names.push(field);

    var value = file_info[field];
    if (['atime','mtime','ctime','birthtime','encrypted_time'].indexOf(field) != -1) {
      if (value != 0) {
        var date = new Date(value);
        field_values.push(date.getTime());
      } else {
        field_values.push(0);
      }
    } else if (typeof value == 'string') {
      field_values.push(escapeSQL(value));
    } else {
      field_values.push(value);
    }
  }

  var field_placeholders = [];
  for (var i = 0; i < field_names.length; i++) {
    field_placeholders[i] = '?';
  }

  var self = this;

  var folder_path = path.dirname(file_info.path);
  self._dbGetFolder(folder_path, function(err, folder) {
    if (err) {
      console.log('CryptoIndex:', 'Get folder failed!');
      return done(err);
    }

    field_names.unshift('folder');
    field_placeholders.unshift('?');
    field_values.unshift(folder._id);

    var query = 
      "INSERT INTO files (" + field_names.join(',') + ") " +
      "VALUES (" + field_placeholders.join(',') + ")"
      ;

    self._indexdb.run(query, field_values, function(err) {
        if (err) {
          console.log('CryptoIndex:', 'Insert file failed!');
          return done(err);
        } else if (!this.lastID) {
          console.log('CryptoIndex:', 'Insert file failed!');
          return done(new Error('lastID not found!'));
        } else {
          return done(null, {_id: this.lastID});
        }
      });
  });
}

CryptoIndex.prototype._dbGetFile = function(file_path, done) {

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  var file_hash = utils.md5Hash(file_path);

  var query = "SELECT * FROM files WHERE hash = ?";
  this._indexdb.get(query, [file_hash], function(err, row) {
    if (err) {
      console.log('CryptoIndex:','Get file failed!');
      return done(err);
    } else if (row) {
      var file_info = fileFromRow(row);
      file_info.path = file_info.path || file_path;
      file_info.hash = file_info.hash || file_hash;

      return done(null, file_info);
    } else {
      return done();
    }
  });
}

CryptoIndex.prototype._dbGetFileById = function(file_id, done) {

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  var query = 
    "SELECT files.*, folders.path AS folder_path " + 
    "FROM files " + 
    "INNER JOIN folders ON folders._id = files.folder " + 
    "WHERE files._id = ?";
  
  this._indexdb.get(query, [file_id], function(err, row) {
    if (err) {
      console.log('CryptoIndex:','Get file failed!');
      return done(err);
    } else if (row) {
      var file_info = fileFromRow(row);
      if (file_info.folder_path) {
        file_info.path = path.join(file_info.folder_path, file_info.name);
      }

      return done(null, file_info);
    } else {
      return done();
    }
  });
}

CryptoIndex.prototype._dbUpdateFile = function(file_path, update_data, opts, done) {
  if (typeof opts == 'function') {
    done = opts;
    opts = {};
  }

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  if (opts.debug || this._debug) console.log('CryptoIndex:', '_dbUpdateFile', file_path);

  var self = this;

  var update_array = [];
  for (var field in update_data) {
    if (field == 'path') continue;

    var value = update_data[field];
    if (['atime','mtime','ctime','birthtime','encrypted_time'].indexOf(field) != -1) {
      if (value != 0) {
        update_array.push(field + " = " + (new Date(value).getTime()));
      } else {
        update_array.push(field + " = 0");
      }
    } else if (typeof value == 'string') {
      update_array.push(field + " = '" + escapeSQL(value) + "'");
    } else {
      update_array.push(field + " = " + value);
    }
  }

  var file_hash = utils.md5Hash(file_path);
  var folder_path = path.dirname(file_info.path);

  self._dbGetFolder(folder_path, function(err, folder) {
    if (err) {
      console.log('CryptoIndex:', 'Get folder failed!');
      return done(err);
    }

    // Append folder._id to UPDATE query
    update_array.unshift('folder = ' + folder._id);

    var query = "UPDATE files SET " + update_array.join(',') + " WHERE hash = ?" ;
    self._indexdb.run(query, [file_hash], function(err) {
      if (err) {
        console.log('CryptoIndex:', 'Update file failed!', file_path);
        return done(err);
      } else {
        return done(null);
      }
    });
  });
}

CryptoIndex.prototype._dbRemoveFile = function(file_path, opts, done) {
  if (typeof opts == 'function') {
    done = opts;
    opts = {};
  }

  if (!this._indexdb) {
    return done(new Error('Missing index db'));
  }

  if (opts.debug || this._debug) console.log('CryptoIndex:', '_dbRemoveFile', file_path);

  var file_hash = utils.md5Hash(file_path);

  var query = "DELETE FROM files WHERE hash = ?";
  this._indexdb.run(query, [file_hash], function(err) {
    if (err) {
      console.log('Delete file failed!', file_path);
    }
    return done(err, this.changes ? this.changes.length : 0);
  });
}

module.exports = CryptoIndex;

