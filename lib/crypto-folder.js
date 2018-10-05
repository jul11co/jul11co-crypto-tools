// lib/crypto-folder.js

var fs = require('fs');
var path = require('path');

var fse = require('fs-extra');

var utils = require('./utils');
var cryptor = require('./cryptor');
var crypto_mount = require('./crypto-mount');

var CryptoFolder = function(folder_path, encrypt_key) {
  this._path = folder_path;
  this._enc_key = encrypt_key;
  this._loaded = false;
  this._entries_map = {};
}

CryptoFolder.prototype.load = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (self._loaded) {
    return done();
  }

  fse.ensureDirSync(self._path);

  if (options.read_only) self._read_only = true;
  self._tmp_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools', 'caches', utils.md5Hash(self._path));

  self._crypto_index = new cryptor.CryptoIndex(
    path.join(self._path, 'INDEX'), 
    self._enc_key, 
    {
      debug: options.debug,
      obfuscate: options.obfuscate,
      read_only: options.read_only
    }
  );

  self._crypto_index.load(function(err) {
    if (err) {
      console.log('Load crypto index failed!');
      // console.log(err);
      if (err.message.indexOf('bad decrypt')!=-1) {
        err.message = 'Wrong passphrase';
      }
    } else {
      self._loaded = true;
    }

    done(err);
  });
}

CryptoFolder.prototype.isLoaded = function() {
  return this._loaded;
}

CryptoFolder.prototype.unload = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (self._loaded && self._crypto_index) {
    self._crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index failed!');
        // console.log(err);
      } else {
        self._crypto_index = null;
        self._loaded = false;
      }
      
      done(err);
    });
  } else {
    done();
  }
}

CryptoFolder.prototype.encrypt = function(INPUT_DIR, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.encrypt(INPUT_DIR, options, done);
    });
  }

  if (options.files_map && utils.fileExists(options.files_map)) {
    console.log('Files map:', options.files_map);
    options.encrypt_files_map = utils.loadFromJsonFile(options.files_map);
  }

  cryptor.encryptDir(INPUT_DIR, self._path, self._enc_key, self._crypto_index, options, function(err, result) {
    done(err, result);
  });
}

CryptoFolder.prototype.decrypt = function(OUTPUT_DIR, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.decrypt(OUTPUT_DIR, options, done);
    });
  }

  fse.ensureDirSync(OUTPUT_DIR);

  cryptor.decryptDir(self._path, OUTPUT_DIR, self._enc_key, self._crypto_index, options, function(err, result) {
    done(err, result);
  });
}

CryptoFolder.prototype.remove = function(entries, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.remove(entries, options, done);
    });
  }

  cryptor.removeFiles(self._path, entries, self._enc_key, self._crypto_index, options, function(err, result) {
    return done(err, result)
  });
}

CryptoFolder.prototype.list = function(options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.list(options, done);
    });
  }

  var count = 0;
  var files = [];
  var total_size = 0;
  var largest_size = 0;
  var largest_file = {};

  // print file list from INDEX
  for (var file_id in self._crypto_index.map()) {
    var file_info = self._crypto_index.get(file_id);
    var will_list = true;

    if (options.list_entries) {
      will_list = options.list_entries.some(function(entry) {
        return (file_info.p.indexOf(entry) == 0);
      });
    }

    if (will_list) {
      count++;
      files.push(file_info);

      if (typeof options.onFileInfo == 'function') {
        options.onFileInfo(file_info, count);
      }

      total_size += file_info.s;

      if (file_info.s > largest_size) {
        largest_size = file_info.s;
        largest_file = {path: file_info.p, size: file_info.s};
      }
    }
  }

  return done(null, {
    count: count,
    files: files,
    total_size: total_size,
    largest_size: largest_size,
    largest_file: largest_file
  });
}

var getParentDirs = function(_path, opts) {
  opts = opts || {};

  var parents = [];
  var parent = path.dirname(_path);
  
  if (opts.trailing_slash) parent = parent + '/';
  
  if (parent && parent != '' && parent != '.' && parent != './') {
    var _parents = getParentDirs(parent, opts);
    if (_parents.length) parents = parents.concat(_parents);
    parents.push(parent);
  }
  
  return parents;
}


CryptoFolder.prototype.listFolder = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  var result = {
    entries: [],
    totalSize: 0
  }

  for (var file_id in self._crypto_index.map()) {
    var file_info = self._crypto_index.get(file_id);
    var entry = {
      type: 'file',
      path: file_info.p,
      size: file_info.s,
      mode: file_info.m,
      atime: file_info.at,
      mtime: file_info.mt,
      ctime: file_info.ct,
      birthtime: file_info.bt,
      encrypted_path: file_info.ep,
      encrypted_time: file_info.et
    };
    
    self._entries_map[entry.path] = entry;

    // add entries for parent dirs (if not added)
    var dirs = getParentDirs(entry.path);
    if (dirs.length) {
      dirs.forEach(function(dir_relpath) {
        if (!self._entries_map[dir_relpath]) {
          self._entries_map[dir_relpath] = {
            type: 'directory',
            path: dir_relpath,
            size: 0,
            mtime: entry.mtime
          }
        } else if (self._entries_map[dir_relpath].mtime < entry.ctime) {
          self._entries_map[dir_relpath].mtime = entry.ctime;
        }
      });
    }
  }

  for (var entry_path in self._entries_map) {
    var entry = self._entries_map[entry_path];
    result.totalSize += entry.size;
    result.entries.push(entry);
  }

  return callback(null, result);
}

CryptoFolder.prototype.removeEntry = function(fpath, opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  if (!self._entries_map[fpath] || !self._entries_map[fpath].encrypted_path) {
    return callback(new Error('Entry not found: ' + fpath));
  }
  if (self._read_only) {
    return callback(new Error('Cryptofolder is read only.'));
  }

  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  // 1. Remove encrypted file
  fse.remove(encrypted_file_abs_path, function(err) {
    if (err) {
      console.log('Remove file failed:', encrypted_file_abs_path);
      return callback(err);
    }

    // 2. Remove file from entries map and crypto index
    self._crypto_index.remove(utils.md5Hash(fpath));
    delete self._entries_map[fpath];

    callback();
  });
}

CryptoFolder.prototype.getEntry = function(fpath, output_dir, opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  if (!self._entries_map[fpath] || !self._entries_map[fpath].encrypted_path) {
    return callback(new Error('Entry not found: ' + fpath));
  }
  
  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  // console.log('getEntry:', bytes(entry.size), fpath);

  var decrypted_file_abs_path = path.join(output_dir, entry.path);
  fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

  var decrypt_opts = {
    obfuscate: self._crypto_index.obfuscate()
  };

  cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, self._enc_key, decrypt_opts, function(err) {
    if (err) {
      console.log('Decrypt file failed!', encrypted_file_abs_path);
      return callback(err);
    }
    if (!utils.fileExists(decrypted_file_abs_path)) {
      return callback(new Error('File not decrypted:', encrypted_file_abs_path));
    }

    var entry_mtime = new Date(entry.mtime).getTime()/1000;
    try {
      fs.utimesSync(decrypted_file_abs_path, new Date(), entry_mtime);
    } catch(e) {
      console.log(e);
    }

    return callback();
  });
}

CryptoFolder.prototype.getEntryDataBuffer = function(fpath, offset, size, opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  if (!self._entries_map[fpath] || !self._entries_map[fpath].encrypted_path) {
    return callback(new Error('Entry not found: ' + fpath));
  }
  
  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  // console.log('getEntryDataBuffer:', bytes(entry.size), fpath);

  var decrypt_opts = {
    obfuscate: self._crypto_index.obfuscate(),
    debug: opts.debug
  };

  cryptor.decryptFilePart(encrypted_file_abs_path, offset, size, self._enc_key, decrypt_opts, function(err, buf) {
    if (err || !buf) {
      console.log('Decrypt file part failed!', encrypted_file_abs_path);
      return callback(err);
    }

    return callback(null, buf);
  });
}

CryptoFolder.prototype.browse = function(options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.browse(options, done);
    });
  }

  // fse.emptyDirSync(self._tmp_dir);

  var DECRYPTED_TMP_DIR = path.join(self._tmp_dir, '_DECRYPTED');

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
  });

  var crypto_source = {
    path: self._path,
    read_only: self._read_only,
    listEntry: self.listFolder.bind(self),
    getEntry: self.getEntry.bind(self),
    // getEntryDataBuffer: self.getEntryDataBuffer.bind(self),
  };

  if (!crypto_source._read_only) {
    crypto_source.removeEntry = self.removeEntry.bind(self);
  }

  require('./crypto-browser')(crypto_source, DECRYPTED_TMP_DIR, options, done);
}

///

CryptoFolder.prototype.mount = function(MOUNT_POINT, options, done) {

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.mount(MOUNT_POINT, options, done);
    });
  }

  // fse.emptyDirSync(self._tmp_dir);

  var DECRYPTED_TMP_DIR = path.join(self._tmp_dir, '_DECRYPTED');
  // options.tmp_dir = DECRYPTED_TMP_DIR;

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
  });

  if (!utils.directoryExists(MOUNT_POINT)) {
    fse.ensureDirSync(MOUNT_POINT);
  }

  var crypto_source = {
    path: self._path,
    read_only: self._read_only,
    list: self.listFolder.bind(self),
    getEntry: self.getEntry.bind(self),
    getEntryDataBuffer: self.getEntryDataBuffer.bind(self),
  };

  if (!crypto_source._read_only) {
    crypto_source.removeEntry = self.removeEntry.bind(self);
  }

  var mount_point = new crypto_mount.MountPoint(crypto_source, MOUNT_POINT, DECRYPTED_TMP_DIR, options);
  mount_point.mount(function(err) {
    if (err) {
      return done(err);
    }
    return done(null, mount_point);
  });
}

module.exports = CryptoFolder;

