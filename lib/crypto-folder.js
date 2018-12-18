// lib/crypto-folder.js

var fs = require('fs');
var path = require('path');

var fse = require('fs-extra');
var df = require('node-df');

var utils = require('./utils');
var cryptor = require('./cryptor');
var crypto_mount = require('./crypto-mount');

var CryptoFolder = function(folder_path, encrypt_key, algorithm) {
  this._path = folder_path;
  this._enc_key = encrypt_key;
  this._algorithm = algorithm;
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

  if (options.read_only) self._read_only = true;

  self._tmp_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools', 'caches', utils.md5Hash(self._path));

  fse.ensureDirSync(self._path);
  fse.ensureDirSync(self._tmp_dir);

  self._crypto_index = new cryptor.CryptoIndex(
    path.join(self._path, 'INDEX'), 
    self._enc_key, 
    {
      debug: options.debug,
      obfuscate: options.obfuscate,
      read_only: options.read_only,
      algorithm: self._algorithm
    }
  );

  self._trash_dir = path.join(self._path, 'TRASH');
  self._trash_files_map = {};
  self._trash_files_count = 0;
  if (options.skip_trash) self._skip_trash = true;

  self._crypto_index.load(function(err) {
    if (err) {
      console.log('Load crypto index failed!');
      // console.log(err);
      if (err.message.indexOf('bad decrypt')!=-1) {
        err.message = 'Wrong passphrase';
      }
      return done(err);
    } else {
      self._loaded = true;
    }

    self.loadTrashIndex(options, function(err) {
      if (err) {
        console.log('Load trash files index failed!', err.message);
      }
      return done();
    });
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
        return done(err);
      } else {
        self._crypto_index = null;
        self._loaded = false;
      }
      
      self.saveTrashIndex(options, function(err) {
        if (err) {
          console.log('Save trash files index failed!', err.message);
        }
        return done();
      });
    });
  } else {
    return done();
  }
}

CryptoFolder.prototype.loadTrashIndex = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }
  
  var self = this;

  var trash_files_index = path.join(self._trash_dir, 'FILES');
  if (utils.fileExists(trash_files_index)) {
    var trash_files_index_tmp = path.join(self._tmp_dir, 'trash_files.json');

    cryptor.decryptFile(trash_files_index, trash_files_index_tmp, self._enc_key, {algorithm: self._algorithm}, function(err) {
      if (!err) {
        self._trash_files_map = utils.loadFromJsonFile(trash_files_index_tmp);
      }
      return done(err);
    });
  } else {
    return done();
  }
}

CryptoFolder.prototype.saveTrashIndex = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (self._trash_files_count > 0 && self._trash_files_map) {
    var trash_files_index_tmp = path.join(self._tmp_dir, 'trash_files.json');
    utils.saveToJsonFile(self._trash_files_map, trash_files_index_tmp);

    fse.ensureDirSync(self._trash_dir);
    var trash_files_index = path.join(self._trash_dir, 'FILES');

    cryptor.encryptFile(trash_files_index_tmp, trash_files_index, self._enc_key, {algorithm: self._algorithm}, function(err) {
      return done(err);
    });
  } else {
    return done();
  }
}

CryptoFolder.prototype.encrypt = function(INPUT_DIR, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

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
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

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
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

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
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

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

  self._crypto_index.getFileList(function(err, _files) {
    
    if (options.list_entries) {
      files = _files.filter(function(file_info) {
        return options.list_entries.some(function(entry) {
          return (file_info.path.indexOf(entry) == 0);
        });
      });
    } else {
      files = _files;
    }

    files.forEach(function(file_info) {
      count++;

      if (typeof options.onFileInfo == 'function') {
        options.onFileInfo(file_info, count);
      }

      total_size += file_info.size;

      if (file_info.size > largest_size) {
        largest_size = file_info.size;
        largest_file = { path: file_info.path, size: file_info.size };
      }
    });

    return done(null, {
      count: count,
      files: files,
      total_size: total_size,
      largest_size: largest_size,
      largest_file: largest_file
    });
  });
}

////

CryptoFolder.prototype.listTrash = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.listTrash(options, done);
    });
  }

  var count = 0;
  var files = [];
  var total_size = 0;

  var largest_size = 0;
  var largest_file = {};

  // print file list from trash files map
  for (var file_id in self._trash_files_map) {
    var entry = self._trash_files_map[file_id];
    var file_info = {
      id: file_id,
      path: entry.path,
      size: entry.size,
      mode: entry.mode,
      atime: entry.atime,
      mtime: entry.mtime,
      ctime: entry.ctime,
      birthtime: entry.birthtime,
      encrypted_path: entry.encrypted_path,
      encrypted_time: entry.encrypted_time
    };

    count++;
    files.push(file_info);

    if (typeof options.onFileInfo == 'function') {
      options.onFileInfo(file_info, count);
    }

    total_size += file_info.size;

    if (file_info.size > largest_size) {
      largest_size = file_info.size;
      largest_file = { path: file_info.path, size: file_info.size };
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

CryptoFolder.prototype.emptyTrash = function(options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }

  var self = this;

  if (!self._loaded) {
    return self.load(options, function(err) {
      if (err) return done(err);
      self.emptyTrash(options, done);
    });
  }

  var files = [];
  var total_size = 0;

  var removed_files = [];
  var removed_size = 0;

  for (var file_id in self._trash_files_map) {
    var entry = self._trash_files_map[file_id];
    var file_info = {
      id: file_id,
      path: entry.path,
      size: entry.size,
      mode: entry.mode,
      atime: entry.atime,
      mtime: entry.mtime,
      ctime: entry.ctime,
      birthtime: entry.birthtime,
      encrypted_path: entry.encrypted_path,
      encrypted_time: entry.encrypted_time
    };
    files.push(file_info);
    total_size += file_info.size;
  }

  // self._trash_files_map = {};
  // self._trash_files_count = 0;

  // fse.emptyDir(self._trash_dir, function(err) {
  //   return done(err, result);
  // });

  var total = files.length;
  var count = 0;

  var onFileRemoved = function(file) {};
  var onFileRemoveFailed = function(err, file) {};

  if (typeof options.onFileDecrypted == 'function') {
    onFileRemoved = function(file) {
      options.onFileRemoved(file, {
        current: count, total: total,
        total_size: total_size, removed_size: removed_size
      });
    }
  }
  if (typeof options.onFileRemoveFailed == 'function') {
    onFileRemoveFailed = function(err, file) {
      options.onFileRemoveFailed(err, file, {
        current: count, total: total,
        total_size: total_size, removed_size: removed_size
      });
    }
  }

  async.eachSeries(files, function(file, cb) {
    count++;
    var encrypted_file_abs_path = path.join(self._trash_dir, 'DATA', file.encrypted_path);

    if (utils.fileExists(encrypted_file_abs_path)) {
      fs.remove(encrypted_file_abs_path, function(err) {
        if (err) {
          onFileRemoveFailed(err, file);
          return cb();
        }

        removed_files.push(file);
        removed_size += file.size;

        onFileRemoved(file);

        return cb();
      });
    } else {
      removed_files.push(file);
      removed_size += file.size;

      onFileRemoved(file);

      return cb();
    }
  }, function(err) {
    done(err, {
      files: files,
      total_size: total_size,
      removed_files: removed_files,
      removed_size: removed_size,
    });
  });
}

////

CryptoFolder.prototype.getFsStats = function(opts, callback) {
  if (typeof opts == 'function') {
    callback = opts;
    opts = {};
  }

  var self = this;

  df({file: self._path}, function(err, result) {
    if (err) return callback(err);
    if (result.length) {
      var fs_stat = result[0];
      if (fs_stat.size) fs_stat.size *= 1024;
      if (fs_stat.used) fs_stat.used *= 1024;
      if (fs_stat.available) fs_stat.available *= 1024;
      return callback(null, fs_stat);
    }
    callback(null, {});
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

  self._crypto_index.getFileList(function(err, _files) {
    
    _files.forEach(function(file_info) {
      var entry = Object.assign(file_info, {type: 'file'});
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
    });
    
    for (var entry_path in self._entries_map) {
      var entry = self._entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    return callback(null, result);
  });
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
    return callback(new Error('Crypto folder is read only.'));
  }
  if (!self._crypto_index || !self._crypto_index.isLoaded()) {
    return callback(new Error('Crypto index not loaded.'));
  }

  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  var moveToTrash = function(cb) {
    fse.ensureDirSync(self._trash_dir);
    var removed_file_path = path.join(self._trash_dir, entry.encrypted_path);

    // 1. Move encrypted file to TRASH directory
    fse.move(encrypted_file_abs_path, removed_file_path, {overwrite: true}, function(err) {
      if (err) {
        console.log('Add file to trash failed! Encrypted file not found:', encrypted_file_abs_path);
        return cb(err);
      }

      // 2. Add to TRASH index
      self._crypto_index.getFile(fpath, function(err, file_info) {
        if (err) {
          console.log('Add file to trash failed! Index entry not found:', encrypted_file_abs_path);
          return cb(err);
        }

        var file_hash = utils.md5Hash(fpath);
        self._trash_files_map[file_hash] = Object.assign({}, file_info);
        self._trash_files_count++;

        cb();
      });
    });
  }

  var deleteEncryptedFile = function(cb) {
    fse.remove(encrypted_file_abs_path, function(err) {
      if (err) {
        console.log('Delete encrypted file failed! Encrypted file not found:', encrypted_file_abs_path);
        return cb(err);
      }

      cb();
    });
  }

  var removeFromFilesIndex = function(cb) {
    self._crypto_index.removeFile(fpath, function(err) {
      if (err) {
        console.log('Remove file from index failed:', encrypted_file_abs_path);
        return cb(err);
      }

      delete self._entries_map[fpath];
      return cb();
    });
  }

  if (utils.fileExists(encrypted_file_abs_path)) {
    if (self._skip_trash) {
      return deleteEncryptedFile(function(err) {
        if (err) return callback(err);
        // Remove file from entries map and crypto index
        removeFromFilesIndex(function(err) {
          if (err) return callback(err);
          return callback();
        });
      });
    }

    moveToTrash(function(err) {
      if (err) return callback(err);
      // Remove file from entries map and crypto index
      removeFromFilesIndex(function(err) {
        if (err) return callback(err);
        return callback();
      });
    });
  } else {
    // Remove file from entries map and crypto index
    removeFromFilesIndex(function(err) {
      if (err) return callback(err);
      return callback();
    });
  }
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

  if (!self._crypto_index || !self._crypto_index.isLoaded()) {
    return callback(new Error('Crypto index not loaded.'));
  }
  
  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  // console.log('getEntry:', bytes(entry.size), fpath);

  var decrypted_file_abs_path = path.join(output_dir, entry.path);
  fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

  var decrypt_opts = {
    obfuscate: self._crypto_index.obfuscate(),
    algorithm: self._algorithm
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
  
  if (!self._crypto_index || !self._crypto_index.isLoaded()) {
    return callback(new Error('Crypto index not loaded.'));
  }

  var entry = self._entries_map[fpath];
  var encrypted_file_abs_path = path.join(self._path, entry.encrypted_path);

  // console.log('getEntryDataBuffer:', bytes(entry.size), fpath);

  var decrypt_opts = {
    fd: opts.fd,
    debug: opts.debug,
    obfuscate: self._crypto_index.obfuscate(),
    algorithm: self._algorithm,
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

  if (!self._read_only) {
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
    getFsStats: self.getFsStats.bind(self),
    list: self.listFolder.bind(self),
    getEntry: self.getEntry.bind(self),
    getEntryDataBuffer: self.getEntryDataBuffer.bind(self),
    onDestroy: options.onDestroy
  };

  if (!self._read_only) {
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

