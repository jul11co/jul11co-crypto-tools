// lib/pack-file.js

var path = require('path');
var fs = require('fs');
var fse = require('fs-extra');

var tar = require('tar');
var tar_stream = require('tar-stream');

var jsonfile = require('jsonfile');
var humanizeDuration = require('humanize-duration');

// options Object
// {
//   path: String, // path to pack file
//   verbose: Boolean,
//   index_file: String, // path to pack index file (should be pack path + '.idx')
// }
var PackFile = function(options) {
  options = options || {};
  this._path = options.path;
  this._verbose = options.verbose;
  this._index = {};
  this._indexed = false;
  this._index_file = options.index_file;
}

module.exports = PackFile;

PackFile.prototype.path = function(callback) {
  return this._path;
}

PackFile.prototype._loadIndexFromFile = function(idx_file) {
  var self = this;
  var index = readIndexFile(idx_file);
  for (var entry_name in index) {
    self._index[entry_name] = {
      path: entry_name,
      type: index[entry_name].type || index[entry_name].t,
      size: index[entry_name].size || index[entry_name].s || 0,
      mode: index[entry_name].mode || index[entry_name].mo,
      type: index[entry_name].type || index[entry_name].t,
      offset: index[entry_name].offset || index[entry_name].o
    };
    var entry_mtime = index[entry_name].mtime || index[entry_name].mt;
    if (typeof entry_mtime == 'number') {
      self._index[entry_name].mtime = new Date();
      self._index[entry_name].mtime.setTime(entry_mtime);
    } else if (typeof entry_mtime == 'string') {
      self._index[entry_name].mtime = new Date(entry_mtime);
    }
  }
}

PackFile.prototype.createIndex = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  var self = this;
  var pack_path = self._path;

  if (!fs.existsSync(pack_path)) {
    return callback(new Error('Pack file not found!'));
  }

  var result = {
    totalSize: 0,
    // entries: [],
    entriesCount: 0
  };

  self._index = {};
  this._indexed = false;

  var idx_file = self._index_file || self._path + '.idx';
  if (!options.overwrite && fs.existsSync(idx_file)) {
    var pack_stat = getStat(self._path);
    var idx_stat = getStat(idx_file);
    
    if (pack_stat['mtime'] < idx_stat['mtime']) {
      self._loadIndexFromFile(idx_file);
      for (var entry_name in self._index) {
        result.totalSize += self._index[entry_name].size;
        result.entriesCount++;
      }
      self._indexed = true;
      return callback(null, result);
    }
  }

  var extract = tar_stream.extract();

  extract.on('entry', function(header, stream, next) {
    // header is the tar header
    // stream is the content body (might be an empty stream)
    // call next when you are done with this entry

    result.totalSize += header.size;
    result.entriesCount++;

    // self._index[header.name] = Object.assign({}, header);
    // self._index[header.name].offset= extract._offset;
    self._index[header.name] = {
      type: header.type || 'file',
      size: header.size || 0,
      mode: header.mode,
      mtime: header.mtime,
      offset: extract._offset
    };

    if (options.onEntry) {
      options.onEntry(header);
    }
    // if (options.verbose) {
    //   console.log((header.type || 'file')[0], header.name, 
    //     'size:'+header.size, 'offset:'+extract._offset);
    // }

    stream.on('end', function() {
      next(); // ready for next entry
    });
    stream.resume(); // just auto drain the stream
  });

  var finished = false;
  var finish = function(err, res) {
    if (finished) return;
    finished = true;

    if (!err && options.save_to_file) {
      var idx_file = self._index_file || self._path + '.idx';
      var index = {};

      for (var entry_name in self._index) {
        var entry = self._index[entry_name];

        index[entry_name] = {
          t: entry.type,
          s: entry.size,
          mo: entry.mode,
          mt: entry.mtime.getTime(),
          o: entry.offset
        };
      }

      writeIndexFile(idx_file, index);
      callback(err, res);
    } else {
      callback(err, res);
    }
  }

  extract.on('error', function(err) {
    console.log('Extract error!');
    finish(err);
  });

  extract.on('finish', function() {
    // console.log('Extract finished.');
  });

  fs.createReadStream(pack_path)
    .pipe(extract)
    .on('error', function(err) {
      finish(err);
    })
    .on('finish', function() {
      self._indexed = true;
      finish(null, result);
    });
}

PackFile.prototype.getIndex = function() {
  return this._index;
}

PackFile.prototype.getIndexStats = function() {
  if (!this._indexed) return {};
  if (this._index_stats) return this._index_stats;

  var self = this;
  self._index_stats = {
    totalSize: 0,
    entriesCount: 0
  };

  for (var entry_name in self._index) {
    self._index_stats.totalSize += self._index[entry_name].size;
    self._index_stats.entriesCount++;
  }

  return self._index_stats;
}

PackFile.prototype.saveIndex = function(idx_file, callback) {
  if (!this._indexed) return callback(new Error('Index not available'));
  fse.ensureDirSync(path.dirname(idx_file));
  
  var index = {};

  for (var entry_name in this._index) {
    var entry = this._index[entry_name];

    index[entry_name] = {
      t: entry.type,
      s: entry.size,
      mo: entry.mode,
      mt: entry.mtime.getTime(),
      o: entry.offset
    };
  }

  var err = writeIndexFile(index, idx_file);
  callback(err);
}

PackFile.prototype.extractEntryToFile = function(entry, file_path, buffer) {
  var self = this;
  
  if (!buffer) {
    // read to buffer
    buffer = new Buffer(entry.size);
    var fd = fs.openSync(self._path, 'r');
    try {
      fs.readSync(fd, buffer, 0, entry.size, entry.offset);
    } catch(e) {
      return e;
    } finally {
      fs.closeSync(fd)
    }
  }
  
  fse.ensureDirSync(path.dirname(file_path));
  // write to file
  fs.writeFileSync(file_path, buffer, {mode: entry.mode});
  // set mtime
  var entry_mtime = entry.mtime.getTime()/1000;
  try {
    fs.utimesSync(file_path, new Date(), entry_mtime);
  } catch(e) {
    return e;
  }
  
  return null;
}

PackFile.prototype.extractEntry = function(name, output_dir, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  var self = this;

  if (!self._indexed && !options.without_index) {
    var start_time = new Date();

    self.createIndex(function(err) {
      if (err) {
        console.log('CREATE INDEX FAILED! ' + err.message);
        options.without_index = true;
      } else if (options.progress) {
        console.log('INDEXING TIME:', humanizeDuration(new Date()-start_time));
      }
      return self.extractEntry(name, output_dir, options, callback);
    });
  } 
  else if (options.without_index) {
    // extract without index
    return self.extract(output_dir, {entries: [name]}, callback);
  } 
  else if (self._indexed && self._index && self._index[name]) {
    var parents_map = {};
    var entry = self._index[name];

    if (entry.type == 'directory' || entry.type == 'Directory') {
      var dir_path = path.join(output_dir, name);
      updateDirSync(dir_path, entry);
      return callback(null, {path: dir_path, entry: entry});
    } else if (entry.type == 'file' || entry.type == 'File') {
      if (entry.size == 0) {
        return callback(err, {path: file_path, entry: entry});
      }

      var file_path = path.join(output_dir, name);
      var err = self.extractEntryToFile(entry, file_path);
      if (err) {
        console.log(err);
        return callback(err, {path: file_path, entry: entry});
      }

      // update parents' atime && mtime
      var parents = [];
      getParentNames(name, parents);
      // parents = parents.filter(function(parent_name) {
      //   return !parents_map[parent_name];
      // });
      // console.log(parents);
      if (parents.length) {
        parents.forEach(function(parent_name) {
          if (self._index[parent_name]) {
            updateDirSync(path.join(output_dir, parent_name), self._index[parent_name]);
            // parents_map[parent_name] = true;
          }
        });
      }
      return callback(null, {path: file_path, entry: entry});
    } else {
      return callback(new Error('Not supported entry type: ' + entry.type))
    }
  } 
  else {
    return callback(new Error('File not found'));
  }
}

PackFile.prototype.extractEntries = function(entries, output_dir, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  var self = this;

  if (!self._indexed && !options.without_index) {
    var start_time = new Date();
    self.createIndex(function(err) {
      if (err) {
        console.log('CREATE INDEX FAILED! ' + err.message);
        options.without_index = true;
      } else if (options.progress) {
        console.log('INDEXING TIME:', humanizeDuration(new Date()-start_time));
      }
      return self.extractEntries(entries, output_dir, options, callback);
    });
  } 
  else if (options.without_index) {
    return self.extract(output_dir, {entries: entries}, callback);
  } 
  else if (self._indexed && self._index) {
    var result = [];
    // var parents_map = {};

    entries.forEach(function(_path) {
      if (!self._index[_path]) {
        result.push({path: _path, error: 'Index not found'});
        return;
      }

      var entry = self._index[_path];
      
      if (entry.type == 'directory' || entry.type == 'Directory') {
        var dir_path = path.join(output_dir, _path);
        updateDirSync(dir_path, entry);
        result.push({path: _path, type: entry.type, path: dir_path, entry: entry});
      } else if (entry.type == 'file' || entry.type == 'File') {
        if (entry.size == 0) {
          result.push({path: _path, type: entry.type, entry: entry});
          return;
        }
        
        var file_path = path.join(output_dir, _path);
        var err = self.extractEntryToFile(entry, file_path);
        if (err) {
          console.log(err);
          result.push({path: _path, error: err.message, type: entry.type, entry: entry});
          return;
        }
        
        // update parents' atime && mtime
        var parents = [];
        getParentNames(_path, parents);
        // parents = parents.filter(function(parent_name) {
        //   return !parents_map[parent_name];
        // });
        if (parents.length) {
          parents.forEach(function(parent_name) {
            if (self._index[parent_name]) {
              updateDirSync(path.join(output_dir, parent_name), self._index[parent_name]);
              // parents_map[parent_name] = true;
            }
          });
        }
        result.push({path: _path, type: entry.type, path: file_path, entry: entry});
      } else {
        result.push({path: _path, error: 'Not supported entry type: ' + entry.type});
      }
    });
    return callback(null, result);
  } 
  else {
    return callback(new Error('Index not found'));
  }
}

PackFile.prototype.list = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  var result = {
    totalSize: 0,
    entries: []
  };

  var self = this;
  var pack_path = self._path;

  if (!fs.existsSync(pack_path)) {
    return callback(new Error('Pack file not found!'));
  }

  var finished = false;
  var finish = function(err, res) {
    if (finished) return;
    finished = true;
    callback(err, res);
  }

  var idx_file = self._index_file || self._path + '.idx';
  if (self._indexed && self._index) {
    for (var _path in self._index) {
      result.totalSize += self._index[_path].size;
      result.entries.push(self._index[_path]);
    }
    return finish(null, result);
  } else if (fs.existsSync(idx_file)) {
    var pack_stat = getStat(self._path);
    var idx_stat = getStat(idx_file);
    
    if (pack_stat['mtime'] < idx_stat['mtime']) {
      self._loadIndexFromFile(idx_file);
      for (var _path in self._index) {
        result.totalSize += self._index[_path].size;
        result.entries.push(self._index[_path]);
      }
      self._indexed = true;
      return finish(null, result);
    }
  }

  if (options.tar_stream) {
    // using tar-stream
    
    var extract = tar_stream.extract();

    extract.on('entry', function(header, stream, next) {
      // header is the tar header
      // stream is the content body (might be an empty stream)
      // call next when you are done with this entry

      result.totalSize += header.size;

      var entry = Object.assign({}, header);
      entry.path = header.name;
      result.entries.push(entry);

      // if (self._verbose || options.verbose) {
      //   console.log((entry.type || 'file')[0], entry.path, entry.size, 
      //     entry.mode, entry.mtime, entry.uid, entry.gid);
      // }

      stream.on('end', function() {
        next(); // ready for next entry
      });
      stream.resume() // just auto drain the stream
    });

    extract.on('error', function(err) {
      console.log('Extract error!');
      finish(err);
    });

    extract.on('finish', function() {
      // console.log('Extract finished.');
    });

    fs.createReadStream(pack_path)
      .pipe(extract)
      .on('error', function(err) {
        finish(err);
      })
      .on('finish', function() {
        finish(null, result);
      });
  } else {
    // using tar

    tar.t({
      file: self._path,
      onentry: function(entry) {
        result.totalSize += entry.size;
        result.entries.push(Object.assign({}, entry));
        // if (self._verbose || options.verbose) {
        //   console.log((entry.type || 'file')[0], entry.path, entry.size, 
        //     entry.mode, entry.mtime, entry.uid, entry.gid);
        // }
      }
    }, function(err) {
      if (err) return finish(err);
      finish(null, result);
    });
  }
}

PackFile.prototype.extract = function(output_dir, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  var self = this;
  var pack_path = self._path;

  if (!fs.existsSync(pack_path)) {
    return callback(new Error('Pack file not found!'));
  }

  if (!options.overwrite && fs.existsSync(output_dir)) {
    return callback(new Error('Output directory exists!'));
  }

  fse.ensureDirSync(output_dir);

  var finished = false;
  var finish = function(err, res) {
    if (finished) return;
    finished = true;
    callback(err, res);
  }

  var result = {
    totalSize: 0,
    entries: []
  };

  var updateResultEntries = function(entry) {
    result.totalSize += entry.size;
    result.entries.push(Object.assign({}, entry));
    if (options.onEntry) {
      options.onEntry(entry);
    }
    // if (self._verbose || options.verbose || options.progress) {
    //   console.log((entry.type || 'file')[0], entry.path, entry.size, 
    //     entry.mode, entry.mtime, entry.uid, entry.gid);
    // }
  }

  var entries = [];
  var ignoreEntries = [];
  var ignorePaths = [];
  var onlyPaths = [];
  var ignoreNames = [];
  var onlyNames = [];

  if (Array.isArray(options.entries) && options.entries.length) {
    entries = options.entries;
  } else if (Array.isArray(options.ignoreEntries) && options.ignoreEntries.length) {
    ignoreEntries = options.ignoreEntries;
  } else if (Array.isArray(options.ignorePaths) && options.ignorePaths.length) {
    ignorePaths = options.ignorePaths;
  } else if (Array.isArray(options.onlyPaths) && options.onlyPaths.length) {
    onlyPaths = options.onlyPaths;
  } else if (Array.isArray(options.ignoreNames) && options.ignoreNames.length) {
    ignoreNames = options.ignoreNames;
  } else if (Array.isArray(options.onlyNames) && options.onlyNames.length) {
    onlyNames = options.onlyNames;
  }

  var isIgnorePath = function(_path) {
    return ignorePaths.some(function(str) { return (_path.indexOf(str)==0); });
  }
  var isOnlyPath = function(_path) {
    return onlyPaths.some(function(str) { return (_path.indexOf(str)==0); });
  }
  var isIgnoreName = function(_path) {
    var name = path.basename(_path);
    return ignoreNames.some(function(str) { return (name.indexOf(str)>=0); });
  }
  var isOnlyName = function(_path) {
    var name = path.basename(_path);
    return onlyNames.some(function(str) { return (name.indexOf(str)>=0); });
  }

  var ignore = function(_path, entry) {
    if (entries.length && entries.indexOf(_path) == -1) {
      return true;
    } else if (ignoreEntries.length && ignoreEntries.indexOf(_path) != -1) {
      return true;
    } else if (ignorePaths.length && isIgnorePath(_path)) {
      return true;
    } else if (onlyPaths.length) {
      if (isOnlyPath(_path)) return false;
      else return true;
    } else if (ignoreNames.length && isIgnoreName(_path)) {
      return true;
    } else if (onlyNames.length) {
      if (isOnlyName(_path)) return false;
      else return true;
    }
    return false;
  }

  tar.x({
    cwd: output_dir,
    file: pack_path,
    newer: !options.overwrite,
    filter: function(_path, entry) {
      // console.log('filter:', _path);
      if (ignore(_path, entry)) {
        if (self._verbose || options.verbose) console.log('skip:', _path);
        return false;
      } else {
        updateResultEntries(entry);
        return true;
      }
    },
    onwarn: function(message, data) {
      console.log(message);
    }
  }, function(err) {
    if (err) return finish(err, result);
    finish(null, result);
  });
};

PackFile.prototype.pack = function(input_dir, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  if (!fs.existsSync(input_dir)) {
    return callback(new Error('Input directory not found!'));
  }

  var self = this;
  var pack_path = self._path;

  var finished = false;
  var finish = function(err, res) {
    if (finished) return;
    finished = true;
    callback(err, res);
  }

  var update = false;
  if (fs.existsSync(pack_path)) {
    if (options.overwrite) {
      fs.removeSync(pack_path);
    } else {
      update = true;
    }
  }

  if (update) { // update pack
    self._updatePack(input_dir, pack_path, options, finish);
  } else { // create new pack
    self._createPack(input_dir, pack_path, options, finish);
  }
};

PackFile.prototype._updatePack = function(input_dir, pack_path, options, finish) {
  if (typeof options == 'function') {
    finish = options;
    options = {};
  }

  var self = this;

  self.list(options, function(err, result) {
    if (err) {
      console.log('List entries failed.');
    }

    var entries_map = {};
    if (result && result.entries) {
      if (self._verbose) console.log('Existing entries:', result.entries.length);
      result.entries.forEach(function(entry) {
        entries_map[entry.path] = entry;
        // if ((self._verbose || options.verbose)) {
        //   console.log((entry.type || 'file')[0], entry.path, entry.size, entry.mtime);
        // }
      });
    }

    var result = {
      totalSize: 0,
      entries: []
    };

    var entries = [];
    var ignoreEntries = [];
    var ignorePaths = [];
    var ignoreNames = [];

    if (options.entries && Array.isArray(options.entries)) {
      entries = options.entries; 
    }
    if (options.ignoreEntries && Array.isArray(options.ignoreEntries)) {
      ignoreEntries = options.ignoreEntries;
    }
    if (options.ignorePaths && Array.isArray(options.ignorePaths)) {
      ignorePaths = options.ignorePaths;
    }
    if (options.ignoreNames && Array.isArray(options.ignoreNames)) {
      ignoreNames = options.ignoreNames;
    }

    var isIgnorePath = function(_path) {
      return ignoreNames.some(function(str) { return (_path.indexOf(str)==0); });
    }
    var isIgnoreName = function(_path) {
      var name = path.basename(_path);
      return ignoreNames.some(function(str) { return (name.indexOf(str)!=-1); });
    }

    var ignore = function(_path, stat) {
      if (entries_map[_path]) {
        var old_entry = entries_map[_path];
        var entry_size = (stat.isDirectory() || stat.isSymbolicLink()) ? 0 : stat['size'];
        var ignored = (entry_size == old_entry.size 
          && stat['mtime'].getTime() == old_entry.mtime.getTime());
        // if (!ignored && (self._verbose || options.verbose)) {
        //   console.log('no ignore:', (old_entry.type || 'file')[0], old_entry.path, 
        //     old_entry.size + ' - ' + entry_size, 
        //     old_entry.mtime + ' - ' + stat['mtime']);
        // }
        return ignored;
      } else if (entries.length && entries.indexOf(_path) == -1) {
        return true;
      } else if (ignoreEntries.length && ignoreEntries.indexOf(_path) != -1) {
        return true;
      } else if (ignorePaths.length && isIgnorePath(_path)) {
        return true;
      } else if (ignoreNames.length && isIgnoreName(_path)) {
        return true;
      }
      return false;
    }

    var updateResultEntries = function(entry) {
      result.totalSize += entry.size;
      result.entries.push(Object.assign({}, entry));
      if (options.onEntry) {
        options.onEntry(entry);
      }
      // if (self._verbose || options.verbose) {
      //   console.log((entry.type || 'file')[0], entry.path, entry.size, entry.mode, entry.mtime);
      // }
    }

    var getEntryType = function(stat) {
      if (stat.isFile()) return 'File';
      if (stat.isDirectory()) return 'Directory';
      if (stat.isSymbolicLink()) return 'SymbolicLink';
      return null;
    }

    tar.u({
      file: pack_path,
      cwd: input_dir,
      filter: function(_path, stat) {
        // console.log('filter:', _path);
        var _relpath = (path.isAbsolute(_path)) ? path.relative(input_dir, _path) :  _path;
        _relpath = (_relpath == '') ? '.' : _relpath;
        if (stat.isDirectory()) _relpath = path.join(_relpath, '/');

        if (ignore(_relpath, stat)) {
          if (self._verbose || options.verbose) console.log('skip:', _relpath);
          return false;
        } else {
          var entry = {
            path: _relpath,
            type: getEntryType(stat),
            size: stat['size'],
            mode: stat['mode'],
            mtime: stat['mtime']
          };
          updateResultEntries(entry);
          return true;
        }
      },
      onwarn: function(message, data) {
        console.log(message);
      }
    }, [''], function(err) {
      if (err) return finish(err);
      var stat = getStat(pack_path);
      if (stat) return finish(null, {
        file: pack_path, 
        size: stat['size'], 
        update: true, 
        updateSize: result.totalSize,
        updateEntries: result.entries.length
      });
      else finish(new Error('Cannot update pack.'));
    })
  });
}

PackFile.prototype._createPack = function(input_dir, pack_path, options, finish) {
  if (typeof options == 'function') {
    finish = options;
    options = {};
  }

  var self = this;

  var result = {
    totalSize: 0,
    entries: []
  };

  var entries = [];
  var ignoreEntries = [];
  var ignorePaths = [];
  var ignoreNames = [];

  if (options.entries && Array.isArray(options.entries)) {
    entries = options.entries; 
  }
  if (options.ignoreEntries && Array.isArray(options.ignoreEntries)) {
    ignoreEntries = options.ignoreEntries;
  }
  if (options.ignorePaths && Array.isArray(options.ignorePaths)) {
    ignorePaths = options.ignorePaths;
  }
  if (options.ignoreNames && Array.isArray(options.ignoreNames)) {
    ignoreNames = options.ignoreNames;
  }

  var isIgnorePath = function(_path) {
    return ignoreNames.some(function(str) { return (_path.indexOf(str)==0); });
  }
  var isIgnoreName = function(_path) {
    var name = path.basename(_path);
    return ignoreNames.some(function(str) { return (name.indexOf(str)!=-1); });
  }

  var ignore = function(_path, stat) {
    if (entries.length && entries.indexOf(_path) == -1) {
      return true;
    } else if (ignoreEntries.length && ignoreEntries.indexOf(_path) != -1) {
      return true;
    } else if (ignorePaths.length && isIgnorePath(_path)) {
      return true;
    } else if (ignoreNames.length && isIgnoreName(_path)) {
      return true;
    }
    return false;
  }

  var updateResultEntries = function(entry) {
    result.totalSize += entry.size;
    result.entries.push(Object.assign({}, entry));
    if (options.onEntry) {
      options.onEntry(entry);
    }
    // if (self._verbose || options.verbose || options.progress) {
    //   console.log((entry.type || 'file')[0], entry.path, entry.size, 
    //     entry.mode, entry.mtime);
    // }
  }

  var getEntryType = function(stat) {
    if (stat.isFile()) return 'File';
    if (stat.isDirectory()) return 'Directory';
    if (stat.isSymbolicLink()) return 'SymbolicLink';
    return null;
  }

  tar.c({
    file: pack_path,
    cwd: input_dir,
    filter: function(_path, stat) {
      // console.log('filter:', _path);
      var _relpath = (path.isAbsolute(_path)) ? path.relative(input_dir, _path) : _path;
      _relpath = (_relpath == '') ? '.' : _relpath;
      if (stat.isDirectory()) _relpath = path.join(_relpath, '/');

      if (ignore(_relpath, stat)) {
        if (self._verbose || options.verbose) console.log('skip:', _relpath);
        return false;
      } else {
        var entry = {
          path: _relpath,
          type: getEntryType(stat),
          size: stat['size'],
          mode: stat['mode'],
          mtime: stat['mtime']
        };
        updateResultEntries(entry);
        return true;
      }
    },
    onwarn: function(message, data) {
      console.log(message);
    }
  }, [''], function(err) {
    if (err) return finish(err);
    var stat = getStat(pack_path);
    if (stat) return finish(null, {
      file: pack_path, 
      size: stat['size'], 
      new: true, 
      newSize: result.totalSize,
      newEntries: result.entries.length
    });
    else finish(new Error('Cannot create pack.'));
  })
}

PackFile.prototype.removeSync = function() {
  if (fs.existsSync(this._path)) {
    fs.removeSync(this._path)
  }
}

///

function readIndexFile(file) {
  var info = {};
  try {
    var stats = fs.statSync(file);
    if (stats.isFile()) {
      info = jsonfile.readFileSync(file);
    }
  } catch (e) {
    console.log(e);
  }
  return info;
}

function writeIndexFile(info, file) {
  var err = null;
  try {
    jsonfile.writeFileSync(file, info);
  } catch (e) {
    err = e;
  }
  return err;
}

function updateDirSync(dir_path, entry) {
  fse.ensureDirSync(dir_path);
  var entry_mtime = entry.mtime.getTime()/1000;
  try {
    fs.utimesSync(dir_path, new Date(), entry_mtime);
  } catch(e) {
    console.log(e);
  }
}

function getParentNames(_path, parents) {
  var parent = path.dirname(_path);
  if (parent && parent != '' && parent != '.') {
    parents.push(parent);
    getParentNames(parent, parents);
  }
}

function getStat(_path) {
  var stat = undefined;
  try {
    stat = fs.lstatSync(_path);
  } catch(e) {
    console.log(e);
  }
  return stat;
}
