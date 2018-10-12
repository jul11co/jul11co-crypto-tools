// lib/crypto-mount.js

var path = require('path');
var fs = require('fs');

var async = require('async');
var bytes = require('bytes');

var fuse = require('fuse-bindings');

var MountPoint = function(crypto_source, mount_dir, tmp_dir, opts) {
  this._crypto_source = crypto_source;
  
  this._mount_dir = path.resolve(mount_dir);
  this.path = this._mount_dir;

  this._tmp_dir = tmp_dir;

  this._opts = opts;
  this._mounted = false;
}

MountPoint.prototype.mount = function(callback) {
  var self = this;
  if (self._mounted) {
    console.log('already mounted:', self._mount_dir);
    return callback();
  }
  exports.mount(self._crypto_source, self._mount_dir, self._tmp_dir, self._opts, function(err) {
    if (err) {
      return callback(err);
    } else {
      self._mounted = true;
      return callback();
    }
  });
}

MountPoint.prototype.isMounted = function() {
  return this._mounted;
}

MountPoint.prototype.unmount = function(callback) {
  if (!this._mounted) return callback();
  exports.unmount(this._crypto_source, this._mount_dir, this._opts, function(err) {
    callback(err);
  });
}

exports.MountPoint = MountPoint;

///

exports.mount = function(crypto_source, mount_point, tmp_dir, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }

  var directory_trailing_slash = options.directory_trailing_slash || false;

  var dirs_map = {};
  var files_map = {};
  
  var entries_count = 0;
  var total_size = 0;

  var addDirToMap = function(dir) {
    var dir_path = dir.path;
    var dir_relpath = dir.path;

    if (!dirs_map[dir_relpath]) {
      dirs_map[dir_relpath] = {};
      dirs_map[dir_relpath].name = path.basename(dir_relpath);
      dirs_map[dir_relpath].path = dir_relpath;
      dirs_map[dir_relpath].relpath = dir_relpath;
      dirs_map[dir_relpath].size = 0;
      // dirs_map[dir_relpath].atime = dir.atime;
      dirs_map[dir_relpath].mtime = dir.mtime;
      // dirs_map[dir_relpath].ctime = dir.ctime;
      dirs_map[dir_relpath].files = [];
      dirs_map[dir_relpath].subdirs = [];
    }

    if (dir_relpath != '.' && dir_relpath != './') {
      var parent_dir_path = path.dirname(dir_path);
      var parent_dir_relpath = parent_dir_path; 
      if (directory_trailing_slash) parent_dir_relpath += '/';

      if (dirs_map[parent_dir_relpath]) {
        dirs_map[parent_dir_relpath].subdirs.push(dir_relpath);
      } else {
        dirs_map[parent_dir_relpath] = {};
        dirs_map[parent_dir_relpath].name = path.basename(parent_dir_relpath);
        dirs_map[parent_dir_relpath].path = parent_dir_relpath;
        dirs_map[parent_dir_relpath].relpath = parent_dir_relpath;
        dirs_map[parent_dir_relpath].size = 0;
        dirs_map[parent_dir_relpath].files = [];
        dirs_map[parent_dir_relpath].subdirs = [];
        dirs_map[parent_dir_relpath].subdirs.push(dir_relpath);
      }
    }
  }
 
  var removeDirFromMap = function(dir) {
    if (!dirs_map[dir.relpath]) return;

    var parent_dir_relpath = path.dirname(dir.path);
    if (directory_trailing_slash) parent_dir_relpath += '/';
    if (dirs_map[parent_dir_relpath]) {
      dirs_map[parent_dir_relpath].subdirs = dirs_map[parent_dir_relpath].subdirs.filter(function(subdir_relpath) {
        return subdir_relpath != dir.relpath;
      });
    }
    
    entries_count = entries_count - 1;
    
    delete dirs_map[dir.relpath];
  }

  var addFileToMap = function(file) {
    file.relpath = file.path;
    files_map[file.relpath] = file;

    var dir_path = path.dirname(file.path);
    var dir_relpath = dir_path; 
    if (directory_trailing_slash) dir_relpath += '/';

    if (dirs_map[dir_relpath]) {
      dirs_map[dir_relpath].size += file.size;
      dirs_map[dir_relpath].files.push(file.relpath);
    } else {
      dirs_map[dir_relpath] = {};
      dirs_map[dir_relpath].name = path.basename(dir_relpath);
      dirs_map[dir_relpath].path = dir_relpath;
      dirs_map[dir_relpath].relpath = dir_relpath;
      dirs_map[dir_relpath].size = file.size;
      dirs_map[dir_relpath].files = [];
      dirs_map[dir_relpath].subdirs = [];
      dirs_map[dir_relpath].files.push(file.relpath);
    }
  }

  var removeFileFromMap = function(file) {
    if (!files_map[file.relpath]) return;

    var dir_relpath = path.dirname(file.path);
    if (directory_trailing_slash) dir_relpath += '/';
    if (dirs_map[dir_relpath]) {
      dirs_map[dir_relpath].size = dirs_map[dir_relpath].size - file.size;
      dirs_map[dir_relpath].files = dirs_map[dir_relpath].files.filter(function(file_relpath) {
        return file_relpath != file.relpath;
      });
    }
    
    entries_count = entries_count - 1;
    total_size = total_size - file.size;
    
    delete files_map[file.relpath];
  }

  var removeFile = function(file_relpath, done) {
    if (!files_map[file_relpath]) {
      return done(new Error('File not found:', file_relpath));
    }

    if (crypto_source.read_only) {
      return done(new Error('Crypto source is read only.'));
    }
    
    var file = files_map[file_relpath];
    if (options.debug) console.log('Remove file:', file.relpath);

    if (typeof crypto_source.removeEntry == 'function') {
      crypto_source.removeEntry(file.relpath, function(err) {
        if (err) return done(err);
        removeFileFromMap(file);
        done();
      });
    } else {
      removeFileFromMap(file);
      done();
    }
  }

  var removeDir = function(dir_relpath, done) {
    if (!dirs_map[dir_relpath]) {
      return done(new Error('Directory not found:', dir_relpath));
    }

    if (crypto_source.read_only) {
      return done(new Error('Crypto source is read only.'));
    }

    var dir = dirs_map[dir_relpath];
    if (options.debug) console.log('Remove dir:', dir.relpath);

    // remove sub-directories
    async.eachSeries(dir.subdirs, function(subdir_relpath, cb) {
      removeDir(subdir_relpath, cb);
    }, function(err) {
      if (err) {
        console.log('Remove subdirs failed!', dir_relpath);
        return done(err);
      }

      // remove files
      async.eachSeries(dir.files, function(file_relpath, cb) {
        removeFile(file_relpath, cb);
      }, function(err) {
        if (err) {
          console.log('Remove files failed!', dir_relpath);
          return done(err);
        }

        // remove from map
        removeDirFromMap(dir);

        done();
      });
    });
  }

  var getDirSize = function(dir_relpath, dir_size_map) {
    if (!dirs_map[dir_relpath]) return 0;
    if (dir_size_map[dir_relpath]) return dir_size_map[dir_relpath];
    
    if (dirs_map[dir_relpath].subdirs.length == 0) {
      dir_size_map[dir_relpath] = dirs_map[dir_relpath].size;
      return dirs_map[dir_relpath].size;
    }
    
    var dir_size = dirs_map[dir_relpath].size; // size of files (if any)
    dirs_map[dir_relpath].subdirs.forEach(function(subdir_relpath) {
      dir_size += getDirSize(subdir_relpath, dir_size_map);
    });
    dir_size_map[dir_relpath] = dir_size;
    
    return dir_size;
  }

  var loadCryptoSource = function(done) {
    crypto_source.list(function(err, result) {
      if (err) return done(err);

      var dir_entries = result.entries.filter(function(entry) {
        return (entry.type == 'directory' || entry.type == 'Directory');
      });
      var dirs = dir_entries.map(function(entry) {
        return {
          path: entry.path,
          name: path.basename(entry.path),
          size: entry.size,
          mode: entry.mode,
          mtime: entry.mtime
        }
      });
      var file_entries = result.entries.filter(function(entry) {
        return (entry.type == 'file' || entry.type == 'File');
      });
      var files = file_entries.map(function(entry) {
        return {
          encrypted_path: entry.encrypted_path,
          path: entry.path,
          name: path.basename(entry.path),
          type: path.extname(entry.path).replace('.',''),
          size: entry.size,
          mode: entry.mode,
          mtime: entry.mtime,
          atime: entry.atime,
          ctime: entry.ctime,
          birthtime: entry.birthtime
        }
      });
      
      console.log('Dirs:', dirs.length);
      console.log('Files:', files.length);

      var total_files_size = 0;
      files.forEach(function(file) {
        total_files_size += file.size;
      });

      console.log('Total File Size:', bytes(total_files_size));

      entries_count = dirs.length + files.length;
      total_size = total_files_size;

      dirs.forEach(function(dir) {
        addDirToMap(dir);
      });

      files.forEach(function(file) {
        addFileToMap(file);
      });

      var dir_size_map = {};
      for (var dir_relpath in dirs_map) {
        dirs_map[dir_relpath].size = getDirSize(dir_relpath, dir_size_map);
      }

      return done();
    });
  }

  var default_blksize = 4096;
  var default_frsize = 4096;
  var default_root_entry = directory_trailing_slash ? './' : '.';

  var fds_map = {};

  var toFlag = function(flags) {
    flags = flags & 3;
    if (flags === 0) return 'r';
    if (flags === 1) return 'w';
    return 'r+';
  }

  var toRelPath = function(fpath) {
    return (fpath == '/') ? '.' : ((fpath.indexOf('/')==0) ? fpath.substring(1) : fpath);
  }

  var fuse_ops = {
    // Called when the filesystem is being stat'ed. 
    // Accepts a fs `stat` object after the return code in the callback.
    statfs: function(fpath, cb) {
      // console.log('statfs(%s)', fpath);
      var blocks_count = (Math.ceil(total_size/default_blksize));
      var stat = {
        bsize: default_blksize,  // block size
        frsize: default_frsize,  // fragment size
        blocks: blocks_count,    // total data blocks
        bfree: 1000000000,       // free blocks
        bavail: 1000000000,      // free blocks available unprivileged user
        files: entries_count,    // total file nodes
        ffree: 1000000,          // free file nodes
        favail: 1000000,         // available file nodes
        // fsid: 1000000,
        // flag: 1000000,
        // namemax: 1000000
      };
      if (typeof crypto_source.getFsStats == 'function') {
        crypto_source.getFsStats(function(err, fs_stats) {
          if (!err && fs_stats) {
            if (fs_stats.available) {
              stat.bfree = (Math.ceil(fs_stats.available/default_blksize));
              stat.bavail = stat.bfree;
            }
          }
          cb(0, stat);
        });
      } else {
        cb(0, stat);
      }
    },
    // Called when a directory is being listed. 
    // Accepts an array of file/directory names after the return code in the callback
    readdir: function(fpath, cb) {
      // console.log('readdir(%s)', path);
      var files = [];
      var dir_path = toRelPath(fpath);
      var dir_entry = dirs_map[dir_path] || dirs_map[dir_path+'/'];
      if (dir_entry) {
        dir_entry.subdirs.forEach(function(dir_relpath) {
          files.push(dirs_map[dir_relpath].name);
        });
        dir_entry.files.forEach(function(file_relpath) {
          files.push(files_map[file_relpath].name);
        });
        cb(0, files);
      } else {
        // console.log('ENOENT:', path);
        cb(fuse.ENOENT);
      }
    },
    // Called when a symlink is being resolved. 
    // Accepts a pathname (that the link should resolve to) after the return code in the callback
    // readlink: function(path, cb) {

    // },
    // Called when a path is being stat'ed. 
    // Accepts a stat object (similar to the one returned in `fs.stat(path, cb))` after the return code in the callback.
    getattr: function(fpath, cb) {
      // console.log('getattr(%s)', fpath);
      var entry_path = toRelPath(fpath);
      var dir_entry = dirs_map[entry_path] || dirs_map[entry_path+'/'];
      if (dir_entry) {        
        cb(0, {
          mtime: new Date(dir_entry.mtime),
          atime: new Date(),
          ctime: new Date(),
          nlink: 1,
          size: 4096,
          mode: 16877,
          uid: process.getuid ? process.getuid() : 0,
          gid: process.getgid ? process.getgid() : 0
        })
      } else if (files_map[entry_path]) {
        var file_entry = files_map[entry_path];
        cb(0, {
          mtime: new Date(file_entry.mtime),
          atime: new Date(file_entry.atime),
          ctime: new Date(file_entry.ctime),
          birthtime: new Date(file_entry.birthtime||file_entry.mtime||0),
          nlink: 1,
          size: file_entry.size,
          mode: file_entry.mode,
          uid: process.getuid ? process.getuid() : 0,
          gid: process.getgid ? process.getgid() : 0
        })
      } else {
        // console.log('ENOENT:', entry_path);
        cb(fuse.ENOENT);
      }
    },
    // Same as `getattr` but is called when someone stats a file descriptor
    fgetattr: function(fpath, fd, cb) {
      // console.log('fgetattr(%s)', fpath);
      var entry_path = toRelPath(fpath);
      if (files_map[entry_path]) {
        var file_entry = files_map[entry_path];
        cb(0, {
          mtime: new Date(file_entry.mtime),
          atime: new Date(file_entry.atime),
          ctime: new Date(file_entry.ctime),
          birthtime: new Date(file_entry.birthtime||file_entry.mtime||0),
          nlink: 1,
          size: file_entry.size,
          mode: file_entry.mode,
          uid: process.getuid ? process.getuid() : 0,
          gid: process.getgid ? process.getgid() : 0
        })
      } else {
        // console.log('ENOENT:', entry_path);
        cb(fuse.ENOENT);
      }
    },
    // Called when a path is being opened. `flags` in a number containing the permissions being requested. 
    // Accepts a file descriptor after the return code in the callback.
    open: function(fpath, flags, cb) {
      if (options.debug) console.log('open(%s, %d)', fpath, flags);
      var flag = toFlag(flags) // convert flags to a node style string
      var file_path = (fpath.indexOf('/')==0) ? fpath.substring(1) : fpath;

      if (typeof crypto_source.getEntryDataBuffer == 'function') {
        var entry_path = toRelPath(fpath);
        var file_entry = files_map[entry_path];
        var file_abs_path = path.join(crypto_source.path, file_entry.encrypted_path);
        try {
          var fd = fs.openSync(file_abs_path, flag);
          fds_map[fd] = {
            path: fpath, 
            abs_path: file_abs_path,
            flag: flag
          };

          return cb(0, fd);
        } catch(e) {
          console.log(e.message);
          return cb(fuse.ENOENT);
        }
      } else {
        crypto_source.getEntry(file_path, tmp_dir, {}, function(err) {
          if (err) {
            console.log('getEntry failed:', err.message);
            return cb(fuse.EIO);
          }
          var file_abs_path = path.join(tmp_dir, file_path);
          var fd = fs.openSync(file_abs_path, flag);
          fds_map[fd] = {
            path: fpath, 
            abs_path: file_abs_path,
            flag: flag
          };
          return cb(0, fd);
        });
      } 
    },
    // Same as `open` but for directories
    // opendir: function(path, flags, cb) {

    // },
    // Called when contents of a file is being read. You should write the result of the read to the buffer and return 
    // the number of bytes written as the first argument in the callback. 
    // If no bytes were written (read is complete) return 0 in the callback.
    read: function(fpath, fd, buffer, length, position, cb) {
      if (options.debug) console.log('read(%s, %d, %d, %d)', fpath, fd, length, position);
      if (typeof crypto_source.getEntryDataBuffer == 'function') {
        var entry_path = toRelPath(fpath);
        crypto_source.getEntryDataBuffer(entry_path, position, length, {
          fd: fd,
          debug: options.debug
        }, function(err, buf) {
          if (err) {
            console.log(err.message);
            return cb(fuse.EIO);
          }
          if (options.debug) console.log('buf.length:', buf.length, 'buffer.length:', buffer.length);
          var bytesRead = buf.copy(buffer, 0, 0, Math.min(buf.length, buffer.length)); // copy from buf to buffer
          if (options.debug) console.log('bytesRead:', bytesRead);
          cb(bytesRead);
        });
      } else {
        fs.read(fd, buffer, 0, length, position, function(err, bytesRead) {
          if (err) {
            console.log(err.message);
            return cb(fuse.EIO);
          }
          cb(bytesRead);
        });
      }
    },
    // Called when a file is being written to. You can get the data being written in buffer and you should return 
    // the number of bytes written in the callback as the first argument.
    write: function(fpath, fd, buffer, length, position, cb) {
      if (options.debug) console.log('write(%s, %d, %d, %d)', fpath, fd, length, position);
      return cb(fuse.EPERM);
    },
    // Called when a file descriptor is being released. Happens when a read/write is done etc.
    release: function(fpath, fd, cb) {
      if (options.debug) console.log('release(%s, %d)', fpath, fd);
      if (fds_map[fd]) delete fds_map[fd];
      fs.closeSync(fd);
      return cb();
    },
    // Same as `release` but for directories
    // releasedir: function(path, fd, cb) {
    //   return cb();
    // },
    // Called when ownership of a path is being changed
    // chown: function(path, uid, gid, cb) {

    // },
    // Called when the mode of a path is being changed
    // chmod: function(path, mode, cb) {

    // },
    // Called when a new file is being opened.
    // create: function(path, mode, cb) {

    // },
    // Called when the atime/mtime of a file is being changed.
    // utimens: function(path, atime, mtime, cb) {

    // },
    // Called when a file is being unlinked.
    unlink: function(fpath, cb) {
      if (options.debug) console.log('unlink(%s)', fpath);
      var entry_path = toRelPath(fpath);
      if (crypto_source.read_only) {
        return cb(fuse.EPERM);
      } else if (files_map[entry_path]) {
        removeFile(entry_path, function(err) {
          if (err) {
            console.log(err.message);
            return cb(fuse.IO);
          }
          cb();
        });
      } else {
        // console.log('ENOENT:', entry_path);
        cb(fuse.ENOENT);
      }
    },
    // Called when a file is being renamed.
    // rename: function(src, dest, cb) {

    // },
    // Called when a new link is created.
    // link: function(src, dest, cb) {

    // },
    // Called when a new symlink is created
    // symlink: function(src, dest, cb) {

    // },
    // Called when a new directory is being created
    // mkdir: function(path, mode, cb) {

    // },
    // Called when a directory is being removed
    rmdir: function(fpath, cb) {
      if (options.debug) console.log('rmdir(%s)', fpath);
      var entry_path = toRelPath(fpath);
      if (crypto_source.read_only) {
        return cb(fuse.EPERM);
      } else if (dirs_map[entry_path]) {
        removeDir(entry_path, function(err) {
          if (err) {
            console.log(err.message);
            return cb(fuse.IO);
          }
          cb();
        });
      } else {
        // console.log('ENOENT:', entry_path);
        cb(fuse.ENOENT);
      }
    },
    // Called when extended attributes of a path are being listed. buffer should be filled with 
    // the extended attribute names as null-terminated strings, one after the other, up to a total 
    // of length in length. (ERANGE should be passed to the callback if length is insufficient.) 
    // The size of buffer required to hold all the names should be passed to the callback either 
    // on success, or if the supplied length was zero.
    // listxattr: function(path, buffer, length, cb) {

    // },
    // Called when extended attributes is being read. 
    // Currently you have to write the result to the provided buffer at offset.
    // getxattr: function(path, name, buffer, length, offset, cb) {

    // },
    // Called when extended attributes is being set (see the extended docs for your platform). 
    // Currently you can read the attribute value being set in `buffer` at `offset`.
    // setxattr: function(path, name, buffer, length, offset, flags, cb) {

    // },
    // Called when an extended attribute is being removed.
    // removexattr: function(path, name, cb) {

    // },
    // destroy: function(cb) {

    // }
  }

  loadCryptoSource(function(err) {
    if (err) return callback(err);

    if (options.dry_run) return done();

    fuse.mount(mount_point, fuse_ops, function (err) {
      if (err) {
        return callback(err);
      }
      callback();
    });
  });
}

exports.unmount = function(crypto_source, mount_point, options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  if (options.debug) console.log('Unmount:', mount_point);
  fuse.unmount(mount_point, function (err) {
    if (err) return callback(err);
    callback();
  });
}
