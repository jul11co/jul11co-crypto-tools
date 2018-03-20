// lib/crypto-mount.js

var path = require('path');
var fs = require('fs');

var bytes = require('bytes');

var fuse = require('fuse-bindings');

exports.mount = function(crypto_source, mount_point, tmp_dir, options, callback) {

  var directory_trailing_slash = options.directory_trailing_slash || false;

  var dirs_map = {};
  var files_map = {};
  
  var entries_count = 0;
  var total_size = 0;

  var loadCryptoSource = function(callback) {
    crypto_source.list(function(err, result) {
      if (err) return callback(err);

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
        var dir_path = dir.path;
        var dir_relpath = dir.path;

        if (!dirs_map[dir_relpath]) {
          dirs_map[dir_relpath] = {};
          dirs_map[dir_relpath].name = path.basename(dir_relpath);
          dirs_map[dir_relpath].path = dir_relpath;
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
            dirs_map[parent_dir_relpath].size = 0;
            dirs_map[parent_dir_relpath].files = [];
            dirs_map[parent_dir_relpath].subdirs = [];
            dirs_map[parent_dir_relpath].subdirs.push(dir_relpath);
          }
        }
      });

      files.forEach(function(file) {

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
          dirs_map[dir_relpath].size = file.size;
          dirs_map[dir_relpath].files = [];
          dirs_map[dir_relpath].subdirs = [];
          dirs_map[dir_relpath].files.push(file.relpath);
        }
      });

      var dir_size_map = {};

      var getDirSize = function(dir_relpath) {
        if (!dirs_map[dir_relpath]) return 0;
        if (dir_size_map[dir_relpath]) return dir_size_map[dir_relpath];
        if (dirs_map[dir_relpath].subdirs.length == 0) {
          dir_size_map[dir_relpath] = dirs_map[dir_relpath].size;
          return dirs_map[dir_relpath].size;
        }
        var dir_size = dirs_map[dir_relpath].size; // size of files (if any)
        dirs_map[dir_relpath].subdirs.forEach(function(subdir_relpath) {
          dir_size += getDirSize(subdir_relpath);
        });
        dir_size_map[dir_relpath] = dir_size;
        return dir_size;
      }

      for(var dir_relpath in dirs_map) {
        // console.log(dir_relpath);
        dirs_map[dir_relpath].size = getDirSize(dir_relpath);
      }

      return callback();

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

  var fuse_ops = {
    // Called when the filesystem is being stat'ed. 
    // Accepts a fs `stat` object after the return code in the callback.
    statfs: function(path, cb) {
      // console.log('statfs(%s)', path);
      cb(0, {
        bsize: default_blksize,
        frsize: default_frsize,
        blocks: (Math.ceil(total_size/default_blksize)),
        bfree: 0,
        bavail: 0,
        files: entries_count,
        ffree: 0,
        favail: 0,
        // fsid: 1000000,
        // flag: 1000000,
        // namemax: 1000000
      });
    },
    // Called when a directory is being listed. 
    // Accepts an array of file/directory names after the return code in the callback
    readdir: function(path, cb) {
      // console.log('readdir(%s)', path);
      var files = [];
      var dir_path = (path == '/') ? '.' : ((path.indexOf('/')==0) ? path.substring(1) : path);
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
    getattr: function(path, cb) {
      // console.log('getattr(%s)', path);
      var entry_path = (path == '/') ? '.' : ((path.indexOf('/')==0) ? path.substring(1) : path);
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
        // console.log('birthtime:', file_entry.birthtime);
        // console.log('mtime:', file_entry.mtime);
        // console.log('atime:', file_entry.atime);
        // console.log('ctime:', file_entry.ctime);
        cb(0, {
          mtime: new Date(file_entry.mtime),
          atime: new Date(file_entry.atime),
          ctime: new Date(file_entry.ctime),
          birthtime: new Date(file_entry.birthtime||0),
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
    fgetattr: function(path, fd, cb) {
      // console.log('fgetattr(%s)', path);
      var entry_path = (path == '/') ? '.' : ((path.indexOf('/')==0) ? path.substring(1) : path);
      if (files_map[entry_path]) {
        var file_entry = files_map[entry_path];
        // console.log('birthtime:', file_entry.birthtime);
        // console.log('mtime:', file_entry.mtime);
        // console.log('atime:', file_entry.atime);
        // console.log('ctime:', file_entry.ctime);
        cb(0, {
          mtime: new Date(file_entry.mtime),
          atime: new Date(file_entry.atime),
          ctime: new Date(file_entry.ctime),
          birthtime: new Date(file_entry.birthtime||0),
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
      // console.log('open(%s, %d)', fpath, flags);
      var flag = toFlag(flags) // convert flags to a node style string
      var file_path = (fpath.indexOf('/')==0) ? fpath.substring(1) : fpath;
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
    },
    // Same as `open` but for directories
    // opendir: function(path, flags, cb) {

    // },
    // Called when contents of a file is being read. You should write the result of the read to the buffer and return 
    // the number of bytes written as the first argument in the callback. 
    // If no bytes were written (read is complete) return 0 in the callback.
    read: function(path, fd, buffer, length, position, cb) {
      // console.log('read(%s, %d, %d, %d)', path, fd, length, position);
      fs.read(fd, buffer, 0, length, position, function(err, bytesRead) {
        if (err) {
          console.log(err.message);
          return cb(fuse.EIO);
        }
        cb(bytesRead);
      });
    },
    // Called when a file is being written to. You can get the data being written in buffer and you should return 
    // the number of bytes written in the callback as the first argument.
    write: function(path, fd, buffer, length, position, cb) {
      console.log('write(%s, %d, %d, %d)', path, fd, length, position);
      return cb(fuse.EPERM);
    },
    // Called when a file descriptor is being released. Happens when a read/write is done etc.
    release: function(path, fd, cb) {
      // console.log('release(%s, %d)', path, fd);
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
    // unlink: function(path, cb) {

    // },
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
    // rmdir: function(path, cb) {

    // },
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

exports.unmount = function(crypto_source, mount_point, callback) {
  fuse.unmount(mount_point, function (err) {
    if (err) return callback(err);
    callback();
  });
}
