// lib/crypto-browser.js

var path = require('path');
var fs = require('fs');

var fse = require('fs-extra');
var moment = require('moment');
var bytes = require('bytes');
var open = require('open');

var JobQueue = require('jul11co-jobqueue');

var utils = require('./utils');

module.exports = function(crypto_source, tmp_dir, options, done) {
  if (typeof options == 'function') {
    done = options;
    options = {};
  }
  options = options || {};
  done = done || function() {};

  var extract_queue = new JobQueue();

  var directory_trailing_slash = options.directory_trailing_slash || false;
  var listen_port = options.listen_post || 31120;

  var all_dirs = [];

  var dirs_map = {};
  var files_map = {};

  var image_files = [];
  var video_files = [];
  var all_files = [];
    
  var file_types_map = {};
  var popular_file_types = [];

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
    // else if (parent == '.') {
    //   parents.push(parent);
    // }
    return parents;
  }

  var sortItems = function(items, field, order) {
    if (order == 'desc') {
      items.sort(function(a,b) {
        if (a[field] > b[field]) return -1;
        if (a[field] < b[field]) return 1;
        return 0;
      });
    } else {
      items.sort(function(a,b) {
        if (a[field] > b[field]) return 1;
        if (a[field] < b[field]) return -1;
        return 0;
      });
    }
  }

  var extractFile = function(file_path, callback) {

    var file_abs_path = path.join(tmp_dir, file_path);

    if (utils.fileExists(file_abs_path) || utils.directoryExists(file_abs_path)) {
      return callback(file_abs_path);
    } else if (crypto_source) {
      // add to queue
      extract_queue.pushJob({
        file_path: file_path,
        output_dir: tmp_dir
      }, function(opts, done) { // handler
        crypto_source.getEntry(opts.file_path, opts.output_dir, {}, function(err) {
          done(err);
        });
      }, function(err) { // complete
        if (err) {
          console.log('Extract file error:', file_path);
          console.log(err.message);
          return callback();
        }
        if (!utils.fileExists(file_abs_path) && !utils.directoryExists(file_abs_path)) {
          console.log('File not extracted:', file_abs_path);
          return callback();
        }
        return callback(file_abs_path);
      });
    } else {
      console.log('File not found:', file_path);
      return callback();
    }
  }

  var startServer = function(cb) {
    var express = require('express');
    var session = require('express-session');

    var app = express();

    // view engine setup
    app.set('views', path.join(__dirname, '..', 'views'));
    app.set('view engine', 'ejs');
    app.use(session({
      secret: 'jul11co-crypto-browser',
      resave: true,
      saveUninitialized: true
    }));
    app.use(express.static(path.join(__dirname, '..', 'public')))

    // GET /
    // GET /?dir=...
    // GET /?images=1
    app.get('/', function(req, res) {
      var dirs = [];
      var files = [];

      var dir_path = req.query.dir ? req.query.dir : '.';
      if (directory_trailing_slash && utils.lastChar(dir_path) != '/') {
        dir_path = dir_path + '/';
      }
      
      var total_size = 0;

      // console.log(dir_parents);
      var parents = [];
      if (dir_path != '.' && dir_path != './') {
        var dir_parents = getParentDirs(dir_path, {trailing_slash: directory_trailing_slash});
        parents = dir_parents.map(function(parent_path) {
          return {path: parent_path, name: path.basename(parent_path)};
        });
      }
      
      // console.log('Path:', dir_path);
      if (req.query.images) {
        files = image_files.map(function(file_relpath) {
          return files_map[file_relpath];
        });
      } 
      else if (req.query.videos) {
        files = video_files.map(function(file_relpath) {
          return files_map[file_relpath];
        });
      }
      else if (req.query.files) {
        files = all_files.map(function(file_relpath) {
          return files_map[file_relpath];
        });
      }
      else if (req.query.file_type) {
        files = file_types_map[req.query.file_type].files.map(function(file_relpath) {
          return files_map[file_relpath];
        });
      }
      else if (dir_path && dirs_map[dir_path]) {
        dirs = dirs_map[dir_path].subdirs.map(function(dir_relpath) {
          return {
            name: dirs_map[dir_relpath].name,
            path: dirs_map[dir_relpath].path,
            size: dirs_map[dir_relpath].size,
            atime: dirs_map[dir_relpath].atime,
            mtime: dirs_map[dir_relpath].mtime,
            ctime: dirs_map[dir_relpath].ctime,
            subdirs_count: dirs_map[dir_relpath].subdirs.length,
            files_count: dirs_map[dir_relpath].files.length
          }
        });
        files = dirs_map[dir_path].files.map(function(file_relpath) {
          return files_map[file_relpath];
        });
      }

      dirs.forEach(function(dir){ total_size += dir.size || 0; });
      files.forEach(function(file) { total_size += file.size || 0; })

      var query = Object.assign({}, req.query);

      // console.log('Dirs:', dirs.length);
      // console.log('Files:', files.length);
      if (query.sort == 'size') {
        sortItems(dirs, 'size', query.order || 'desc');
        sortItems(files, 'size', query.order || 'desc');
        if (req.session) {
          req.session.sort = query.sort;
          req.session.order = query.order || 'desc';
        }
      } else if (query.sort == 'mtime') {
        sortItems(dirs, 'mtime', query.order || 'desc');
        sortItems(files, 'mtime', query.order || 'desc');
        if (req.session) {
          req.session.sort = query.sort;
          req.session.order = query.order || 'desc';
        }
      } else if (query.sort == 'type') {
        sortItems(files, 'type', query.order || 'asc');
        if (req.session) {
          req.session.sort = query.sort;
          req.session.order = query.order || 'asc';
        }
      } else if (query.sort != 'name' && req.session.sort) {
        // console.log(req.session.sort, req.session.order);
        sortItems(dirs, req.session.sort, query.order || req.session.order);
        sortItems(files, req.session.sort, query.order || req.session.order);
        query.sort = req.session.sort;
        query.order = query.order || req.session.order;
      } else {
        sortItems(dirs, 'name', query.order || 'asc');
        sortItems(files, 'name', query.order || 'asc');
        if (req.session) {
          delete req.session.sort;
          delete req.session.order;
        }
      }

      query.limit = query.limit ? parseInt(query.limit) : 1000;
      query.skip = query.skip ? parseInt(query.skip) : 0;
      
      var start_index = Math.min(query.skip, files.length);
      var end_index = Math.min(query.skip + query.limit, files.length);
      var files_length = files.length;
      files = files.slice(start_index, end_index);

      res.render('crypto-browser', {
        query: query,
        title: path.basename(crypto_source.path),
        parents: parents,
        dir_path: dir_path,
        dir_name: path.basename(dir_path),
        total_size: total_size,
        dirs: dirs,
        files: files,
        files_length: files_length,
        files_count: all_files.length,
        images_count: image_files.length,
        videos_count: video_files.length,
        popular_file_types: popular_file_types,
        path: path,
        bytes: bytes,
        moment: moment,
        ellipsisMiddle: utils.ellipsisMiddle
      });
    });

    // GET /open?path=...
    app.get('/open', function(req, res) {
      extractFile(req.query.path, function(file_abs_path) {
        if (!file_abs_path) {
          return res.status(404).send('Path not found! ' + req.query.path);
        }

        var fpath = file_abs_path; // path.join(data_dir, req.query.path);
        open(fpath);
        return res.json({ok: 1});
      });
    });

    var getFile = function(req, res) {
      extractFile(req.query.path, function(file_abs_path) {
        if (!file_abs_path) {
          return res.status(404).send('Path not found! ' + req.query.path);
        }

        var filepath = file_abs_path; // path.join(data_dir, req.query.path);
        return res.sendFile(filepath);
      });
    }

    // GET /file?path=...
    app.get('/file', getFile);
    app.get('/files/:filename', getFile);

    var stat_map = {};

    // GET /video?path=...
    app.get('/video', function(req, res) {
      if (typeof crypto_source.getEntryDataBuffer == 'function') {

        var filepath = req.query.path;
        var file = files_map[filepath];

        var fileSize = file.size
        var range = req.headers.range

        if (range) {
          console.log('Range:', range);

          var parts = range.replace(/bytes=/, "").split("-")
          var start = parseInt(parts[0], 10)
          var end = parts[1]
            ? parseInt(parts[1], 10)
            : fileSize-1

          var chunksize = (end-start)+1
          // if (chunksize > 100000) {
          //   chunksize = 100000
          //   end = (chunksize-1)+start;
          // }

          var head = {
            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
            'Accept-Ranges': 'bytes',
            'Content-Length': chunksize,
            'Content-Type': 'video/mp4',
          }
          if (path.extname(filepath) == '.webm') {
            head['Content-Type'] = 'video/webm';
          }

          crypto_source.getEntryDataBuffer(filepath, start, chunksize, function(err, buf) {
            if (err) {
              res.status(500).send(err.message);
            } else if (!buf) {
              res.status(500).send('Cannot get buffer');
            } else {
              console.log(head);
              res.writeHead(206, head)
              res.end(buf);
            }
          });
        } else {
          var head = {
            'Content-Length': fileSize,
            'Content-Type': 'video/mp4',
          }
          if (path.extname(filepath) == '.webm') {
            head['Content-Type'] = 'video/webm';
          }

          crypto_source.getEntryDataBuffer(filepath, 0, fileSize, function(err, buf) {
            if (err) {
              res.status(500).send(err.message);
            } else if (!buf) {
              res.status(500).send('Cannot get buffer');
            } else {
              res.writeHead(200, head)
              res.end(buf);
            }
          });
        }
      } else {
        extractFile(req.query.path, function(file_abs_path) {
          if (!file_abs_path) {
            return res.status(404).send('Path not found! ' + req.query.path);
          }

          var filepath = file_abs_path; // path.join(data_dir, req.query.path);

          if (!stat_map[filepath]) {
            stat_map[filepath] = fs.statSync(filepath);
          }

          var stat = stat_map[filepath];
          var fileSize = stat.size
          var range = req.headers.range

          if (range) {
            console.log('Range:', range);
            
            var parts = range.replace(/bytes=/, "").split("-")
            var start = parseInt(parts[0], 10)
            var end = parts[1]
              ? parseInt(parts[1], 10)
              : fileSize-1

            var chunksize = (end-start)+1
            var file = fs.createReadStream(filepath, {start, end})
            var head = {
              'Content-Range': `bytes ${start}-${end}/${fileSize}`,
              'Accept-Ranges': 'bytes',
              'Content-Length': chunksize,
              'Content-Type': 'video/mp4',
            }
            if (path.extname(filepath) == '.webm') {
              head['Content-Type'] = 'video/webm';
            }

            res.writeHead(206, head)
            file.pipe(res)
          } else {
            var head = {
              'Content-Length': fileSize,
              'Content-Type': 'video/mp4',
            }
            if (path.extname(filepath) == '.webm') {
              head['Content-Type'] = 'video/webm';
            }
            res.writeHead(200, head)
            fs.createReadStream(filepath).pipe(res)
          }
        });
      }
    });

    var startListen = function(cb) {
      app.listen(listen_port, function () {
        console.log('Listening on http://localhost:'+listen_port);
        if (!options.no_open) open('http://localhost:'+listen_port);
        cb(null, listen_port);
      }).on('error', function(err) {
      if (err.code == 'EADDRINUSE') {
          setTimeout(function() {
            listen_port = listen_port + 1;
            startListen(cb);
          });
        } else {
          console.log(err);
        }
      });
    }

    startListen(cb);
  }

  // var supported_file_types = [
  //   'mp4','mkv','avi','wmv','webm',
  //   'png','gif','jpg','jpeg',
  //   'txt'
  // ];
  var image_file_types = [
    'jpg','jpeg','png','gif',
  ];
  var video_file_types = [
    'mp4','webm',
  ];

  var list_opts = {};
  // list_opts.file_types = supported_file_types;

  var addDirToMap = function(dir) {
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
  }

  var addFileToMap = function(file) {
    file.relpath = file.path; // path.relative(data_dir, file.path);
    file.type = (file.type) ? file.type.toLowerCase() : '';

    files_map[file.relpath] = file;

    if (image_file_types.indexOf(file.type)!=-1) {
      image_files.push(file.relpath);
    } else if (video_file_types.indexOf(file.type)!=-1) {
      video_files.push(file.relpath);
    }
    all_files.push(file.relpath);

    if (file.type && file.type != '') {
      if (!file_types_map[file.type]) {
        file_types_map[file.type] = {};
        file_types_map[file.type].count = 0;
        file_types_map[file.type].files = [];
      }
      file_types_map[file.type].count++;
      file_types_map[file.type].files.push(file.relpath);
    }
    
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

  console.log('Loading entries...');

  crypto_source.listEntry(list_opts, function(err, result) {
    if (err) {
      console.log('List crypto source failed!', crypto_source.path);
      // console.log(err);
      return done(err);
    }

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
        mtime: entry.mtime
      }
    });
    
    console.log('Dirs:', dirs.length);
    // files = files.filter(function(file) { 
    //   return supported_file_types.indexOf(file.type) != -1;
    // });
    console.log('Files:', files.length);

    var total_files_size = 0;
    files.forEach(function(file) { 
      // console.log('File:', file.path);
      total_files_size += file.size;
    });
    console.log('Size:', bytes(total_files_size));

    dirs.forEach(function(dir) {
      addDirToMap(dir);
    });

    files.forEach(function(file) {
      addFileToMap(file);
    });

    // console.log(dirs_map);

    var dir_size_map = {};
    for(var dir_relpath in dirs_map) {
      dirs_map[dir_relpath].size = getDirSize(dir_relpath, dir_size_map);
    }

    // sort all dirs by name
    // all_dirs.sort(function(a,b) {
    //   if (a.path > b.path) return 1;
    //   if (a.path < b.path) return -1;
    //   return 0;
    // });

    // get popular file types
    var file_types = [];
    for(var file_type in file_types_map) {
      file_types.push({type: file_type, count: file_types_map[file_type].count});
    }
    file_types.sort(function(a,b) {
      if (a.count>b.count) return -1;
      if (a.count<b.count) return 1;
      return 0;
    });
    if (file_types.length > 10) popular_file_types = file_types.slice(0, 10);
    else popular_file_types = file_types.slice(0);

    startServer(done);
  });
}