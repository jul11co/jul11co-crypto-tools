#!/usr/bin/env node

var fs = require('fs');
var path = require('path');
var util = require('util');

var fse = require('fs-extra');
var async = require('async');
var crypto = require('crypto');
var chalk = require('chalk');
var bytes = require('bytes');
var prompt = require('prompt');

var tar = require('tar-fs');
var tar_stream = require('tar-stream');
var humanizeDuration = require('humanize-duration');

var log = require('single-line-log').stdout;

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var PackFile = require('./lib/pack-file');

var VERSION = '0.0.2';

function printUsage() {
  console.log('cryptopack - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptopack --create,-C [OPTIONS] <input-dir> [output-pack | output-dir]');
  console.log('       cryptopack --extract,-E [OPTIONS] <input-pack> [output-dir] [entries...]');
  console.log('       cryptopack --list,-L [OPTIONS] <input-pack> [entries...]');
  console.log('       cryptopack --index,-I [OPTIONS] <input-pack>');
  console.log('       cryptopack --browse,-B [OPTIONS] <input-pack>');
  console.log('       cryptopack --mount,-M [OPTIONS] <input-pack> <mount-point>');
  console.log('');
  console.log('       cryptopack --config');
  console.log('       cryptopack --config --set-passphrase');
  console.log('       cryptopack --config --set-salt');
  console.log('       cryptopack --config --clear-encryption-key');
  console.log('       cryptopack --gen-enc-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --force                   -f    : force replace or update existing pack file');
  console.log('     --verbose                 -v    : verbose');
  console.log('     --progress                      : show progress');
  console.log('');
  console.log('     --recursive               -r    : scan input directory recursively (default: no)');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('     --enc-key=STRING                : custom encryption key');
  console.log('');
  console.log('     --min-size=<NUMBER>[GB,MB,KB]   : scan for files with minimum size (default: not set)');
  console.log('     --max-size=<NUMBER>[GB,MB,KB]   : scan for files with maximum size (default: not set)');
  console.log('');
  console.log('     --exclude-dir=<STRING>          : exclude directories contain this string');
  console.log('     --exclude-file=<STRING>         : exclude files contain this string');
  console.log('');
}

if (process.argv.length < 3 || process.argv.indexOf('--help') >= 0) {
  printUsage();
  process.exit();
}

var argv = [];
var options = {};
for (var i = 2; i < process.argv.length; i++) {
  if (process.argv[i] == '--create' || process.argv[i] == '-C') {
    options.create = true;
  } else if (process.argv[i] == '--extract' || process.argv[i] == '-E') {
    options.extract = true;
  } else if (process.argv[i] == '--list' || process.argv[i] == '-L') {
    options.list = true;
  } else if (process.argv[i] == '--index' || process.argv[i] == '-I') {
    options.index = true;
  } else if (process.argv[i] == '--browse' || process.argv[i] == '-B') {
    options.browse = true;
  } else if (process.argv[i] == '--mount' || process.argv[i] == '-M') {
    options.mount = true;
  } else if (process.argv[i] == '--default' || process.argv[i] == '-d') {
    options.default = true;
  } else if (process.argv[i] == '--ignore-errors') {
    options.ignore_errors = true;
  } else if (process.argv[i] == '--stop-if-errors' || process.argv[i] == '-e') {
    options.ignore_errors = false;
  } else if (process.argv[i] == '--recursive' || process.argv[i] == '-r') {
    options.recursive = true;
  } else if (process.argv[i] == '--force' || process.argv[i] == '-f') {
    options.force = true;
  } else if (process.argv[i] == '--verbose' || process.argv[i] == '-v') {
    options.verbose = true;
  } else if (process.argv[i].indexOf('--exclude-dir=') == 0) {
    var dir = process.argv[i].split('=')[1];
    options.exclude_dirs = options.exclude_dirs || [];
    if (options.exclude_dirs.indexOf(dir) == -1) options.exclude_dirs.push(dir);
  } else if (process.argv[i].indexOf('--exclude-file=') == 0) {
    var file = process.argv[i].split('=')[1];
    options.exclude_files = options.exclude_files || [];
    if (options.exclude_files.indexOf(file) == -1) options.exclude_files.push(file);
  } else if (process.argv[i].indexOf('--') == 0) {
    var arg = process.argv[i];
    if (arg.indexOf("=") > 0) {
      var arg_kv = arg.split('=');
      arg = arg_kv[0];
      arg = arg.replace('--','');
      arg = utils.replaceAll(arg, '-', '_');
      options[arg] = arg_kv[1];
    } else {
      arg = arg.replace('--','');
      arg = utils.replaceAll(arg, '-', '_');
      options[arg] = true;
    }
  } else {
    argv.push(process.argv[i]);
  }
}

if (typeof options.ignore_errors == 'undefined') {
  options.ignore_errors = true;
}

if (options.version) {
  console.log('cryptopack - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  process.exit();
}

if (options.salt) {
  console.log('Custom salt:', options.salt);
}

// ---

if (options.min_size) {
  var min_size = utils.parseSize(options.min_size);
  if (isNaN(min_size)) {
    console.log('Invalid min size parameter');
    process.exit();
  }
  options.min_file_size = min_size;
  console.log('Min. file size:', bytes(min_size));
}
if (options.max_size) {
  var max_size = utils.parseSize(options.max_size);
  if (isNaN(max_size)) {
    console.log('Invalid max size parameter');
    process.exit();
  }
  options.max_file_size = max_size;
  console.log('Max. file size:', bytes(max_size));
}

// ---

var config = {};
var config_dir = path.join(utils.getUserHome(), '.jul11co', 'crypto-tools');

fse.ensureDirSync(config_dir);

var config_file = path.join(config_dir, 'config.json');
if (utils.fileExists(config_file)) {
  config = utils.loadFromJsonFile(config_file);
}

var generateEncryptionKey = function(passphrase, salt) {
  return utils.sha512Hash(passphrase, salt || options.salt || config.salt || 'jul11co-crypto-tools');
}

var getPromptPassphrase = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  prompt.message = '';
  prompt.delimiter = '';
  prompt.start();

  prompt.get([{
    name: 'passphrase',
    message: chalk.magenta('Please enter passphrase:'),
    hidden: true
  }], function (err, result) {
    if (err) {
      prompt.stop();
      return callback(err);
    }
    var passphrase = result.passphrase;

    if (!options.verify) {
      prompt.stop();
      return callback(null, passphrase);
    }

    prompt.get([{
      name: 'passphrase',
      message: chalk.magenta('Please re-enter passphrase:'),
      hidden: true
    }], function (err, result) {
      if (err) {
        prompt.stop();
        return callback(err);
      }

      if (passphrase != result.passphrase) {
        console.log('Passphrases don\'t match!');
        prompt.stop();
        return callback(new Error('Passphrases don\'t match!'));
      }

      prompt.stop();
      return callback(null, passphrase);
    });
  });
}

var getPromptSalt = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  prompt.message = '';
  prompt.delimiter = '';
  prompt.start();

  prompt.get([{
    name: 'salt',
    message: chalk.magenta('Please enter salt:'),
    hidden: true
  }], function (err, result) {
    if (err) {
      prompt.stop();
      return callback(err);
    }
    
    prompt.stop();
    return callback(null, result.salt);
  });
}

/// 

function _pack(INPUT_DIR, OUTPUT_PACK, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: OUTPUT_PACK });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(OUTPUT_PACK));
  options.output_dir = TMP_DIR;

  fse.ensureDirSync(TMP_DIR);

  var output_pack_exists = false;
  if (utils.fileExists(OUTPUT_PACK)) {
    output_pack_exists = true;
  }

  var pack_opts = {};
  if (options.progress) {
    pack_opts.onEntry = function(entry) {
      console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
    }
  }

  var onDirEncrypted = function(err, result) {
    if (!err && result && result.new_files) {
      if (utils.fileExists(OUTPUT_PACK)) {
        console.log('Updating existing cryptopack...');
        pack_file.pack(TMP_DIR, pack_opts, function(err, res) {
          if (err) {
            console.log('Updating existing cryptopack... Error!');
            console.log(err);
          } else {
            if (!options.debug) fse.removeSync(TMP_DIR);
            var stats = utils.getFileStats(OUTPUT_PACK);
            if (options.progress) console.log('Updating existing cryptopack... OK');
            console.log('Cryptopack updated:', OUTPUT_PACK, chalk.magenta(stats ? bytes(stats['size']) : ''));
          }
        });
      } else {
        console.log('Creating new cryptopack...');
        pack_file.pack(TMP_DIR, pack_opts, function(err, res) {
          if (err) {
            console.log('Creating new cryptopack... Error!');
            console.log(err);
          } else {
            if (!options.debug) fse.removeSync(TMP_DIR);
            var stats = utils.getFileStats(OUTPUT_PACK);
            if (options.progress) console.log('Creating new cryptopack... OK');
            console.log('Cryptopack created:', OUTPUT_PACK, chalk.magenta(stats ? bytes(stats['size']) : ''));
          }
        });
      }
    } else {
      if (!options.debug) fse.removeSync(TMP_DIR);
      console.log('Cryptopack not changed.');
    }
  }

  var startDirEncrypt = function() {
    var crypto_index = new cryptor.CryptoIndex(path.join(TMP_DIR, 'INDEX'), ENC_KEY);
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error! ');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        process.exit();
      }

      options.onFileEncrypt = function(original_file, encrypted_file, progress) {
        log(chalk.magenta('Encrypt:'), progress.current + '/' + progress.total, 
          path.relative(INPUT_DIR, original_file.path), chalk.magenta(bytes(original_file.size)));
      }
      options.onFileEncrypted = function(original_file, encrypted_file, progress) {
        log(chalk.green('Encrypted:'), progress.current + '/' + progress.total, 
          path.relative(INPUT_DIR, original_file.path), chalk.magenta(bytes(original_file.size)));
      }
      options.onFileEncryptFailed = function(err, original_file, encrypted_file, progress) {
        log(chalk.red('Encrypt failed:'), progress.current + '/' + progress.total, 
          original_file.path, chalk.magenta(bytes(original_file.size)), err.message);
      }

      process.on('SIGINT', function() {
        console.log("\nCaught interrupt signal");
        crypto_index.unload(function(err) {
          if (err) {
            console.log('Unload crypto index error!');
            console.log(err);
          }
          onDirEncrypted(err, result);
        })
      });

      cryptor.encryptDir(INPUT_DIR, TMP_DIR, ENC_KEY, crypto_index, options, function(err, result) {
        if (err) {
          console.log('Encrypt folder error!');
          console.log(err);
        } else if (result) {
          console.log('----');
          console.log('Directory:', result.dirs.length + ' director' + ((result.dirs.length != 1) ? 'ies.': 'y.'));
          console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

          // console.log(result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
          //   + ' (' + bytes(result.total_size) + ') processed.');

          if (result.encrypted && result.encrypted.length) {
            console.log('Encrypted:', chalk.magenta(result.encrypted.length 
              + ' file' + ((result.encrypted.length != 1) ? 's': '') 
              + ' (' + bytes(result.encrypted_size) + ').'));
          }

          if (result.errors && result.errors.length) {
            console.log('----');
            console.log(chalk.red(errors.length + ' errors.'));
            result.errors.forEach(function(error) {
              console.log(error);
            });
          }
        }

        crypto_index.unload(function(err) {
          if (err) {
            console.log('Unload crypto index error!');
            console.log(err);
          }
          onDirEncrypted(err, result);
        })
      });
    });
  }

  // fse.ensureDirSync(INPUT_DIR);
  fse.emptyDirSync(TMP_DIR);

  if (utils.fileExists(OUTPUT_PACK)) {
    console.log('Reading existing cryptopack...');
    pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
      if (err) {
        console.log('Reading existing cryptopack... Error!');
        console.log(err);
      } else {
        if (options.progress) console.log('Reading existing cryptopack... OK');
        startDirEncrypt();
      }
    });
  } else {
    startDirEncrypt();
  }
}

function _extract(INPUT_PACK, OUTPUT_DIR, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_PACK });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_PACK));
  options.input_dir = TMP_DIR;

  fse.ensureDirSync(OUTPUT_DIR);

  var onDirDecrypted = function() {
    if (!options.debug) fse.removeSync(TMP_DIR);
    console.log('Cryptopack unpacked.');
  }

  var startDirDecrypt = function() {
    var crypto_index = new cryptor.CryptoIndex(path.join(TMP_DIR, 'INDEX'), ENC_KEY, {read_only: true});
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        process.exit();
      }

      var entries = [];

      if (options.extract_entries && options.extract_entries.length) {
        for (var file_id in crypto_index.map()) {
          var file_info = crypto_index.get(file_id);
          var will_extract = options.extract_entries.some(function(entry) {
            return (file_info.name.indexOf(entry) == 0);
          });
          if (will_extract) {
            entries.add(path.join(file_id[0], file_id[1], file_id[2], file_id));
          }
        }
      }

      var extract_opts = {overwrite: true};
      if (entries.length) {
        extract_opts.entries = entries;
      }
      if (options.progress) {
        extract_opts.onEntry = function(entry) {
          console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
        }
      }

      pack_file.extract(TMP_DIR, extract_opts, function(err, result) {
        if (err) {
          console.log('Extract files failed!');
          console.log(err);
        } else {

          options.onFileDecrypt = function(decrypted_file, encrypted_file, progress) {
            log(chalk.magenta('Decrypt:'), progress.current + '/' + progress.total, 
              decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
          }
          options.onFileDecrypted = function(decrypted_file, encrypted_file, progress) {
            log(chalk.green('Decrypted:'), progress.current + '/' + progress.total, 
              decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
          }
          options.onFileDecryptFailed = function(err, decrypted_file, encrypted_file, progress) {
            log(chalk.red('Decrypted failed:'), progress.current + '/' + progress.total, 
              decrypted_file.path, chalk.magenta(bytes(decrypted_file.size)));
          }

          // decrypt extracted folder
          cryptor.decryptDir(TMP_DIR, OUTPUT_DIR, ENC_KEY, crypto_index, options, function(err, result) {
            if (err) {
              console.log('Decrypt folder error!');
              console.log(err);
            } else if (result) {
              console.log('----');
              console.log('Total:', result.files.length + ' file' + ((result.files.length != 1) ? 's.': '.'));

              // console.log(result.processed.length + ' file' + ((result.processed.length != 1) ? 's': '') 
              //   + ' (' + bytes(result.total_size) + ') processed.');

              if (result.decrypted && result.decrypted.length) {
                console.log('Decrypted:', chalk.magenta(result.decrypted.length 
                  + ' file' + ((result.decrypted.length != 1) ? 's': '') 
                  + ' (' + bytes(result.decrypted_size) + ').'));
              }
              
              if (result.errors && result.errors.length) {
                console.log('----');
                console.log(chalk.red(result.errors.length + ' errors.'));
                result.errors.forEach(function(error) {
                  console.log(error);
                });
              }
            }
            
            // unload index
            crypto_index.unload(function(err) {
              if (err) {
                console.log('Unload crypto index error!');
                console.log(err);
              }
              onDirDecrypted();
            });
          });
        }
      });
    });
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  console.log('Reading cryptopack...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptopack... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptopack... OK');
      startDirDecrypt();
    }
  });
}

function _list(INPUT_PACK, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_PACK });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_PACK));
  options.input_dir = TMP_DIR;

  var startPackList = function() {
    var crypto_index = new cryptor.CryptoIndex(path.join(TMP_DIR, 'INDEX'), ENC_KEY, {read_only: true});
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        process.exit();
      }
      
      var count = 0;
      var total_size = 0;

      var largest_size = 0;
      var largest_file = {};

      // print file list from INDEX
      for (var file_id in crypto_index.map()) {
        var file_info = crypto_index.get(file_id);
        var will_list = true;
        if (options.list_entries) {
          will_list = options.list_entries.some(function(entry) {
            return (file_info.p.indexOf(entry) == 0);
          });
        }
        if (will_list) {
          count++;
          console.log(utils.padLeft(''+count, 6)+'.', chalk.magenta(utils.padLeft(bytes(file_info.s), 8)), file_info.p);
          total_size += file_info.s;
          if (file_info.s > largest_size) {
            largest_size = file_info.s;
            largest_file = {path: file_info.p, size: file_info.s};
          }
        }
      }

      console.log('----');
      console.log('Total files:', count);
      console.log('Total size:', bytes(total_size));
      if (largest_size>0) {
        console.log('Largest file:', chalk.magenta(bytes(largest_file.size)), largest_file.path);
      }
      
      crypto_index.unload(function(err) {
        if (err) {
          console.log('Unload crypto index error!');
          console.log(err);
        }
      });
    });
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  console.log('Reading cryptopack...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptopack... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptopack... OK');
      startPackList();
    }
  });
}

function _index(INPUT_PACK, options, done) {

  var pack_file = new PackFile({ path: INPUT_PACK });

  var index_opts = {overwrite: true};
  if (options.progress) {
    index_opts.onEntry = function(entry) {
      console.log((entry.type || 'File')[0], entry.name || entry.path, chalk.magenta(bytes(entry.size)));
    }
  }

  if (options.progress) console.log('Generating index...');
  var start_time = new Date();
  pack_file.createIndex(index_opts, function(err) {
    if (err) {
      console.log('Generating index... Error!');
      console.log(err);
      process.exit();
    }
    if (options.progress) console.log('Generating index... Done');
    if (options.progress) console.log('INDEXING TIME:', humanizeDuration(new Date()-start_time));

    var idx_stats = pack_file.getIndexStats();
    if (idx_stats) {
      console.log('Entries count:', idx_stats.entriesCount);
      console.log('Total size:', bytes(idx_stats.totalSize));
    }

    var idx_file = argv[1] || INPUT_PACK + '.idx';
    pack_file.saveIndex(idx_file, function(err) {
      if (err) {
        console.log('Saving index to file... Error!');
        console.log(err);
        process.exit();
      }

      var stat = utils.getStat(idx_file);
      if (stat) {
        console.log('Index file created:', idx_file, bytes(stat['size']));
      } else {
        console.log('Cannot generate index file!', idx_file);
      }
      process.exit();
    });
  });
}

function _browse(INPUT_PACK, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_PACK });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_PACK));
  options.input_dir = TMP_DIR;

  var DECRYPTED_TMP_DIR = path.join(TMP_DIR, '_DECRYPTED');

  var crypto_index = null;
  var browser_opts = {};
  var entries_map = {};

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
    fse.emptyDirSync(TMP_DIR);
  });

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

  var loadCryptoIndex = function(callback) {
    if (!crypto_index) return callback(new Error('Crypto index not specified.'));
    if (crypto_index.loaded()) return callback();
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        return callback(err);
      }
      callback();
    });
  }

  var unloadCryptoIndex = function(callback) {
    if (!crypto_index || !crypto_index.loaded()) return callback();
    crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index error!');
        console.log(err);
      }
      callback(err);
    });
  }

  var listPack = function(opts, callback) {
    if (typeof opts == 'function') {
      callback = opts;
      opts = {};
    }
    if (!crypto_index.loaded()) {
      return loadCryptoIndex(function(err) {
        if (err) {
          return callback(err);
        }
        listPack(opts, callback);
      });
    }

    var result = {
      entries: [],
      totalSize: 0
    }

    for (var file_id in crypto_index.map()) {
      var file_info = crypto_index.get(file_id);
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
      entries_map[entry.path] = entry;
      // add entries for parent dirs (if not added)
      var dirs = getParentDirs(entry.path);
      if (dirs.length) {
        dirs.forEach(function(dir_relpath) {
          if (!entries_map[dir_relpath]) {
            entries_map[dir_relpath] = {
              type: 'directory',
              path: dir_relpath,
              size: 0,
              mtime: entry.mtime
            }
          } else if (entries_map[dir_relpath].mtime < entry.ctime) {
            entries_map[dir_relpath].mtime = entry.ctime;
          }
        });
      }
    }

    for (var entry_path in entries_map) {
      var entry = entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    unloadCryptoIndex(function() {
      return callback(null, result);
    });
  }

  var extractEntry = function(fpath, output_dir, opts, callback) {
    if (!entries_map[fpath] || !entries_map[fpath].encrypted_path) {
      return callback(new Error('Entry not found: ' + fpath));
    }
    
    var entry = entries_map[fpath];
    var encrypted_file_abs_path = path.join(TMP_DIR, entry.encrypted_path);

    // console.log('extractEntry:', fpath);

    pack_file.extractEntry(entry.encrypted_path, TMP_DIR, function(err) {
      if (err) return callback(err);
      if (!utils.fileExists(encrypted_file_abs_path)) {
        return callback(new Error('File not extracted:', encrypted_file_abs_path));
      }

      var decrypted_file_abs_path = path.join(DECRYPTED_TMP_DIR, entry.path);
      fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

      cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, ENC_KEY, function(err) {
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
    })
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  console.log('Reading cryptopack...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptopack... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptopack... OK');

      crypto_index = new cryptor.CryptoIndex(path.join(TMP_DIR, 'INDEX'), ENC_KEY, {read_only: true});
      var crypto_source = {
        path: pack_file.path(),
        listEntry: listPack,
        getEntry: extractEntry
      };
      require('./lib/crypto-browser')(crypto_source, DECRYPTED_TMP_DIR, browser_opts);
    }
  });
}

function _mount(INPUT_PACK, MOUNT_POINT, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_PACK });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_PACK));
  options.input_dir = TMP_DIR;

  var DECRYPTED_TMP_DIR = path.join(TMP_DIR, '_DECRYPTED');
  options.tmp_dir = DECRYPTED_TMP_DIR;

  var crypto_index = null;
  var entries_map = {};

  process.on('exit', function() {
    fse.emptyDirSync(DECRYPTED_TMP_DIR);
    fse.emptyDirSync(TMP_DIR);
  });

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

  var loadCryptoIndex = function(callback) {
    if (!crypto_index) return callback(new Error('Crypto index not specified.'));
    if (crypto_index.loaded()) return callback();
    // load index
    crypto_index.load(function(err) {
      if (err) {
        console.log('Load crypto index error!');
        // console.log(err);
        if (err.message.indexOf('bad decrypt')!=-1) {
          console.log(chalk.red('Wrong passphrase.'));
        }
        return callback(err);
      }
      callback();
    });
  }

  var unloadCryptoIndex = function(callback) {
    if (!crypto_index || !crypto_index.loaded()) return callback();
    crypto_index.unload(function(err) {
      if (err) {
        console.log('Unload crypto index error!');
        console.log(err);
      }
      callback(err);
    });
  }

  var listPack = function(opts, callback) {
    if (typeof opts == 'function') {
      callback = opts;
      opts = {};
    }
    if (!crypto_index.loaded()) {
      return loadCryptoIndex(function(err) {
        if (err) {
          return callback(err);
        }
        listPack(opts, callback);
      });
    }

    var result = {
      entries: [],
      totalSize: 0
    }

    for (var file_id in crypto_index.map()) {
      var file_info = crypto_index.get(file_id);
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
      entries_map[entry.path] = entry;
      // add entries for parent dirs (if not added)
      var dirs = getParentDirs(entry.path);
      if (dirs.length) {
        dirs.forEach(function(dir_relpath) {
          if (!entries_map[dir_relpath]) {
            entries_map[dir_relpath] = {
              type: 'directory',
              path: dir_relpath,
              size: 0,
              mtime: entry.mtime
            }
          } else if (entries_map[dir_relpath].mtime < entry.ctime) {
            entries_map[dir_relpath].mtime = entry.ctime;
          }
        });
      }
    }

    for (var entry_path in entries_map) {
      var entry = entries_map[entry_path];
      result.totalSize += entry.size;
      result.entries.push(entry);
    }

    unloadCryptoIndex(function() {
      return callback(null, result);
    });
  }

  var extractEntry = function(fpath, output_dir, opts, callback) {
    if (!entries_map[fpath] || !entries_map[fpath].encrypted_path) {
      return callback(new Error('Entry not found: ' + fpath));
    }
    
    var entry = entries_map[fpath];
    var encrypted_file_abs_path = path.join(TMP_DIR, entry.encrypted_path);

    // console.log('extractEntry:', fpath);

    pack_file.extractEntry(entry.encrypted_path, TMP_DIR, function(err) {
      if (err) return callback(err);
      if (!utils.fileExists(encrypted_file_abs_path)) {
        return callback(new Error('File not extracted:', encrypted_file_abs_path));
      }

      var decrypted_file_abs_path = path.join(output_dir, entry.path);
      fse.ensureDirSync(path.dirname(decrypted_file_abs_path));

      cryptor.decryptFile(encrypted_file_abs_path, decrypted_file_abs_path, ENC_KEY, function(err) {
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
    })
  }

  // fse.ensureDirSync(TMP_DIR);
  fse.emptyDirSync(TMP_DIR);

  if (!utils.directoryExists(MOUNT_POINT)) {
    fse.ensureDirSync(MOUNT_POINT);
  }

  console.log('Reading cryptopack...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptopack... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptopack... OK');

      crypto_index = new cryptor.CryptoIndex(path.join(TMP_DIR, 'INDEX'), ENC_KEY, {read_only: true});
      var crypto_source = {
        path: pack_file.path(),
        list: listPack,
        getEntry: extractEntry
      };

      var mounted = false;
      var crypto_mount = require('./lib/crypto-mount');

      crypto_mount.mount(crypto_source, MOUNT_POINT, DECRYPTED_TMP_DIR, options, function(err) {
        if (err) {
          console.log(err);
          return done(err);
        }
        mounted = true;
        console.log('Crypto folder mounted on ' + MOUNT_POINT);

        process.on('SIGINT', function () {
          if (!mounted) return;

          crypto_mount.unmount(crypto_source, MOUNT_POINT,function(err) {
            if (err) {
              console.log('Can not unmount: ' + MOUNT_POINT, err);
              console.log(err);
            } else {
              console.log('Unmounted: ' + MOUNT_POINT);
            }
          });
        })
      });
    }
  });
}

/////

if (options.config) {
  if (options.set_passphrase) {
    getPromptPassphrase({verify: true}, function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var enc_key = generateEncryptionKey(passphrase);
      config.enc_key = enc_key;
      utils.saveToJsonFile(config, config_file);
      console.log('Config saved.');
      process.exit();
    });
  } else if (options.clear_encryption_key) {
    delete config.enc_key;    
    utils.saveToJsonFile(config, config_file);
    console.log('Config saved.');
    process.exit();
  } else if (options.set_salt) {
    getPromptSalt(function(err, salt) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      config.salt = salt;
      utils.saveToJsonFile(config, config_file);
      console.log('Config saved.');
      process.exit();
    });
  } else {
    console.log(config);
    process.exit();
  }
} else if (options.gen_enc_key) {
  getPromptPassphrase({verify: true}, function(err, passphrase) {
    if (err) {
      // console.log(err);
      process.exit();
    }
    var ENC_KEY = generateEncryptionKey(passphrase);
    console.log('Encryption key:', ENC_KEY);
  });
} else if (options.create || (argv[0] && utils.directoryExists(argv[0]))) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_DIR = path.resolve(argv[0]);
  if (!utils.directoryExists(INPUT_DIR)) {
    console.log('Directory not found:', INPUT_DIR);
    process.exit();
  }
  console.log('Input directory: ' + INPUT_DIR 
    + (options.recursive ? chalk.magenta(' (recursive)') : chalk.yellow(' (without recursive)')));
  options.input_dir = INPUT_DIR;

  var default_output_pack = path.join(path.dirname(INPUT_DIR), path.basename(INPUT_DIR) + '.cryptopack');
  var OUTPUT_PACK = default_output_pack;
  if (argv[1] && utils.directoryExists(path.resolve(argv[1]))) {
    var output_dir = path.resolve(argv[1]);
    OUTPUT_PACK = path.join(output_dir, path.basename(INPUT_DIR) + '.cryptopack');
  } else if (argv[1]) {
    OUTPUT_PACK = path.resolve(argv[1]);
  }

  if (!options.force && utils.fileExists(OUTPUT_PACK)) {
    console.log(chalk.red('Cryptopack exists:'), OUTPUT_PACK);
    console.log(chalk.grey('Hint: Add --force or -f to update existing cryptopack.'));
    process.exit();
  }
  console.log('Cryptopack: ' + OUTPUT_PACK);

  if ((options.default && config.enc_key) || options.enc_key) {
    _pack(INPUT_DIR, OUTPUT_PACK, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase({verify: true}, function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _pack(INPUT_DIR, OUTPUT_PACK, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.extract) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var default_output_dir = path.join(path.dirname(INPUT_PACK), path.basename(INPUT_PACK, path.extname(INPUT_PACK)));
  var OUTPUT_DIR = argv[1] ? path.resolve(argv[1]) : default_output_dir;
  if (!options.force && utils.directoryExists(OUTPUT_DIR)) {
    console.log(chalk.red('Directory exists:'), OUTPUT_DIR);
    console.log(chalk.grey('Hint: Add --force or -f to merge/replace files in existing directory.'));
    process.exit();
  }
  console.log('Extract to: ' + OUTPUT_DIR);
  options.output_dir = OUTPUT_DIR;

  var entries_to_extract = [];
  if (argv.length > 2) {
    for (var i = 2; i < argv.length; i++) {
      entries_to_extract.push(argv[i]);
    }
  }
  if (entries_to_extract.length) {
    options.extract_entries = entries_to_extract;
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    _extract(INPUT_PACK, OUTPUT_DIR, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _extract(INPUT_PACK, OUTPUT_DIR, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.list) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var entries_to_list = [];
  if (argv.length > 1) {
    for (var i = 1; i < argv.length; i++) {
      entries_to_list.push(argv[i]);
    }
  }
  if (entries_to_list.length) {
    options.list_entries = entries_to_list;
  }

  if ((options.default && config.enc_key) || options.enc_key) {
    _list(INPUT_PACK, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _list(INPUT_PACK, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.browse) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  if ((options.default && config.enc_key) || options.enc_key) {
    _browse(INPUT_PACK, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else if (options.passphrase) {
    var ENC_KEY = generateEncryptionKey(options.passphrase);
    _browse(INPUT_PACK, ENC_KEY, options, function(err) {
      if (err) {
        console.log(err);
      }
      process.exit();
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _browse(INPUT_PACK, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.mount) {

  if (argv.length < 2) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  var MOUNT_POINT = path.resolve(argv[1]);
  options.mount_point = MOUNT_POINT;
  console.log('Mount point: ' + MOUNT_POINT);
  
  if ((options.default && config.enc_key) || options.enc_key) {
    _mount(INPUT_PACK, MOUNT_POINT, options.enc_key || config.enc_key, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else if (options.passphrase) {
    var ENC_KEY = generateEncryptionKey(options.passphrase);
    _mount(INPUT_PACK, MOUNT_POINT, ENC_KEY, options, function(err) {
      if (err) {
        console.log(err);
      }
    })
  } else {
    getPromptPassphrase(function(err, passphrase) {
      if (err) {
        // console.log(err);
        console.log('');
        process.exit();
      }
      var ENC_KEY = generateEncryptionKey(passphrase);
      _mount(INPUT_PACK, MOUNT_POINT, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
      })
    });
  }
} else if (options.index) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_PACK = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_PACK)) {
    console.log(chalk.red('Cryptopack not found:'), INPUT_PACK);
    process.exit();
  }
  console.log('Cryptopack: ' + INPUT_PACK);

  _index(INPUT_PACK, options, function(err) {
    if (err) {
      console.log(err);
    }
    process.exit();
  })

} else {
  printUsage();
  process.exit();
}
