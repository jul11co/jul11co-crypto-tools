#!/usr/bin/env node

var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var fse = require('fs-extra');
var async = require('async');
var chalk = require('chalk');
var bytes = require('bytes');
var prompt = require('prompt');

var utils = require('./lib/utils');
var cryptor = require('./lib/cryptor');

var PackFile = require('./lib/pack-file');

var VERSION = '0.0.1';

function printUsage() {
  console.log('cryptofile - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  console.log('');
  console.log('Usage:');
  console.log('       cryptofile --encode,-E [OPTIONS] <input-file> [encrypted-file]');
  console.log('       cryptofile --decode,-D [OPTIONS] <encrypted-file> [output-file]');
  console.log('       cryptofile --info [OPTIONS] <encrypted-file>');
  console.log('');
  console.log('       cryptofile --config');
  console.log('       cryptofile --config --set-passphrase');
  console.log('       cryptofile --config --set-salt');
  console.log('       cryptofile --config --clear-encryption-key');
  console.log('');
  console.log('OPTIONS:');
  console.log('');
  console.log('     --default                 -d    : use default encryption key (if exists)');
  console.log('');
  console.log('     --force                   -f    : force replace or update existing pack file');
  console.log('     --verbose                 -v    : verbose');
  console.log('');
  console.log('     --gen-enc-key                   : generate encryption key');
  console.log('     --enc-key=STRING                : custom encryption key');
  console.log('');
}

if (process.argv.length < 3 || process.argv.indexOf('--help') >= 0) {
  printUsage();
  process.exit();
}

var argv = [];
var options = {};
for (var i = 2; i < process.argv.length; i++) {
  if (process.argv[i] == '--encode' || process.argv[i] == '-E') {
    options.encode = true;
  } else if (process.argv[i] == '--decode' || process.argv[i] == '-D') {
    options.decode = true;
  } else if (process.argv[i] == '--default' || process.argv[i] == '-d') {
    options.default = true;
  } else if (process.argv[i] == '--ignore-errors') {
    options.ignore_errors = true;
  } else if (process.argv[i] == '--stop-if-errors' || process.argv[i] == '-e') {
    options.ignore_errors = false;
  } else if (process.argv[i] == '--force' || process.argv[i] == '-f') {
    options.force = true;
  } else if (process.argv[i] == '--verbose' || process.argv[i] == '-v') {
    options.verbose = true;
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
  console.log('cryptofile - version ' + VERSION + ', cryptor - version ' + cryptor.getVersion());
  process.exit();
}

if (options.salt) {
  console.log('Custom salt:', options.salt);
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

/////

function _encode(INPUT_FILE, OUTPUT_FILE, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: OUTPUT_FILE });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(OUTPUT_FILE));
  options.output_dir = TMP_DIR;

  fse.ensureDirSync(TMP_DIR);

  var pack_opts = {};
  if (options.progress) {
    pack_opts.onEntry = function(entry) {
      console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
    }
  }

  var onFileEncrypted = function(err) {
    if (!err) {
      if (utils.fileExists(OUTPUT_FILE)) {
        if (options.progress) console.log('Updating existing cryptofile...');
        pack_file.pack(TMP_DIR, pack_opts, function(err, res) {
          if (err) {
            console.log('Updating existing cryptofile... Error!');
            console.log(err);
          } else {
            if (!options.debug) fse.removeSync(TMP_DIR);
            var stats = utils.getFileStats(OUTPUT_FILE);
            if (options.progress) console.log('Updating existing cryptofile... OK');
            console.log('Cryptofile updated:', OUTPUT_FILE, chalk.magenta(stats ? bytes(stats['size']) : ''));
          }
        });
      } else {
        if (options.progress) console.log('Creating new cryptofile...');
        pack_file.pack(TMP_DIR, pack_opts, function(err, res) {
          if (err) {
            console.log('Creating new cryptofile... Error!');
            console.log(err);
          } else {
            if (!options.debug) fse.removeSync(TMP_DIR);
            var stats = utils.getFileStats(OUTPUT_FILE);
            if (options.progress) console.log('Creating new cryptofile... OK');
            console.log('Cryptofile created:', OUTPUT_FILE, chalk.magenta(stats ? bytes(stats['size']) : ''));
          }
        });
      }
    } else {
      if (!options.debug) fse.removeSync(TMP_DIR);
      console.log('Cryptofile not changed.');
    }
  }

  var startFileEncrypt = function() {
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

      var file_stat = utils.getStat(INPUT_FILE);
      if (!file_stat) {
        console.log('Cannot get file info!');
        crypto_index.unload(function(err) {
          if (err) {
            console.log('Unload crypto index error!');
            console.log(err);
          }
          process.exit();
        })
        return;
      }

      console.log(file_stat);

      var file_name = path.basename(INPUT_FILE);

      var encrypted_file_name = 'DATA'; // utils.md5Hash(file_name);
      var encrypted_file_path = path.join(TMP_DIR, encrypted_file_name);

      fse.ensureDirSync(path.dirname(encrypted_file_path));

      if (options.progress) console.log('Encrypting file...');
      cryptor.encryptFile(INPUT_FILE, encrypted_file_path, ENC_KEY, options, function(err) {
        if (err) {
          console.log('Encrypt file error!');
          console.log(err);
        } else {
          if (options.progress) console.log('Encrypting file... OK');
          // add to crypto index
          crypto_index.put('DATA', {    
            p: file_name,                  // path
            ep: encrypted_file_name,       // encrypted file path
            et: new Date(),                // encrypted time
            s: file_stat['size'],          // size
            m: file_stat['mode'],          // mode
            at: file_stat['atime'],        // atime
            mt: file_stat['mtime'],        // mtime
            ct: file_stat['ctime'],        // ctime
          });
          var encrypted_file_stat = utils.getStat(encrypted_file_path);
          if (encrypted_file_stat) {
            console.log('Encrypted size:', bytes(encrypted_file_stat['size']));
          }
        }
        crypto_index.unload(function(err) {
          if (err) {
            console.log('Unload crypto index error!');
            console.log(err);
          }
          onFileEncrypted(err);
        })
      });
    });
  }

  // fse.ensureDirSync(INPUT_FILE);
  fse.emptyDirSync(TMP_DIR);

  if (utils.fileExists(OUTPUT_FILE)) {
    if (options.progress) console.log('Reading existing cryptofile...');
    pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
      if (err) {
        console.log('Reading existing cryptofile... Error!');
        console.log(err);
      } else {
        if (options.progress) console.log('Reading existing cryptofile... OK');
        startFileEncrypt();
      }
    });
  } else {
    startFileEncrypt();
  }
}

function _decode(INPUT_FILE, OUTPUT_FILE, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_FILE });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_FILE));
  options.input_dir = TMP_DIR;

  var onDirDecrypted = function() {
    if (!options.debug) fse.removeSync(TMP_DIR);
    console.log('Cryptofile unpacked.');
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

      if (!crypto_index.get('DATA')) {
        console.log('Missing DATA!');
        crypto_index.unload(function(err) {
          if (err) {
            console.log('Unload crypto index error!');
            console.log(err);
          }
          if (!options.debug) fse.removeSync(TMP_DIR);
          process.exit();
        });
        return;
      }

      var data_info = crypto_index.get('DATA');
      var file = {
        encrypted: data_info.ep, 
        original: {
          path: data_info.p,
          size: data_info.s,
          mode: data_info.m,
          atime: data_info.at,
          mtime: data_info.mt,
          ctime: data_info.ct
        }
      };
      var orig_file = file.original;
      
      var extract_opts = {overwrite: true};

      if (options.progress) {
        extract_opts.onEntry = function(entry) {
          console.log((entry.type || 'File')[0], entry.path, chalk.magenta(bytes(entry.size)));
        }
      }

      pack_file.extractEntries([file.encrypted], extract_opts, function(err, result) {
        if (err) {
          console.log('Extract files failed!');
          console.log(err);
        } else {
          // decrypt extracted file(s)
          var encrypted_file_path = path.join(TMP_DIR, file.encrypted);

          if (options.progress) console.log('Decrypting file...');
          cryptor.decryptFile(encrypted_file_path, OUTPUT_FILE, ENC_KEY, options, function(err) {
            if (err) {
              console.log('Decrypt file error!');
              console.log(err);
            } else {
              if (options.progress) console.log('Decrypting file... OK');
              var decrypted_file_stat = utils.getStat(OUTPUT_FILE);
              if (decrypted_file_stat) {
                console.log('Decrypted file:', OUTPUT_FILE);
                console.log('Decrypted size:', bytes(decrypted_file_stat['size']));
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

  if (options.progress) console.log('Reading cryptofile...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptofile... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptofile... OK');
      startDirDecrypt();
    }
  });
}

function _info(INPUT_FILE, ENC_KEY, options, done) {

  var pack_file = new PackFile({ path: INPUT_FILE });

  // temp dir
  var TMP_DIR = path.join(config_dir, 'caches', utils.md5Hash(INPUT_FILE));
  options.input_dir = TMP_DIR;

  var startFileInfo = function() {
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
      
      var data_info = crypto_index.get('DATA');
      if (data_info) {
        console.log(chalk.bold('File name:'), data_info.p);
        console.log(chalk.bold('File size:'), bytes(data_info.s));
        var encrypted_file_stat = utils.getStat(INPUT_FILE);
        if (encrypted_file_stat) {
          console.log(chalk.bold('Encrypted size:'), bytes(encrypted_file_stat['size']));
        }
      } else {
        console.log('Missing DATA!');
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

  if (options.progress) console.log('Reading cryptofile...');
  pack_file.extractEntries(['INDEX','VERSION','VERIFY'], TMP_DIR, options, function(err, res) {
    if (err) {
      console.log('Reading cryptofile... Error!');
      console.log(err);
    } else {
      if (options.progress) console.log('Reading cryptofile... OK');
      startFileInfo();
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
  }else if (options.set_salt) {
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
} else if (options.encode) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log('File not found:', INPUT_FILE);
    process.exit();
  }
  console.log('Input file: ' + INPUT_FILE);

  var default_output_file = path.join(path.dirname(INPUT_FILE), path.basename(INPUT_FILE) + '.cryptofile');
  var OUTPUT_FILE = (argv[1]) ? path.resolve(argv[1]) : default_output_file;

  if (!options.force && utils.fileExists(OUTPUT_FILE)) {
    console.log(chalk.red('Cryptofile exists:'), OUTPUT_FILE);
    console.log(chalk.grey('Hint: Add --force or -f to overwrite existing cryptofile.'));
    process.exit();
  }
  console.log('Encode to: ' + OUTPUT_FILE);

  if ((options.default && config.enc_key) || options.enc_key) {
    _encode(INPUT_FILE, OUTPUT_FILE, options.enc_key || config.enc_key, options, function(err) {
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
      _encode(INPUT_FILE, OUTPUT_FILE, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.decode) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log(chalk.red('Cryptofile not found:'), INPUT_FILE);
    process.exit();
  }
  console.log('Cryptofile: ' + INPUT_FILE);

  var default_output_dir = path.join(path.dirname(INPUT_FILE), path.basename(INPUT_FILE, path.extname(INPUT_FILE)));
  var OUTPUT_FILE = argv[1] ? path.resolve(argv[1]) : default_output_dir;

  if (!options.force && utils.fileExists(OUTPUT_FILE)) {
    console.log(chalk.red('File exists:'), OUTPUT_FILE);
    console.log(chalk.grey('Hint: Add --force or -f to replace existing file.'));
    process.exit();
  }
  console.log('Decode to: ' + OUTPUT_FILE);

  if ((options.default && config.enc_key) || options.enc_key) {
    _decode(INPUT_FILE, OUTPUT_FILE, options.enc_key || config.enc_key, options, function(err) {
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
      _decode(INPUT_FILE, OUTPUT_FILE, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else if (options.info) {

  if (argv.length < 1) {
    printUsage();
    process.exit();
  }

  var INPUT_FILE = path.resolve(argv[0]);
  if (!utils.fileExists(INPUT_FILE)) {
    console.log(chalk.red('Cryptofile not found:'), INPUT_FILE);
    process.exit();
  }
  console.log('Cryptofile: ' + INPUT_FILE);

  if ((options.default && config.enc_key) || options.enc_key) {
    _info(INPUT_FILE, options.enc_key || config.enc_key, options, function(err) {
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
      _info(INPUT_FILE, ENC_KEY, options, function(err) {
        if (err) {
          console.log(err);
        }
        process.exit();
      })
    });
  }
} else {
  printUsage();
  process.exit();
}
