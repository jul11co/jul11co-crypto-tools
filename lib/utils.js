// lib/utils.js

var path = require('path');
var fs = require('fs');
var urlutil = require('url');
var crypto = require('crypto');

var mkdirp = require('mkdirp');
var jsonfile = require('jsonfile');

function getUserHome() {
  return process.env[(process.platform == 'win32') ? 'USERPROFILE' : 'HOME'];
}

function getFileStats(file_path) {
  var stats = undefined;
  try {
    stats = fs.lstatSync(file_path);
  } catch(e) {
    console.log(e);
  }
  return stats;
}

function fileExists(file_path) {
  try {
    var stats = fs.statSync(file_path);
    if (stats.isFile()) {
      return true;
    }
  } catch (e) {
  }
  return false;
}

function directoryExists(directory) {
  try {
    var stats = fs.statSync(directory);
    if (stats.isDirectory()) {
      return true;
    }
  } catch (e) {
  }
  return false;
}

function ensureDirectoryExists(directory) {
  try {
    var stats = fs.statSync(directory);
    // if (stats.isDirectory()) {
    //   console.log('Directory exists: ' + directory);
    // }
  } catch (e) {
    // console.log(e);
    if (e.code == 'ENOENT') {
      // fs.mkdirSync(directory);
      mkdirp.sync(directory);
      console.log('Directory created: ' + directory);
    }
  }
}

function isHttpUrl(string) {
  var pattern = /^((http|https):\/\/)/;
  return pattern.test(string);
}

function isValidLink(link_href) {
  if (!link_href || link_href === '') return false;
  if (link_href.indexOf('#') == 0 
    || link_href.indexOf('mailto:') >= 0 
    || link_href.indexOf('javascript:') == 0) {
    return false;
  }
  return true;
}

function urlGetHost(_url) {
  if (!_url || _url == '') return '';
  var host_url = '';
  var url_obj = urlutil.parse(_url);
  if (url_obj.slashes) {
    host_url = url_obj.protocol + '//' + url_obj.host;
  } else {
    host_url = url_obj.protocol + url_obj.host;
  }
  return host_url;
}

function ellipsisMiddle(str, max_length, first_part_length, last_part_length) {
  if (!max_length) max_length = 140;
  if (!first_part_length) first_part_length = 40;
  if (!last_part_length) last_part_length = 20;
  if (str.length > max_length) {
    return str.substr(0, first_part_length) + '...' + str.substr(str.length-last_part_length, str.length);
  }
  return str;
}

// http://stackoverflow.com/questions/2998784/
function numberPad(num, size) {
  var s = "000000000" + num;
  return s.substr(s.length-size);
}

function escapeRegExp(string) {
  return string.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
}

function replaceAll(string, find, replace) {
  return string.replace(new RegExp(escapeRegExp(find), 'g'), replace);
}

function extractSubstring(original, prefix, suffix) {
  if (!original) return '';
  var tmp = original.substring(original.indexOf(prefix) + prefix.length);
  tmp = tmp.substring(0, tmp.indexOf(suffix));
  return tmp;
}

function trimText(input, max_length) {
  if (!input || input == '') return '';
  max_length = max_length || 60;
  var output = input.trim();
  if (output.length > max_length) {
    output = output.substring(0, max_length) + '...';
  }
  return output;
}

var loadFromJsonFile = function(file) {
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

var saveToJsonFile = function(info, file) {
  var err = null;
  try {
    jsonfile.writeFileSync(file, info, { spaces: 2 });
  } catch (e) {
    err = e;
  }
  return err;
}

var parseSize = function(string) {
  var file_size = -1;
  if (string) {
    if (string.indexOf('KB')) {
      var size = string.replace('KB','');
      size = parseInt(size);
      if (isNaN(size)) {
        console.log('Invalid size:', string);
        return size;
      }
      file_size = size*1024;
    } else if (string.indexOf('MB')) {
      var size = string.replace('MB','');
      size = parseInt(min_size);
      if (isNaN(size)) {
        console.log('Invalid size:', string);
        return size;
      }
      file_size = size*1024*1024;
    } else if (string.indexOf('GB')) {
      var size = string.replace('GB','');
      size = parseInt(size);
      if (isNaN(size)) {
        console.log('Invalid size:', string);
        return size;
      }
      file_size = size*1024*1024*1024;
    }
  }
  return file_size;
}

function lastChar(str) {
  return str.substring(str.length-1);
}

function containText(str, str_array) {
  if (!str || str == '' || !str_array || str_array.length ==0) return false;
  var contained = false;
  for (var i = 0; i < str_array.length; i++) {
    if (str.indexOf(str_array[i]) != -1) {
      contained = true;
      break;
    }
  }
  return contained;
}

function md5Hash(string) {
  return crypto.createHash('md5').update(string).digest('hex');
}

function sha512Hash(string, salt) {
  var hash = crypto.createHmac('sha512', salt);
  hash.update(string);
  return hash.digest('hex');
}

function padRight(string, length, padchar) {
  var str = string || '';
  padchar = padchar || ' ';
  if (str == '') {
    for (var i = 0; i<length; i++) str += padchar;
  } else if (str.length < length) {
    for (var i = str.length; i<length; i++) str += padchar;
  }
  return str;
}

function padLeft(string, length, padchar) {
  var str = string || '';
  padchar = padchar || ' ';
  if (str == '') {
    for (var i = 0; i<length; i++) str += padchar;
  } else if (str.length < length) {
    for (var i = str.length; i<length; i++) str = padchar + str;
  }
  return str;
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

module.exports = {
  getUserHome: getUserHome,
  
  getFileStats: getFileStats,

  md5Hash: md5Hash,
  sha512Hash: sha512Hash,

  getStat: getStat,

  fileExists: fileExists,
  directoryExists: directoryExists,
  ensureDirectoryExists: ensureDirectoryExists,

  parseSize: parseSize,

  isValidLink: isValidLink,
  urlGetHost: urlGetHost,
  ellipsisMiddle: ellipsisMiddle,
  numberPad: numberPad,
  isHttpUrl: isHttpUrl,

  trimText: trimText,
  containText: containText,

  lastChar: lastChar,

  padRight: padRight,
  padLeft: padLeft,

  replaceAll: replaceAll,
  extractSubstring: extractSubstring,

  loadFromJsonFile: loadFromJsonFile,
  saveToJsonFile: saveToJsonFile
}
