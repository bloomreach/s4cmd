#!/usr/bin/env python

#
# Copyright 2012 BloomReach, Inc.
# Portions Copyright 2014 Databricks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Super S3 command line tool.
"""

import sys, os, re, optparse, multiprocessing, fnmatch, time, hashlib, errno
import logging, traceback, types, threading, random, socket

IS_PYTHON2 = sys.version_info[0] == 2

if IS_PYTHON2:
  from cStringIO import StringIO
  import Queue
  import ConfigParser
else:
  from io import StringIO
  import queue as Queue
  import configparser  as ConfigParser

  def cmp(a, b):
    return (a > b) - (a < b)

from functools import cmp_to_key


# We need boto 2.3.0 for multipart upload1
import boto
import boto.s3
import boto.s3.key
import boto.exception

##
## Global constants
##

S4CMD_VERSION = "1.5.20"

PATH_SEP = '/'
DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S UTC'
TIMESTAMP_REGEX = re.compile(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}).(\d{3})Z')
TIMESTAMP_FORMAT = '%4s-%2s-%2s %2s:%2s'
SOCKET_TIMEOUT = 5 * 60 # in sec(s) (timeout if we don't receive any recv() callback)
socket.setdefaulttimeout(SOCKET_TIMEOUT)

# Global list for temp files.
TEMP_FILES = set()

# Environment variable names for S3 credentials.
S3_ACCESS_KEY_NAME = "S3_ACCESS_KEY"
S3_SECRET_KEY_NAME = "S3_SECRET_KEY"


##
## Utility classes
##

class Options:
  '''Default option class for available options. Use the default value from opt parser.
     The values can be overwritten by command line options or set at run-time.
  '''
  def __init__(self, opt = None):
    parser = get_opt_parser()
    for o in parser.option_list:
      self.__dict__[o.dest] = o.default if (opt is None) or (opt.__dict__[o.dest] is None) else opt.__dict__[o.dest]

class Failure(RuntimeError):
  '''Exception for runtime failures'''
  pass

class InvalidArgument(RuntimeError):
  '''Exception for invalid input parameters'''
  pass

class RetryFailure(Exception):
  '''Runtime failure that can be retried'''
  pass


class S4cmdLoggingClass:
  def __init__(self):
    self.log = logging.Logger("s4cmd")
    self.log.stream = sys.stderr
    self.log_handler = logging.StreamHandler(self.log.stream)
    self.log.addHandler(self.log_handler)


  def configure(self, opt):
    'Configure the logger based on command-line arguments'''

    self.log_handler.setFormatter(logging.Formatter('%(message)s', DATETIME_FORMAT))
    if opt.debug:
      self.log.verbosity = 3
      self.log_handler.setFormatter(logging.Formatter(
          '  (%(levelname).1s)%(filename)s:%(lineno)-4d %(message)s',
          DATETIME_FORMAT))
      self.log.setLevel(logging.DEBUG)
    elif opt.verbose:
      self.log.verbosity = 2
      self.log.setLevel(logging.INFO)
    else:
      self.log.verbosity = 1
      self.log.setLevel(logging.ERROR)


  def get_loggers(self):
    '''Return a list of the logger methods: (debug, info, warn, error)'''

    return self.log.debug, self.log.info, self.log.warn, self.log.error

s4cmd_logging = S4cmdLoggingClass()
debug, info, warn, error = s4cmd_logging.get_loggers()


def get_default_thread_count():
  return int(os.getenv('S4CMD_NUM_THREADS', multiprocessing.cpu_count() * 4))


def log_calls(func):
  '''Decorator to log function calls.'''
  def wrapper(*args, **kwargs):
    callStr = "%s(%s)" % (func.__name__, ", ".join([repr(p) for p in args] + ["%s=%s" % (k, repr(v)) for (k, v) in list(kwargs.items())]))
    debug(">> %s", callStr)
    ret = func(*args, **kwargs)
    debug("<< %s: %s", callStr, repr(ret))
    return ret
  return wrapper

##
## Utility functions
##

def synchronized(func):
  '''Decorator to synchronize function.'''
  func.__lock__ = threading.Lock()
  def synced_func(*args, **kargs):
    with func.__lock__:
      return func(*args, **kargs)
  return synced_func

def clear_progress():
  '''Clear previous progress message, if any.'''
  progress('')

@synchronized
def progress(msg, *args):
  '''Show current progress message to stderr.
     This function will remember the previous message so that next time,
     it will clear the previous message before showing next one.
  '''
  # Don't show any progress if the output is directed to a file.
  if not sys.stderr.isatty():
    return

  text = (msg % args)
  if progress.prev_message:
    sys.stderr.write(' ' * len(progress.prev_message) + '\r')
  sys.stderr.write(text + '\r')
  progress.prev_message = text

progress.prev_message = None

@synchronized
def message(msg, *args):
  '''Program message output.'''
  clear_progress()
  text = (msg % args)
  sys.stdout.write(text + '\n')

def fail(message, exc_info = None, status = 1, stacktrace = False):
  '''Utility function to handle runtime failures gracefully.
     Show concise information if possible, then terminate program.
  '''
  text = message
  if exc_info:
    text += str(exc_info)
  error(text)
  if stacktrace:
    error(traceback.format_exc())
  clean_tempfiles()
  if __name__ == '__main__':
    sys.exit(status)
  else:
    raise RuntimeError(status)

@synchronized
def tempfile_get(target):
  '''Get a temp filename for atomic download.'''
  fn = '%s-%s.tmp' % (target, ''.join(random.Random().sample("0123456789abcdefghijklmnopqrstuvwxyz", 15)))
  TEMP_FILES.add(fn)
  return fn

@synchronized
def tempfile_set(tempfile, target):
  '''Atomically rename and clean tempfile'''
  if target:
    os.rename(tempfile, target)
  else:
    os.unlink(tempfile)

  if target in TEMP_FILES:
    TEMP_FILES.remove(tempfile)

def clean_tempfiles():
  '''Clean up temp files'''
  for fn in TEMP_FILES:
    if os.path.exists(fn):
      os.unlink(fn)

class S3URL:
  '''Simple wrapper for S3 URL.
     This class parses a S3 URL and provides accessors to each component.
  '''
  S3URL_PATTERN = re.compile(r'(s3[n]?)://([^/]+)[/]?(.*)')

  def __init__(self, uri):
    '''Initialization, parse S3 URL'''
    try:
      self.proto, self.bucket, self.path = S3URL.S3URL_PATTERN.match(uri).groups()
      self.proto = 's3' # normalize s3n => s3
    except:
      raise InvalidArgument('Invalid S3 URI: %s' % uri)

  def __str__(self):
    '''Return the original S3 URL'''
    return S3URL.combine(self.proto, self.bucket, self.path)

  def get_fixed_path(self):
    '''Get the fixed part of the path without wildcard'''
    pi = self.path.split(PATH_SEP)
    fi = []
    for p in pi:
      if '*' in p or '?' in p:
        break
      fi.append(p)
    return PATH_SEP.join(fi)

  @staticmethod
  def combine(proto, bucket, path):
    '''Combine each component and general a S3 url string, no path normalization
       here. The path should not start with slash.
    '''
    return '%s://%s/%s' % (proto, bucket, path)

  @staticmethod
  def is_valid(uri):
    '''Check if given uri is a valid S3 URL'''
    return S3URL.S3URL_PATTERN.match(uri) != None

class TaskQueue(Queue.Queue):
  '''Wrapper class to Queue.
     Since we need to ensure that main thread is not blocked by child threads
     and cannot be wake up by Ctrl-C interrupt, we have to override join()
     method.
  '''
  def __init__(self):
    Queue.Queue.__init__(self)
    self.exc_info = None

  def join(self):
    '''Override original join() with a timeout and handle keyboard interrupt.'''
    self.all_tasks_done.acquire()
    try:
      while self.unfinished_tasks:
        self.all_tasks_done.wait(1000)

        # Child thread has exceptions, fail main thread too.
        if self.exc_info:
          fail('[Thread Failure] ', exc_info = self.exc_info)
    except KeyboardInterrupt:
      raise Failure('Interrupted by user')
    finally:
      self.all_tasks_done.release()

  def terminate(self, exc_info = None):
    '''Terminate all threads by deleting the queue and forcing the child threads
       to quit.
    '''
    if exc_info:
      self.exc_info = exc_info
    try:
      while self.get_nowait():
        self.task_done()
    except Queue.Empty:
      pass

class ThreadPool(object):
  '''Utility class for thread pool.
     This class needs to work with a utility class, which is derived from Worker.
  '''

  class Worker(threading.Thread):
    '''Utility thread worker class.
       This class handles all items in task queue and execute them. It also
       handles runtime errors gracefully, and provides automatic retry.
    '''
    def __init__(self, pool):
      '''Thread worker initalization.
         Setup values and start threads right away.
      '''
      threading.Thread.__init__(self)
      self.pool = pool
      self.opt = pool.opt
      self.daemon = True
      self.start()

    def run(self):
      '''Main thread worker execution.
         This function extract items from task queue and execute them accordingly.
         It will retry tasks when encounter exceptions by putting the same item
         back to the work queue.
      '''
      while True:
        item = self.pool.tasks.get()
        if not item:
          break

        try:
          func_name, retry, args, kargs = item
          self.__class__.__dict__[func_name](self, *args, **kargs)
        except InvalidArgument as e:
          self.pool.tasks.terminate(e)
          fail('[Invalid Argument] ', exc_info = e)
        except Failure as e:
          self.pool.tasks.terminate(e)
          fail('[Runtime Failure] ', exc_info = e)
        # Also retry known S3ResponseError since S3 has transient
        # errors from time to time.
        # except boto.exception.S3ResponseError, e:
        #   self.pool.tasks.terminate(e)
        #   fail('[S3ResponseError] %s: %s' % (e.error_code, e.error_message))
        except OSError as e:
          self.pool.tasks.terminate(e)
          fail('[OSError] %d: %s' % (e.errno, e.strerror))
        except Exception as e:
          # XXX Should we retry on all unknown exceptions?
          if retry >= self.opt.retry:
            self.pool.tasks.terminate(e)
            fail('[Runtime Exception] ', exc_info = e, stacktrace = True)
          else:
            # Show content of exceptions.
            error(e)

          time.sleep(self.opt.retry_delay)
          self.pool.tasks.put((func_name, retry + 1, args, kargs))
        finally:
          self.pool.processed()
          self.pool.tasks.task_done()

  def __init__(self, thread_class, opt):
    '''Constructor of ThreadPool.
       Create workers and pool will automatically inherit all methods from
       thread_class by redirecting calls through __getattribute__().
    '''
    self.opt = opt
    self.tasks = TaskQueue()
    self.processed_tasks = 0
    self.thread_class = thread_class
    self.workers = []
    for i in range(opt.num_threads):
      self.workers.append(thread_class(self))

  def __enter__(self):
    '''Utility function for with statement'''
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    '''Utility function for with statement, wait for completion'''
    self.join()
    return isinstance(exc_value, TypeError)

  def __getattribute__(self, name):
    '''Special attribute accessor to add tasks into task queue.
       Here if we found a function not in ThreadPool, we will try
       to see if we have a function in the utility class. If so, we
       add the function call into task queue.
    '''
    try:
      attr = super(ThreadPool, self).__getattribute__(name)
    except AttributeError as e:
      if name in self.thread_class.__dict__:
        # Here we masquerade the original function with add_task(). So the
        # function call will be put into task queue.
        def deferred_task(*args, **kargs):
          self.add_task(name, *args, **kargs)
        attr = deferred_task
      else:
        raise AttributeError('Unable to resolve %s' % name)
    return attr

  def add_task(self, func_name, *args, **kargs):
    '''Utility function to add a single task into task queue'''
    self.tasks.put((func_name, 0, args, kargs))

  def join(self):
    '''Utility function to wait all tasks to complete'''
    self.tasks.join()

    # Force each thread to break loop.
    for worker in self.workers:
      self.tasks.put(None)

    # Wait for all thread to terminate.
    for worker in self.workers:
      worker.join()
      worker.s3 = None

  @synchronized
  def processed(self):
    '''Increase the processed task counter and show progress message'''
    self.processed_tasks += 1
    qsize = self.tasks.qsize()
    if qsize > 0:
      progress('[%d task(s) completed, %d remaining, %d thread(s)]', self.processed_tasks, qsize, len(self.workers))
    else:
      progress('[%d task(s) completed, %d thread(s)]', self.processed_tasks, len(self.workers))

class S3Handler(object):
  '''Core S3 class.
     This class provide the functions for all operations. It will start thread
     pool to execute tasks generated by each operation. See ThreadUtil for
     more details about the tasks.
  '''

  S3_KEYS = None

  @staticmethod
  def s3_keys_from_env():
    '''Retrieve S3 access keys from the environment, or None if not present.'''
    env = os.environ
    if S3_ACCESS_KEY_NAME in env and S3_SECRET_KEY_NAME in env:
      keys = (env[S3_ACCESS_KEY_NAME], env[S3_SECRET_KEY_NAME])
      debug("read S3 keys from environment")
      return keys
    else:
      return None

  @staticmethod
  def s3_keys_from_s3cfg(opt):
    '''Retrieve S3 access key settings from s3cmd's config file, if present; otherwise return None.'''
    try:
      if opt.s3cfg != None:
        s3cfg_path = "%s" % opt.s3cfg
      else:
        s3cfg_path = "%s/.s3cfg" % os.environ["HOME"]
      if not os.path.exists(s3cfg_path):
        return None
      config = ConfigParser.ConfigParser()
      config.read(s3cfg_path)
      keys = config.get("default", "access_key"), config.get("default", "secret_key")
      debug("read S3 keys from $HOME/.s3cfg file")
      return keys
    except Exception as e:
      info("could not read S3 keys from %s file; skipping (%s)", s3cfg_path, e)
      return None

  @staticmethod
  def init_s3_keys(opt):
    '''Initialize s3 access keys from environment variable or s3cfg config file.'''
    S3Handler.S3_KEYS = S3Handler.s3_keys_from_env() or S3Handler.s3_keys_from_s3cfg(opt)

  def __init__(self, opt):
    '''Constructor, connect to S3 store'''
    self.s3 = None
    self.opt = opt
    self.connect()

  def __del__(self):
    '''Destructor, stop s3 connection'''
    if self.s3 is not None:
      self.s3.close()
      self.s3 = None

  def connect(self):
    '''Connect to S3 storage'''
    try:
      if S3Handler.S3_KEYS:
        self.s3 = boto.connect_s3(S3Handler.S3_KEYS[0],
                                  S3Handler.S3_KEYS[1],
                                  is_secure = self.opt.use_ssl,
                                  suppress_consec_slashes = False)
      else:
        self.s3 = boto.connect_s3(is_secure = self.opt.use_ssl,
                                  suppress_consec_slashes = False)
    except Exception as e:
      raise RetryFailure('Unable to connect to s3: %s' % e)

  @log_calls
  def list_buckets(self):
    '''List all buckets'''
    result = []
    for bucket in self.s3.get_all_buckets():
      result.append({
          'name': S3URL.combine('s3', bucket.name, ''),
          'is_dir': True,
          'size': 0,
          'last_modified': bucket.creation_date
        })
    return result

  @log_calls
  def s3walk(self, basedir, show_dir = None):
    '''Walk through a S3 directory. This function initiate a walk with a basedir.
       It also supports multiple wildcards.
    '''
    # Provide the default value from command line if no override.
    if not show_dir:
      show_dir = self.opt.show_dir

    # trailing slash normalization, this is for the reason that we want
    # ls 's3://foo/bar/' has the same result as 's3://foo/bar'. Since we
    # call partial_match() to check wildcards, we need to ensure the number
    # of slashes stays the same when we do this.
    if basedir[-1] == PATH_SEP:
      basedir = basedir[0:-1]

    s3url = S3URL(basedir)
    result = []

    pool = ThreadPool(ThreadUtil, self.opt)
    pool.s3walk(s3url, s3url.get_fixed_path(), s3url.path, result)
    pool.join()

    # automatic directory detection
    if not show_dir and len(result) == 1 and result[0]['is_dir']:
      path = result[0]['name']
      s3url = S3URL(path)
      result = []
      pool = ThreadPool(ThreadUtil, self.opt)
      pool.s3walk(s3url, s3url.get_fixed_path(), s3url.path, result)
      pool.join()

    def compare(x, y):
      '''Comparator for ls output'''
      result = -cmp(x['is_dir'], y['is_dir'])
      if result != 0:
        return result
      return cmp(x['name'], y['name'])
    compare = cmp_to_key(compare)
    return sorted(result, key=compare)

  @log_calls
  def local_walk(self, basedir):
    '''Walk through local directories from root basedir'''
    result = []

    for root, dirs, files in os.walk(basedir):
      for f in files:
        result.append(os.path.join(root, f))
    return result

  @log_calls
  def get_basename(self, path):
    '''Unix style basename.
       This fuction will return 'bar' for '/foo/bar/' instead of empty string.
       It is used to normalize the input trailing slash.
    '''
    if path[-1] == PATH_SEP:
      path = path[0:-1]
    return os.path.basename(path)

  def source_expand(self, source):
    '''Expand the wildcards for an S3 path. This emulates the shall expansion
       for wildcards if the input is local path.
    '''
    result = []

    if not isinstance(source, list):
      source = [source]

    for src in source:
      # XXX Hacky: We need to disable recursive when we expand the input
      #            parameters, need to pass this as an override parameter if
      #            provided.
      tmp = self.opt.recursive
      self.opt.recursive = False
      result += [f['name'] for f in self.s3walk(src, True)]
      self.opt.recursive = tmp

    if (len(result) == 0) and (not self.opt.ignore_empty_source):
      fail("[Runtime Failure] Source doesn't exist.")

    return result

  @log_calls
  def put_single_file(self, pool, source, target):
    '''Upload a single file or a directory by adding a task into queue'''
    if os.path.isdir(source):
      if self.opt.recursive:
        for f in [f for f in self.local_walk(source) if not os.path.isdir(f)]:
          target_url = S3URL(target)
          # deal with ./ or ../ here by normalizing the path.
          joined_path = os.path.normpath(os.path.join(target_url.path, os.path.relpath(f, source)))
          pool.upload(None, f, S3URL.combine('s3', target_url.bucket, joined_path))
      else:
        message('omitting directory "%s".' % source)
    else:
      pool.upload(None, source, target)

  @log_calls
  def put_files(self, source, target):
    '''Upload files to S3.
       This function can handle multiple file upload if source is a list.
       Also, it works for recursive mode which copy all files and keep the
       directory structure under the given source directory.
    '''
    pool = ThreadPool(ThreadUtil, self.opt)
    if not isinstance(source, list):
      source = [source]

    if target[-1] == PATH_SEP:
      for src in source:
        self.put_single_file(pool, src, os.path.join(target, self.get_basename(src)))
    else:
      if len(source) == 1:
        self.put_single_file(pool, source[0], target)
      else:
        raise Failure('Target "%s" is not a directory (with a trailing slash).' % target)

    pool.join()

  @log_calls
  def update_privilege(self, source, target):
    '''Get privileges from metadata of the source in s3, and apply them to target'''
    s3url = S3URL(source)
    bucket = self.s3.lookup(s3url.bucket, validate=self.opt.validate)
    remoteKey = bucket.get_key(s3url.path)
    if 'privilege' in remoteKey.metadata:
      os.chmod(target, int(remoteKey.metadata['privilege'], 8))

  @log_calls
  def get_single_file(self, pool, source, target):
    '''Download a single file or a directory by adding a task into queue'''
    if source[-1] == PATH_SEP:
      if self.opt.recursive:
        basepath = S3URL(source).path
        for f in [f for f in self.s3walk(source) if not f['is_dir']]:
          pool.download(None, f['name'], os.path.join(target, os.path.relpath(S3URL(f['name']).path, basepath)))
      else:
        message('omitting directory "%s".' % source)
    else:
      pool.download(None, source, target)

  @log_calls
  def get_files(self, source, target):
    '''Download files.
       This function can handle multiple files if source S3 URL has wildcard
       characters. It also handles recursive mode by download all files and
       keep the directory structure.
    '''
    pool = ThreadPool(ThreadUtil, self.opt)
    source = self.source_expand(source)

    if os.path.isdir(target):
      for src in source:
        self.get_single_file(pool, src, os.path.join(target, self.get_basename(S3URL(src).path)))
    else:
      if len(source) > 1:
        raise Failure('Target "%s" is not a directory.' % target)
        # Get file if it exists on s3 otherwise do nothing
      elif len(source) == 1:
        self.get_single_file(pool, source[0], target)
      else:
        #Source expand may return empty list only if ignore-empty-source is set to true
        pass

    pool.join()

  @log_calls
  def delete_removed_files(self, source, target):
    '''Remove remote files that are not present in the local source.
    '''
    message("Deleting files found in %s and not in %s", source, target)
    if os.path.isdir(source):
      unecessary = []
      basepath = S3URL(target).path
      for f in [f for f in self.s3walk(target) if not f['is_dir']]:
        local_name = os.path.join(source, os.path.relpath(S3URL(f['name']).path, basepath))
        if not os.path.isfile(local_name):
          message("%s not found locally, adding to delete queue", local_name)
          unecessary.append(f['name'])
      if len(unecessary) > 0:
        pool = ThreadPool(ThreadUtil, self.opt)
        for del_file in unecessary:
          pool.delete(del_file)
        pool.join()
    else:
      raise Failure('Source "%s" is not a directory.' % target)


  @log_calls
  def cp_single_file(self, pool, source, target, delete_source):
    '''Copy a single file or a directory by adding a task into queue'''
    if source[-1] == PATH_SEP:
      if self.opt.recursive:
        basepath = S3URL(source).path
        for f in [f for f in self.s3walk(source) if not f['is_dir']]:
          pool.copy(f['name'], os.path.join(target, os.path.relpath(S3URL(f['name']).path, basepath)), delete_source)
      else:
        message('omitting directory "%s".' % source)
    else:
      pool.copy(source, target, delete_source)

  @log_calls
  def cp_files(self, source, target, delete_source = False):
    '''Copy files
       This function can handle multiple files if source S3 URL has wildcard
       characters. It also handles recursive mode by copying all files and
       keep the directory structure.
    '''
    pool = ThreadPool(ThreadUtil, self.opt)
    source = self.source_expand(source)

    if target[-1] == PATH_SEP:
      for src in source:
        self.cp_single_file(pool, src, os.path.join(target, self.get_basename(S3URL(src).path)), delete_source)
    else:
      if len(source) > 1:
        raise Failure('Target "%s" is not a directory (with a trailing slash).' % target)
        # Copy file if it exists otherwise do nothing
      elif len(source) == 1:
        self.cp_single_file(pool, source[0], target, delete_source)
      else:
        # Source expand may return empty list only if ignore-empty-source is set to true
        pass

    pool.join()

  @log_calls
  def del_files(self, source):
    '''Delete files on S3'''
    src_files = []
    for key in self.s3walk(source):
      if not key['is_dir']: # ignore directories
        src_files.append(key['name'])
    pool = ThreadPool(ThreadUtil, self.opt)

    for src_file in src_files:
      pool.delete(src_file)

    pool.join()

  @log_calls
  def sync_files(self, source, target):
    '''Sync files to S3. Does implement deletions if syncing TO s3.
       Currently identical to get/put -r -f --sync-check with exception of deletions.
    '''
    src_s3_url = S3URL.is_valid(source)
    dst_s3_url = S3URL.is_valid(target)

    if src_s3_url and not dst_s3_url:
      self.get_files(source, target)
    elif not src_s3_url and dst_s3_url:
      self.put_files(source, target)
      if self.opt.delete_removed:
        self.delete_removed_files(source, target)
    elif src_s3_url and dst_s3_url:
      self.cp_files(source, target)
    else:
      raise InvalidArgument('No S3 URI provided')

  @log_calls
  def size(self, source):
    '''Get the size component of the given s3url. If it is a
       directory, combine the sizes of all the files under
       that directory. Subdirectories will not be counted unless
       --recursive option is set.
    '''
    result = []
    for src in self.source_expand(source):
      size = 0
      for f in self.s3walk(src):
        size += f['size']
      result.append((src, size))

    return result

class ThreadUtil(S3Handler, ThreadPool.Worker):
  '''Thread workers for S3 operations.
     This class contains all thread workers for S3 operations.

     1) Expand source into [source] list if it contains wildcard characters '*' or '?'.
        This is done by shell, but we need to do this ourselves for S3 path.
        Basically we see [source] as the first-class source list.

     2) Run the following algorithm:
        if target is directory? (S3 path uses trailing slash to determine this)
          for src in source:
            copy src to target/src.basename
        else
          if source has only one element?
            copy src to target
          else
            error "target should be a directory"!

     3) Copy operations should work for both single file and directory:
        def copy(src, target)
          if src is a directory?
            copy the whole directory recursively to target
          else
            copy the file src to target
  '''

  def __init__(self, pool):
    '''Constructor'''
    S3Handler.__init__(self, pool.opt)
    ThreadPool.Worker.__init__(self, pool)

  def reset(self):
    '''Reset connection for retry.'''
    if self.s3:
      self.s3.close()
    self.connect()

  def auto_reset(func):
    '''Simple decorator for connection reset.
       This is necessary to have a clean connection if s3 connection failed.
    '''
    def wrapper(self, *args, **kwargs):
      self.reset()
      return func(self, *args, **kwargs)
    return wrapper

  @log_calls
  def mkdirs(self, target):
    '''Ensure all directories are created for a given target file.'''
    path = os.path.dirname(target)
    if path and path != '/' and not os.path.isdir(path):
      # Multi-threading means there will be intervleaved execution
      # between the check and creation of the directory.
      try:
        os.makedirs(path)
      except OSError as ose:
        if ose.errno != errno.EEXIST:
          raise Failure('Unable to create directory (%s)' % (path,))

  @log_calls
  def file_hash(self, filename, block_size = None):
    '''Calculate MD5 hash code for a local file'''
    if not block_size:
      block_size = 2**20
    m = hashlib.md5()
    with open(filename, 'rb') as f:
      while True:
        data = f.read(block_size)
        if not data:
          break
        m.update(data)
    return m.hexdigest()

  @log_calls
  def sync_check(self, localFilename, remoteKey):
    '''Check MD5 for a local file and a remote file.
       Return True if they have the same md5 hash, otherwise False.
    '''
    if not remoteKey:
      return False
    if not os.path.exists(localFilename):
      return False
    localmd5 = self.file_hash(localFilename)
    # check multiple md5 locations
    return (remoteKey.etag and remoteKey.etag == '"%s"' % localmd5) or \
           (remoteKey.md5 and remoteKey.md5 == localmd5) or \
           ('md5' in remoteKey.metadata and remoteKey.metadata['md5'] == localmd5)

  @log_calls
  def partial_match(self, path, filter_path):
    '''Partially match a path and a filter_path with wildcards.
       This function will return True if this path partially match a filter path.
       This is used for walking through directories with multiple level wildcard.
    '''
    if not path or not filter_path:
      return True

    # trailing slash normalization
    if path[-1] == PATH_SEP:
      path = path[0:-1]
    if filter_path[-1] == PATH_SEP:
      filter_path += '*'

    pi = path.split(PATH_SEP)
    fi = filter_path.split(PATH_SEP)

    # Here, if we are in recursive mode, we allow the pi to be longer than fi.
    # Otherwise, length of pi should be equal or less than the lenght of fi.
    min_len = min(len(pi), len(fi))
    matched = fnmatch.fnmatch(PATH_SEP.join(pi[0:min_len]), PATH_SEP.join(fi[0:min_len]))
    return matched and (self.opt.recursive or len(pi) <= len(fi))

  @log_calls
  @auto_reset
  def s3walk(self, s3url, s3dir, filter_path, result):
    '''Thread worker for s3walk.
       Recursively walk into all subdirectories if they still match the filter
       path partially.
    '''
    bucket = self.s3.lookup(s3url.bucket, validate=self.opt.validate)

    for key in bucket.list(s3dir, PATH_SEP):
      if not self.partial_match(key.name, filter_path):
        continue

      # determine if it is a leaf node.
      is_dir = (key.name[-1] == PATH_SEP)
      if is_dir:
        is_leaf = (key.name.count(PATH_SEP) == filter_path.count(PATH_SEP) + 1)
      else:
        is_leaf = (key.name.count(PATH_SEP) == filter_path.count(PATH_SEP))

      if self.opt.recursive:
        is_leaf = not is_dir

      if is_leaf:
        result.append({
          'name': S3URL.combine(s3url.proto, s3url.bucket, key.name),
          'is_dir': is_dir,
          'size': key.size if not is_dir else 0,
          'last_modified': key.last_modified if not is_dir else None
        })
      elif is_dir and key.name != s3dir: # bug?
        self.pool.s3walk(s3url, key.name, filter_path, result)

  class MultipartItem:
    '''Utility class for multiple part upload/download.
       This class is used to keep track of a single upload/download file, so
       that we can initialize/finalize a file when needed.
    '''
    def __init__(self, id):
      '''Constructor.
         An unique identify for a single donwload/upload file.
           - Download: the temporary file name.
           - Upload: the id of multipart upload provided by S3.
      '''
      self.id = id
      self.processed = 0
      self.total = -1

    @synchronized
    def complete(self):
      '''Increase the processed counter, and see if the file is completely
         uploaded or downloaded.
      '''
      self.processed += 1
      return self.processed == self.total

  @log_calls
  def get_file_splits(self, id, source, target, fsize, splitsize):
    '''Get file splits for upload/download.'''
    pos = 0
    part = 1 # S3 part id starts from 1
    mpi = ThreadUtil.MultipartItem(id)
    splits = []

    while pos < fsize:
      chunk = min(splitsize, fsize - pos)
      assert(chunk > 0)
      splits.append((mpi, source, target, pos, chunk, part))
      part += 1
      pos += chunk
    mpi.total = len(splits)

    return splits

  @log_calls
  def get_file_privilege(self, source):
    '''Get privileges of a local file'''
    try:
      return str(oct(os.stat(source).st_mode)[-3:])
    except Exception as e:
      raise Failure('Could not get stat for %s, error_message = %s', source, e)

  @log_calls
  @auto_reset
  def upload(self, mpi, source, target, pos = 0, chunk = 0, part = 0):
    '''Thread worker for upload operation.'''
    s3url = S3URL(target)
    bucket = self.s3.lookup(s3url.bucket, validate=self.opt.validate)

    # Initialization: Set up multithreaded uploads.
    if not mpi:
      fsize = os.path.getsize(source)
      key = bucket.get_key(s3url.path)

      # optional checks
      if self.opt.dry_run:
        message('%s => %s', source, target)
        return
      elif self.opt.sync_check and self.sync_check(source, key):
        message('%s => %s (synced)', source, target)
        return
      elif not self.opt.force and key:
        raise Failure('File already exists: %s' % target)

      # Small file optimization.
      if fsize < self.opt.max_singlepart_upload_size:
        key = boto.s3.key.Key(bucket)
        key.key = s3url.path
        key.set_metadata('privilege',  self.get_file_privilege(source))
        key.set_contents_from_filename(source)
        message('%s => %s', source, target)
        return

      # Here we need to have our own md5 value because multipart upload calculates
      # different md5 values.
      mpu = bucket.initiate_multipart_upload(s3url.path, metadata = {'md5': self.file_hash(source), 'privilege': self.get_file_privilege(source)})

      for args in self.get_file_splits(mpu.id, source, target, fsize, self.opt.multipart_split_size):
        self.pool.upload(*args)
      return

    # Handle each part in parallel, post initialization.
    for mp in bucket.list_multipart_uploads():
      if mp.id == mpi.id:
        mpu = mp
        break
    if mpu is None:
      raise Failure('Could not find MultiPartUpload %s' % mpu_id)

    data = None
    with open(source, 'rb') as f:
      f.seek(pos)
      data = f.read(chunk)
    if not data:
      raise Failure('Unable to read data from source: %s' % source)

    mpu.upload_part_from_file(StringIO(data), part)

    # Finalize
    if mpi.complete():
      try:
        mpu.complete_upload()
        message('%s => %s', source, target)
      except Exception as e:
        mpu.cancel_upload()
        raise RetryFailure('Upload failed: Unable to complete upload %s.' % source)

  @log_calls
  def _verify_file_size(self, key, downloaded_file):
    '''Verify the file size of the downloaded file.'''
    file_size = os.path.getsize(downloaded_file)
    if key.size != file_size:
      raise RetryFailure('Downloaded file size inconsistent: %s' % (repr(key)))

  @log_calls
  def _kick_off_downloads(self, s3url, bucket, source, target):
    '''Kick off download tasks, or directly download the file if the file is small.'''
    key = bucket.get_key(s3url.path)

    # optional checks
    if self.opt.dry_run:
      message('%s => %s', source, target)
      return
    elif self.opt.sync_check and self.sync_check(target, key):
      message('%s => %s (synced)', source, target)
      return
    elif not self.opt.force and os.path.exists(target):
      raise Failure('File already exists: %s' % target)

    if key is None:
      raise Failure('The key "%s" does not exists.' % (s3url.path,))

    resp = self.s3.make_request('HEAD', bucket = bucket, key = key)
    fsize = int(resp.getheader('content-length'))

    # Small file optimization.
    if fsize < self.opt.max_singlepart_download_size:
      tempfile = tempfile_get(target)
      try: # Atomically download file with
        if self.opt.recursive:
          self.mkdirs(tempfile)
        key.get_contents_to_filename(tempfile)
        self.update_privilege(source, tempfile)
        self._verify_file_size(key, tempfile)
        tempfile_set(tempfile, target)
        message('%s => %s', source, target)
      except Exception as e:
        tempfile_set(tempfile, None)
        raise RetryFailure('Download Failure: %s, Source: %s.' % (e.message, source))

      return

    # Here we use temp filename as the id of mpi.
    for args in self.get_file_splits(tempfile_get(target), source, target, fsize, self.opt.multipart_split_size):
      self.pool.download(*args)
    return

  @log_calls
  @auto_reset
  def download(self, mpi, source, target, pos = 0, chunk = 0, part = 0):
    '''Thread worker for download operation.'''
    s3url = S3URL(source)
    bucket = self.s3.lookup(s3url.bucket, validate=self.opt.validate)

    # Initialization
    if not mpi:
      self._kick_off_downloads(s3url, bucket, source, target)
      return

    tempfile = mpi.id
    if self.opt.recursive:
      self.mkdirs(tempfile)

    # Download part of the file, range is inclusive.
    resp = self.s3.make_request('GET', bucket = s3url.bucket, key = s3url.path, headers = {'Range': 'bytes=%d-%d' % (pos, pos + chunk - 1)})
    fd = os.open(tempfile, os.O_CREAT | os.O_WRONLY)
    try:
      os.lseek(fd, pos, os.SEEK_SET)

      while True:
        data = resp.read(chunk)
        if not data:
          break
        os.write(fd, data)
    finally:
      os.close(fd)

    # Finalize
    if mpi.complete():
      key = bucket.get_key(s3url.path)
      try:
        self.update_privilege(source, tempfile)
        self._verify_file_size(key, tempfile)
        tempfile_set(tempfile, target)
        message('%s => %s', source, target)
      except Exception as e:
        # Note that we don't retry in this case, because
        # We are going to remove the temp file, and if we
        # retry here with original parameters (wrapped in
        # the task item), it would fail anyway
        tempfile_set(tempfile, None)
        raise Failure('Download Failure: %s, Source: %s.' % (e.message, source))

  @log_calls
  @auto_reset
  def copy(self, source, target, delete_source = False):
    '''Copy a single file from source to target using boto S3 library.'''
    source_url = S3URL(source)
    target_url = S3URL(target)

    if not self.opt.dry_run:
      bucket = self.s3.lookup(source_url.bucket, validate=self.opt.validate)
      key = bucket.get_key(source_url.path)
      key.copy(target_url.bucket, target_url.path)
      if delete_source:
        key.delete()
    message('%s => %s' % (source, target))

  @log_calls
  @auto_reset
  def delete(self, source):
    '''Thread worker for download operation.'''
    s3url = S3URL(source)
    bucket = self.s3.lookup(s3url.bucket, validate=self.opt.validate)
    key = bucket.get_key(s3url.path)

    if not self.opt.dry_run:
      key.delete()
    message('Delete %s', source)

class CommandHandler(object):
  '''Main class to handle commands.
     This class is responsible for parameter validation and call the corresponding
     operations.
  '''

  def __init__(self, opt):
    '''Constructor'''
    self.opt = opt

  def run(self, args):
    '''Main entry to handle commands. Dispatch to individual command handler.'''
    if len(args) == 0:
      raise InvalidArgument('No command provided')
    cmd = args[0]
    if cmd + '_handler' in CommandHandler.__dict__:
      CommandHandler.__dict__[cmd + '_handler'](self, args)
    else:
      raise InvalidArgument('Unknown command %s' % cmd)

  def s3handler(self):
    '''Create a S3Handler instances for multithread operations.'''
    return S3Handler(self.opt)

  @log_calls
  def validate(self, format, args):
    '''Validate input parameters with given format.
       This function also checks for wildcards for recursive mode.
    '''
    fmtMap = {
      'cmd': 'Command',
      's3': 's3 path',
      'local': 'local path'
    }
    fmts = format.split('|')
    if len(fmts) != len(args):
      raise InvalidArgument('Invalid number of parameters')

    for i, fmt in enumerate(fmts):
      valid = False
      for f in fmt.split(','):
        if f == 'cmd' and args[i] + '_handler' in CommandHandler.__dict__:
          valid = True
        if f == 's3' and S3URL.is_valid(args[i]):
          valid = True
        if f == 'local' and not S3URL.is_valid(args[i]):
          valid = True
      if not valid:
        raise InvalidArgument('Invalid parameter: %s, %s expected' % (args[i], fmtMap[fmt.split(',')[0]]))

  @log_calls
  def pretty_print(self, keylist):
    '''Pretty print the result of s3walk. Here we calculate the maximum width
       of each column and align them.
    '''

    def normalize_time(timestamp):
      '''Normalize the timestamp format for pretty print.'''
      if not timestamp:
        return ' ' * 16
      m = TIMESTAMP_REGEX.match(timestamp)
      result = m.groups()[0:5] if m else ['', '', '', '', '']
      return TIMESTAMP_FORMAT % result

    cwidth = [0, 0, 0]
    format = '%%%ds %%%ds %%-%ds'

    # Calculate maximum width for each column.
    result = []
    for key in keylist:
      last_modified = normalize_time(key['last_modified'])
      size = str(key['size']) if not key['is_dir'] else 'DIR'
      name = key['name']
      item = (last_modified, size, name)
      for i, value in enumerate(item):
        if cwidth[i] < len(value):
          cwidth[i] = len(value)
      result.append(item)

    # Format output.
    for item in result:
      text = (format % tuple(cwidth)) % item
      message('%s', text.rstrip())

  @log_calls
  def ls_handler(self, args):
    '''Handler for ls command'''
    if len(args) == 1:
      self.pretty_print(self.s3handler().list_buckets())
      return

    self.validate('cmd|s3', args)
    self.pretty_print(self.s3handler().s3walk(args[1]))

  @log_calls
  def put_handler(self, args):
    '''Handler for put command'''

    # Special check for shell expansion
    if len(args) < 3:
      raise InvalidArgument('Invalid number of parameters')
    self.validate('|'.join(['cmd'] + ['local'] * (len(args) - 2) + ['s3']), args)

    source = args[1:-1] # shell expansion
    target = args[-1]

    self.s3handler().put_files(source, target)

  @log_calls
  def get_handler(self, args):
    '''Handler for get command'''

    # Special case when we don't have target directory.
    if len(args) == 2:
      args += ['.']

    self.validate('cmd|s3|local', args)
    source = args[1]
    target = args[2]
    self.s3handler().get_files(source, target)

  @log_calls
  def sync_handler(self, args):
    '''Handler for sync command.
       XXX Here we emulate sync command with get/put -r -f --sync-check. So
           it doesn't provide delete operation.
    '''
    self.opt.recursive = True
    self.opt.sync_check = True
    self.opt.force = True

    self.validate('cmd|s3,local|s3,local', args)
    source = args[1]
    target = args[2]

    self.s3handler().sync_files(source, target)

  @log_calls
  def cp_handler(self, args):
    '''Handler for cp command'''

    self.validate('cmd|s3|s3', args)
    source = args[1]
    target = args[2]
    self.s3handler().cp_files(source, target)

  @log_calls
  def mv_handler(self, args):
    '''Handler for mv command'''

    self.validate('cmd|s3|s3', args)
    source = args[1]
    target = args[2]
    self.s3handler().cp_files(source, target, True)

  @log_calls
  def del_handler(self, args):
    '''Handler for del command'''
    self.validate('cmd|s3', args)
    source = args[1]
    self.s3handler().del_files(source)

  @log_calls
  def du_handler(self, args):
    '''Handler for size command'''
    for src, size in self.s3handler().size(args[1:]):
      message('%s\t%s' % (size, src))

  @log_calls
  def _totalsize_handler(self, args):
    '''Handler of total_size command'''
    total_size = 0
    for src, size in self.s3handler().size(args[1:]):
      total_size += size
    message(str(total_size))

if __name__ == '__main__':
  if not sys.argv[0]: sys.argv[0] = ''  # Workaround for running with optparse from egg

  # Parser for command line options.
  parser = optparse.OptionParser(description = 'Super S3 command line tool. Version %s' % S4CMD_VERSION)
  parser.add_option(
      '-p', '--config', help = 'path to s3cfg config file', dest = 's3cfg',
      type = 'string', default = None)
  parser.add_option(
      '-f', '--force', help = 'force overwrite files when download or upload',
      dest = 'force', action = 'store_true', default = False)
  parser.add_option(
      '-r', '--recursive', help = 'recursively checking subdirectories',
      dest = 'recursive', action = 'store_true', default = False)
  parser.add_option(
      '-s', '--sync-check', help = 'check file md5 before download or upload',
      dest = 'sync_check', action = 'store_true', default = False)
  parser.add_option(
      '-n', '--dry-run', help = 'trial run without actual download or upload',
      dest = 'dry_run', action = 'store_true', default = False)
  parser.add_option(
      '-t', '--retry', help = 'number of retries before giving up',
      dest = 'retry', type = int, default = 3)
  parser.add_option(
      '--retry-delay', help = 'seconds to sleep between retries',
      type = int, default = 10)
  parser.add_option(
      '-c', '--num-threads', help = 'number of concurrent threads',
      type = int, default = get_default_thread_count())
  parser.add_option(
      '-d', '--show-directory', help = 'show directory instead of its content',
      dest = 'show_dir', action = 'store_true', default = False)
  parser.add_option(
      '--ignore-empty-source', help = 'ignore empty source from s3',
      dest = 'ignore_empty_source', action = 'store_true', default = False)
  parser.add_option(
      '--use-ssl', help = 'use SSL connection to S3', dest = 'use_ssl',
      action = 'store_true', default = False)
  parser.add_option(
      '--verbose', help = 'verbose output', dest = 'verbose',
      action = 'store_true', default = False)
  parser.add_option(
      '--debug', help = 'debug output', dest = 'debug',
      action = 'store_true', default = False)
  parser.add_option(
      '--validate', help = 'validate lookup operation', dest = 'validate',
      action = 'store_true', default = False)
  parser.add_option(
      '-D', '--delete-removed',
      help = 'delete remote files that do not exist locally',
      dest = 'delete_removed', action = 'store_true', default = False)
  parser.add_option(
      '--multipart-split-size',
      help = 'size in MB to split multipart transfers', type = int,
      default = 50 * 1024 * 1024)
  parser.add_option(
      '--max-singlepart-download-size',
      help = 'files with size (in MB) greater than this will be downloaded in '
      'multipart transfers', type = int, default = 50 * 1024 * 1024)
  parser.add_option(
      '--max-singlepart-upload-size',
      help = 'files with size (in MB) greater than this will be uploaded in '
      'multipart transfers', type = int, default = 4500 * 1024 * 1024)

  (opt, args) = parser.parse_args()
  s4cmd_logging.configure(opt)

  # Initalize keys for S3.
  S3Handler.init_s3_keys(opt)

  try:
    CommandHandler(opt).run(args)
  except InvalidArgument as e:
    fail('[Invalid Argument] ', exc_info = e)
  except Failure as e:
    fail('[Runtime Failure] ', exc_info = e)
  except boto.exception.S3ResponseError as e:
    fail('[S3ResponseError] %s: %s' % (e.error_code, e.error_message))
  except Exception as e:
    fail('[Runtime Exception] ', exc_info = e, stacktrace = True)

  clean_tempfiles()
  progress('') # Clear progress message before exit.

# Revision history:
#
#   - 1.0.1:  Fixed wrongly directory created by cp command with a single file.
#             Fixed wrong directory discovery with a single child directory.
#   - 1.0.2:  Fix the problem of get/put/sync directories.
#             Fix the wildcard check for sync command.
#             Temporarily avoid multipart upload for files smaller than 4.5G
#             Stop showing progress if output is not connected to tty.
#   - 1.5:    Allow wildcards with recursive mode.
#             Support -d option for ls command.
#   - 1.5.1:  Fix the bug that recursive S3 walk wrongly check the prefix.
#             Add more tests.
#             Fix md5 etag (with double quote) checking bug.
#   - 1.5.2:  Read keys from environment variable or s3cfg.
#             Implement mv command.
#   - 1.5.3:  Implement du and _totalsize command.
#   - 1.5.4:  Implement --ignore-empty-source parameter for backward compatibility.
#   - 1.5.5:  Implement environment variable S4CMD_NUM_THREADS to change the default
#             number of threads.
#   - 1.5.6:  Fix s4cmd get/sync error with --ignore-empty-source for empty source
#   - 1.5.7:  Fix multi-threading race condition with os.makedirs call
#   - 1.5.8:  Fix the initialization of Options class.
#   - 1.5.9:  Open source licensing.
#   - 1.5.10: Fix options global variable bug
#   - 1.5.11: Fix atomic write issue for small files calling boto API directly.
#             Add code to cleanup temp files.
#             Fix a bug where pretty_print calls message() without format.
#   - 1.5.12: Add RetryFailure class to unknown network failures.
#   - 1.5.13: Also retry S3ResponseError exceptions.
#   - 1.5.14: Copy file privileges. If s4cmd sync is used, then it only update
#             privileges of files when their signatures are different
#   - 1.5.15: Close http connection cleanly after thread pool execution.
#   - 1.5.16: Disable consecutive slashes removal.
#   - 1.5.17: Check file size consistency after download; will retry the download if inconsistent.
#   - 1.5.18: Use validate=self.opt.validate to prevent extraneous list API calls.
#   - 1.5.19: Set socket.setdefaulttimeout() to prevent boto/s3 socket read block in httplib.
#   - 1.5.20: Merge change from oniltonmaciel@github for arguments for multi-part upload.
#             Fix setup.py for module and command line tool
#   - 1.5.21: Merge changes from linsomniac@github for better argument parsing
#   - 1.5.22: Add compatibility for Python3
#   - 1.5.23: Add bash command line completion
