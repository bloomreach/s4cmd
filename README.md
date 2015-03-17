# s4cmd

### Super S3 command line tool

Chou-han Yang
2012-11-09 (covers s4cmd version 1.5.19)

## Motivation

S4cmd is a command-line utility for accessing
[Amazon S3](http://en.wikipedia.org/wiki/Amazon_S3), inspired by
[s3cmd](http://s3tools.org/s3cmd).

We have used s3cmd heavily for a number of scripted, data-intensive
applications. However as the need for a variety of small improvements arose, we
created our own implementation, s4cmd. It is intended as an alternative to
s3cmd for enhanced performance and for large files, and with a number of
additional features and fixes that we have found useful.

It strives to be compatible with the most common usage scenarios for s3cmd. It
does not offer exact drop-in compatibility, due to a number of corner cases where
different behavior seems preferable, or for bugfixes.


## Features

S4cmd supports the regular commands you might expect for fetching and storing
files in S3: `ls`, `put`, `get`, `cp`, `mv`, `sync`, `del`, `du`.

The main features that distinguish s4cmd are:

- Simple (less than 1500 lines of code) and implemented in pure Python, based
  on the widely used [Boto](https://github.com/boto/boto) library.
- Multi-threaded/multi-connection implementation for enhanced performance on all
  commands. As with many network-intensive applications (like web browsers),
  accessing S3 in a single-threaded way is often significantly less efficient than
  having multiple connections actively transferring data at once.  In general, we
  get a 2X boost to upload/download speeds from this.
- Path handling: S3 is not a traditional filesystem with built-in support for
  directory structure: internally, there are only objects, not directories or
  folders. However, most people use S3 in a hierarchical structure, with paths
  separated by slashes, to emulate traditional filesystems. S4cmd follows
  conventions to more closely replicate the behavior of traditional filesystems
  in certain corner cases.  For example, "ls" and "cp" work much like in Unix
  shells, to avoid odd surprises. (For examples see compatibility notes below.)
- Wildcard support: Wildcards, including multiple levels of wildcards, like in
  Unix shells, are handled. For example:
  s3://my-bucket/my-folder/20120512/*/*chunk00?1?
- Automatic retry: Failure tasks will be executed again after a delay.
- Multi-part upload support for files larger than 5GB.
- Handling of MD5s properly with respect to multi-part uploads (for the sordid
  details of this, see below).
- Miscellaneous enhancements and bugfixes:
  - Partial file creation: Avoid creating empty target files if source does not
    exist. Avoid creating partial output files when commands are interrupted.
  - General thread safety: Tool can be interrupted or killed at any time without
    being blocked by child threads or leaving incomplete or corrupt files in
    place.
  - Ensure exit code is nonzero on all failure scenarios (a very important
    feature in scripts).
  - Expected handling of symlinks (they are followed).
  - Support both `s3://` and `s3n://` prefixes (the latter is common with
    Amazon Elastic Mapreduce).

Limitations:

- No CloudFront or other feature support.
- Currently, we simulate `sync` with `get` and `put` with `--recursive --force --sync-check`.


## Installation and Setup
You can install `s4cmd` [PyPI](https://pypi.python.org/pypi/s4cmd).

```
pip install s4cmd
```

- Copy or create a symbolic link so you can run `s4cmd.py` as `s4cmd`. (It is just
a single file!)
- If you already have a `~/.s3cfg` file from configuring `s3cmd`, credentials
from this file will be used.  Otherwise, set the `S3_ACCESS_KEY` and
`S3_SECRET_KEY` environment variables to contain your S3 credentials.


## Common Commands

### s4cmd ls [path]

> List all contents of a directory.
>
> Available parameters:
>>* -r/--recursive: recursively display all contents including subdirectories under the given path.
>>* -d/--show-directory: show the directory entry instead of its content.

### s4cmd put <source> <target>

> Upload local files up to S3.
>
> Available parameters:
>>*   -r/--recursive: also upload directories recursively.
>>*   -s/--sync-check: check md5 hash to avoid uploading the same content.
>>*   -f/--force: override existing file instead of showing error message.
>>*   -n/--dry-run: emulate the operation without real upload.

### s4cmd get <source> <target>

> Download files from S3 to local filesystem.
>
> Available parameters:
>>*   -r/--recursive: also download directories recursively.
>>*   -s/--sync-check: check md5 hash to avoid downloading the same content.
>>*   -f/--force: override existing file instead of showing error message.
>>*   -n/--dry-run: emulate the operation without real download.

### s4cmd sync <source> <target>

> Synchronize the contents of two directories. The directory can either be local or remote, but currently, it doesn't support two local directories.
>
> Available parameters:
>>*   -r/--recursive: also sync directories recursively.
>>*   -s/--sync-check: check md5 hash to avoid syncing the same content.
>>*   -f/--force: override existing file instead of showing error message.
>>*   -n/--dry-run: emulate the operation without real sync.

### s4cmd cp <source> <target>

> Copy a file or a directory from a S3 location to another.
>
> Available parameters:
>>*   -r/--recursive: also copy directories recursively.
>>*   -s/--sync-check: check md5 hash to avoid copying the same content.
>>*   -f/--force: override existing file instead of showing error message.
>>*   -n/--dry-run: emulate the operation without real copy.

### s4cmd mv <source> <target>

> Move a file or a directory from a S3 location to another.
>
> Available parameters:
>>*   -r/--recursive: also move directories recursively.
>>*   -s/--sync-check: check md5 hash to avoid moving the same content.
>>*   -f/--force: override existing file instead of showing error message.
>>*   -n/--dry-run: emulate the operation without real move.

### s4cmd del <path>

> Delete files or directories on S3.
>
> Available parameters:
>>*   -r/--recursive: also delete directories recursively.
>>*   -n/--dry-run: emulate the operation without real delete.

### s4cmd du <path>

> Get the size of the given directory.
>
> Available parameters:
>>*   -r/--recursive: also add sizes of sub-directories recursively.


## Compatibility between s3cmd and s4cmd

Prefix matching: In s3cmd, unlike traditional filesystems, prefix names match listings:
>>s3cmd ls s3://my-bucket/ch
>s3://my-bucket/charlie/
>s3://my-bucket/chyang/

In s4cmd, behavior is the same as with a Unix shell:

>>s4cmd ls s3://my-bucket/ch
>(empty)

To get prefix behavior, use explicit wildcards instead: s4cmd ls s3://my-bucket/ch*

Similarly, sync and cp commands emulate the Unix cp command, so directory to
directory sync use different syntax:

- s3cmd sync s3://bucket/path/dirA s3://bucket/path/dirB/ will copy contents in dirA to dirB.
- s4cmd sync s3://bucket/path/dirA s3://bucket/path/dirB/ will copy dirA *into* dirB.

To achieve the s3cmd behavior, use wildcards:
s4cmd sync s3://bucket/path/dirA/* s3://bucket/path/dirB/

Note s4cmd doesn't support dirA without trailing slash indicating dirA/* as
what rsync supported.

No automatic override for put command:
s3cmd put fileA s3://bucket/path/fileB will return error if fileB exists.
Use -f as well as get command.

Bugfixes for handling of non-existent paths: Often s3cmd creates empty files when specified paths do not exist:
s3cmd get s3://my-bucket/no_such_file downloads an empty file.
s4cmd get s3://my-bucket/no_such_file returns an error.
s3cmd put no_such_file s3://my-bucket/ uploads an empty file.
s4cmd put no_such_file s3://my-bucket/ returns an error.


## Additional technical notes

Etags, MD5s and multi-part uploads: Traditionally, the etag of an object in S3
has been its MD5.  However, this changed with the introduction of S3 multi-part
uploads; in this case the etag is still a unique ID, but it is not the MD5 of
the file. Amazon has not revealed the definition of the etag in this case, so
there is no way we can calculate and compare MD5s based on the etag header in
general. The workaround we use is to upload the MD5 as a supplemental content
header (called "md5", instead of "etag"). This enables s4cmd to check the MD5
hash before upload or download. The only limitation is that this only works for
files uploaded via s4cmd. Programs that do not understand this header will
still have to download and verify the MD5 directly.


## Unimplemented features

- Deletion with sync command.
- CloudFront or other feature support beyond basic S3 access.
- Command-line auto-complete.
