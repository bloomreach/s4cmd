# CHANGELOG

#### v2.1.0

- Added `--endpoint_url` flag to allow s4cmd to work with non-s3 object storage services ([#82](https://github.com/bloomreach/s4cmd/pull/82)) 
- Fix bug in pip install ([#102](https://github.com/bloomreach/s4cmd/pull/102))
- Fix bug which was leading to errors on zero length files ([#81](https://github.com/bloomreach/s4cmd/pull/81))
- Add flag `--version` to display s4cmd version
- Check added to ensure consistency of `os.write` in method `write_file_chunk`
- Full E2E test-suite running on python 2 and 3, backed by Travis-CI

#### v2.0.1

- Merge change from @rameshrajagopal for S3 keys in command-line parameters.

#### v2.0.0

- Fully migrated from old boto 2.x to new boto3 library.
- Support S3 pass through APIs.
- Support batch delete (with delete_objects API).
- Support S4CMD_OPTS environment variable.
- Support moving files larger than 5GB with multipart upload.
- Support timestamp filtering with --last-modified-before and --last-modified-after options.
- Faster upload with lazy evaluation of md5 hash.
- Listing large number of files with S3 pagination, with memory is the limit.
- New directory to directory dsync command to replace old sync command.

#### v1.5.23

- Add bash command line completion

#### v1.5.22

- Add compatibility for Python3

#### v1.5.21

- Merge changes from linsomniac@github for better argument parsing

#### v1.5.20

- Merge change from oniltonmaciel@github for arguments for multi-part upload.
- Fix setup.py for module and command line tool

#### v1.5.19

- Set socket.setdefaulttimeout() to prevent boto/s3 socket read block in httplib.

#### v1.5.18

- Use validate=self.opt.validate to prevent extraneous list API calls.

#### v1.5.17

- Check file size consistency after download; will retry the download if inconsistent.

#### v1.5.16

- Disable consecutive slashes removal.

#### v1.5.15

- Close http connection cleanly after thread pool execution.

#### v1.5.14

- Copy file privileges. If s4cmd sync is used, then it only update privileges of files when their signatures are different

#### v1.5.13

- Also retry S3ResponseError exceptions.

#### v1.5.12

- Add RetryFailure class to unknown network failures.

#### v1.5.11

- Fix atomic write issue for small files calling boto API directly.
- Add code to cleanup temp files.
- Fix a bug where pretty_print calls message() without format.

#### v1.5.10

- Fix options global variable bug 

#### v1.5.9

- Open source licensing.

#### v1.5.8

- Fix the initialization of Options class.

#### v1.5.7

- Fix multi-threading race condition with os.makedirs call

#### v1.5.6

- Fix s4cmd get/sync error with --ignore-empty-source for empty source

#### v1.5.5

- Implement environment variable S4CMD_NUM_THREADS to change the default
number of threads.

#### v1.5.4

- Implement --ignore-empty-source parameter for backward compatibility.

#### v1.5.3

- Implement du and _totalsize command.

#### v1.5.2

- Read keys from environment variable or s3cfg.
- Implement mv command

#### v1.5.1

- Fix the bug that recursive S3 walk wrongly check the prefix.
- Add more tests.
- Fix md5 etag (with double quote) checking bug.

#### v1.5

- Allow wildcards with recursive mode.
- Support -d option for ls command.

#### v1.0.2

- Fix the problem of get/put/sync directories.
- Fix the wildcard check for sync command.
- Temporarily avoid multipart upload for files smaller than 4.5G
- Stop showing progress if output is not connected to tty.

#### v1.0.1

- Fixed wrongly directory created by cp command with a single file.
- Fixed wrong directory discovery with a single child directory.

