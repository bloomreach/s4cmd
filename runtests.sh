#!/bin/bash

#
# Copyright 2012 BloomReach, Inc.
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

#
# Tests for s4cmd command line tool
#

LOCALDIR=./test-tmp
REMOTEDIR=s3://br-tmp/s4cmd/test
S4CMD=$(pwd)/s4cmd.py
FILESIZE=1M

# Create testing data locally
rm -rf $LOCALDIR
mkdir $LOCALDIR
pushd $LOCALDIR

mkdir source
pushd source
  dd if=/dev/urandom of=001 bs=$FILESIZE count=2
  dd if=/dev/urandom of=010 bs=$FILESIZE count=2
  dd if=/dev/urandom of=101 bs=$FILESIZE count=2
  mkdir a
  pushd a
    mkdir a
    pushd a
      dd if=/dev/urandom of=a-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a-101 bs=$FILESIZE count=2
    popd
    mkdir a1
    pushd a1
      dd if=/dev/urandom of=a1-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a1-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a1-101 bs=$FILESIZE count=2
    popd
    mkdir a2
    pushd a2
      dd if=/dev/urandom of=a2-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a2-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a2-101 bs=$FILESIZE count=2
    popd
    mkdir a3
    pushd a3
      dd if=/dev/urandom of=a3-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a3-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=a3-101 bs=$FILESIZE count=2
    popd
  popd

  mkdir b
  pushd b
    mkdir b
    pushd b
      dd if=/dev/urandom of=b-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b-101 bs=$FILESIZE count=2
    popd
    mkdir b1
    pushd b1
      dd if=/dev/urandom of=b1-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b1-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b1-101 bs=$FILESIZE count=2
    popd
    mkdir b2
    pushd b2
      dd if=/dev/urandom of=b2-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b2-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b2-101 bs=$FILESIZE count=2
    popd
    mkdir b3
    pushd b3
      dd if=/dev/urandom of=b3-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b3-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=b3-101 bs=$FILESIZE count=2
    popd
  popd

  mkdir c
  pushd c
    mkdir c
    pushd c
      dd if=/dev/urandom of=c-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c-101 bs=$FILESIZE count=2
    popd
    mkdir c1
    pushd c1
      dd if=/dev/urandom of=c1-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c1-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c1-101 bs=$FILESIZE count=2
    popd
    mkdir c2
    pushd c2
      dd if=/dev/urandom of=c2-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c2-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c2-101 bs=$FILESIZE count=2
    popd
    mkdir c3
    pushd c3
      dd if=/dev/urandom of=c3-001 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c3-010 bs=$FILESIZE count=2
      dd if=/dev/urandom of=c3-101 bs=$FILESIZE count=2
    popd
  popd
  
popd

# Clear target testing directory
$S4CMD del -r $REMOTEDIR/

echo 'Start test cases'

tree source | tail -n +2 > source.tree

#####################################################################
CASE_ID=case1-1
echo "Test $CASE_ID: single file upload/download"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/001 $REMOTEDIR/$CASE_ID/001 > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 > $CASE_ID.log 2>&1

md5sum source/001 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/001 | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case1-2
echo "Test $CASE_ID: single file upload/download (Trailing slash)"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/001 $REMOTEDIR/$CASE_ID/001-1/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/001-1/001 $CASE_ID/001-1 > $CASE_ID.log 2>&1

md5sum source/001 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/001-1 | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case2-1
echo "Test $CASE_ID: wildcards upload"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/* $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case2-2
echo "Test $CASE_ID: wildcards upload (trailing slash)"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/*/?2/b?-1?1 $REMOTEDIR/$CASE_ID/a > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/a $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/b?-1?1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case3-1
echo "Test $CASE_ID: list files"
#####################################################################
$S4CMD put source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD ls $REMOTEDIR/$CASE_ID/ > $CASE_ID.out 2> $CASE_ID.err

n1=$(ls source/*/?2/*-??1 | wc -l)
n2=$(cat $CASE_ID.out | wc -l)
if [[ "$n1" -eq "$n2" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case3-2
echo "Test $CASE_ID: list files (show directory)"
#####################################################################
$S4CMD put source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD ls -d $REMOTEDIR/$CASE_ID > $CASE_ID.out 2> $CASE_ID.err

n1=$(cat $CASE_ID.out | wc -l)
if [[ "$n1" -eq "1" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case4-1
echo "Test $CASE_ID: single directory (upload and download)"
#####################################################################
$S4CMD put -r source/a/a1/ $REMOTEDIR/$CASE_ID > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID/ $CASE_ID > $CASE_ID.log 2>&1

md5sum source/a/a1/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case4-2
echo "Test $CASE_ID: single directory (Trailing slash)"
#####################################################################
$S4CMD put -r source/a/a1/ $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID/a1/ $CASE_ID > $CASE_ID.log 2>&1

md5sum source/a/a1/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case4-3
echo "Test $CASE_ID: single directory (Wildcards)"
#####################################################################
mkdir $CASE_ID
$S4CMD put -r source/a/a?/ $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID/a?/ $CASE_ID > $CASE_ID.log 2>&1

md5sum source/a/a?/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/*/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case4-4
echo "Test $CASE_ID: single directory (prefix)"
#####################################################################
mkdir $CASE_ID
$S4CMD put -r source/a/a $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID/a $CASE_ID > $CASE_ID.log 2>&1

md5sum source/a/a/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/*/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case5-1
echo "Test $CASE_ID: trailing slash"
#####################################################################
$S4CMD put -r source/a/a1 $REMOTEDIR/$CASE_ID > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID $CASE_ID > $CASE_ID.log 2>&1

md5sum source/a/a1/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case5-2
echo "Test $CASE_ID: trailing slash (normalization)"
#####################################################################
$S4CMD put -r source/a/a1/ $REMOTEDIR/$CASE_ID > $CASE_ID.log 2>&1
$S4CMD get -r $REMOTEDIR/$CASE_ID $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/a/a1/* | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case6-1
echo "Test $CASE_ID: syncing up and down"
#####################################################################
$S4CMD sync source $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD sync $REMOTEDIR/$CASE_ID/ $CASE_ID/ > $CASE_ID.log 2>&1
tree $CASE_ID/source | tail -n +2 > $CASE_ID.tree

result=$(diff source.tree $CASE_ID.tree)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case6-2
echo "Test $CASE_ID: syncing up and down (current directory)"
#####################################################################
cd source
$S4CMD sync ./ $REMOTEDIR/$CASE_ID/source > ../$CASE_ID.log 2>&1
cd ..
mkdir $CASE_ID
cd $CASE_ID
$S4CMD sync $REMOTEDIR/$CASE_ID/source ./ > ../$CASE_ID.log 2>&1
cd ..
tree $CASE_ID/source | tail -n +2 > $CASE_ID.tree

result=$(diff source.tree $CASE_ID.tree)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case7-1
echo "Test $CASE_ID: wildcard download"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case7-2
echo "Test $CASE_ID: wildcard download (trailing slash)"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source/ $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case8-1
echo "Test $CASE_ID: single file copy"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/001 $REMOTEDIR/$CASE_ID/001_copy > $CASE_ID.log 2>&1
$S4CMD cp $REMOTEDIR/$CASE_ID/001_copy $REMOTEDIR/$CASE_ID/001 > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 > $CASE_ID.log 2>&1

md5sum source/001 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/001 | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case8-2
echo "Test $CASE_ID: recursive copy"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source $REMOTEDIR/$CASE_ID-copy/ > $CASE_ID.log 2>&1
$S4CMD cp -r $REMOTEDIR/$CASE_ID-copy $REMOTEDIR/$CASE_ID > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case8-3
echo "Test $CASE_ID: wildcards copy"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source $REMOTEDIR/$CASE_ID-copy/ > $CASE_ID.log 2>&1
$S4CMD cp -r $REMOTEDIR/$CASE_ID-copy/source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/* $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case9-1
echo "Test $CASE_ID: single file move"
#####################################################################
mkdir $CASE_ID
$S4CMD put source/001 $REMOTEDIR/$CASE_ID/001_copy > $CASE_ID.log 2>&1
$S4CMD mv $REMOTEDIR/$CASE_ID/001_copy $REMOTEDIR/$CASE_ID/001 > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 > $CASE_ID.log 2>&1

md5sum source/001 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/001 | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case9-2
echo "Test $CASE_ID: recursive move"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source $REMOTEDIR/$CASE_ID-copy/ > $CASE_ID.log 2>&1
$S4CMD mv -r $REMOTEDIR/$CASE_ID-copy $REMOTEDIR/$CASE_ID > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case9-3
echo "Test $CASE_ID: wildcards move"
#####################################################################
mkdir $CASE_ID
$S4CMD sync source $REMOTEDIR/$CASE_ID-copy/ > $CASE_ID.log 2>&1
$S4CMD mv -r $REMOTEDIR/$CASE_ID-copy/source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/* $CASE_ID/ > $CASE_ID.log 2>&1

md5sum source/*/?2/*-??1 | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/* | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case10-1
echo "Test $CASE_ID: get size with du"
#####################################################################
$S4CMD put source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD du $REMOTEDIR/$CASE_ID/ > $CASE_ID.out 2> $CASE_ID.err

s=$(cat $CASE_ID.out | cut -f1)
if [[ "$s" -eq "12582912" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case10-2
echo "Test $CASE_ID: get total size (experimental)"
#####################################################################
$S4CMD put source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD _totalsize $REMOTEDIR/$CASE_ID $REMOTEDIR/$CASE_ID > $CASE_ID.out 2> $CASE_ID.err

s=$(cat $CASE_ID.out | cut -f1)
if [[ "$s" -eq "25165824" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case11
echo "Test $CASE_ID: large files (> 5G)"
#####################################################################
mkdir $CASE_ID
#dd if=/dev/urandom of=large bs=500M count=2
cp ../large large
$S4CMD put large $REMOTEDIR/$CASE_ID/large > $CASE_ID.log 2>&1
$S4CMD get $REMOTEDIR/$CASE_ID/large $CASE_ID/large > $CASE_ID.log 2>&1

md5sum large | cut -f1 -d' ' > $CASE_ID.md5
md5sum $CASE_ID/large | cut -f1 -d' ' > $CASE_ID.chk
result=$(diff $CASE_ID.md5 $CASE_ID.chk)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

#####################################################################
CASE_ID=case12
echo "Test $CASE_ID: deletion"
#####################################################################
$S4CMD sync source $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD del -r $REMOTEDIR/$CASE_ID/ > $CASE_ID.log 2>&1
$S4CMD ls $REMOTEDIR/$CASE_ID/ > $CASE_ID.out 2> $CASE_ID.err

result=$(cat $CASE_ID.out)
if [[ -z "$result" ]]; then
  echo "  - OK"
else
  echo "  - Failed"
fi

popd # from local-tmp
