#!/bin/bash

#
# Copyright 2012-2021 BloomReach, Inc.
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

# Python settings, can be python 2 or 3
PYTHON=${PYTHON:-python}
PYTHONPATH=${PYTHONPATH:-$(pwd)}
PYTHON_VERSION=$(python --version 2>&1)
PYTHON_VERSION_NUM=$(awk '{print $2}' <<< ${PYTHON_VERSION})
BUILD_ID=${BUILD_ID:-0}
LOCALDIR=./test-tmp
REMOTEDIR=${REMOTEDIR:-"s3://bucket/path"}
REMOTEDIR="${REMOTEDIR}/${BUILD_ID}/${PYTHON_VERSION_NUM}"
S4CMD="${PYTHON} $(pwd)/s4cmd.py"
S4CMD_OPTS=${S4CMD_OPTS:-"--debug"}
FILESIZE=1M
TEST_FAILED=false

function initialize {
  # Create testing data locally
  rm -rf $LOCALDIR
  mkdir $LOCALDIR
  pushd $LOCALDIR

  mkdir source
  pushd source
    dd if=/dev/urandom of=001 bs=$FILESIZE count=2
    dd if=/dev/urandom of=010 bs=$FILESIZE count=2
    dd if=/dev/urandom of=101 bs=$FILESIZE count=2
    touch 011
    chmod 700 001
    chmod 770 010
    chmod 707 101
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
  $S4CMD del ${S4CMD_OPTS} -r $REMOTEDIR/

  echo 'Start test cases'

  tree source | tail -n +2 > source.tree

  popd # from local-tmp
}

function case1-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single file upload/download"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/001 $REMOTEDIR/$CASE_ID/001 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 >> $CASE_ID.log 2>&1

  md5sum source/001 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/001 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case1-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single file upload/download (Trailing slash)"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/001 $REMOTEDIR/$CASE_ID/001-1/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001-1/001 $CASE_ID/001-1 >> $CASE_ID.log 2>&1

  md5sum source/001 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/001-1 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case1-3 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: Empty file upload/download"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/011 $REMOTEDIR/$CASE_ID/011 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/011 $CASE_ID/011 >> $CASE_ID.log 2>&1

  md5sum source/011 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/011 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case2-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcards upload"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/* $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case2-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcards upload (trailing slash)"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/*/?2/b?-1?1 $REMOTEDIR/$CASE_ID/a >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/a $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/b?-1?1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case3-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: list files"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD ls ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ >> $CASE_ID.out 2> $CASE_ID.err

  n1=$(ls source/*/?2/*-??1 | wc -l)
  n2=$(cat $CASE_ID.out | wc -l)
  if [[ "$n1" -eq "$n2" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case3-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: list files (show directory)"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD ls ${S4CMD_OPTS} -d $REMOTEDIR/$CASE_ID >> $CASE_ID.out 2> $CASE_ID.err

  n1=$(cat $CASE_ID.out | wc -l)
  if [[ "$n1" -eq "1" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case4-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single directory (upload and download)"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} -r source/a/a1/ $REMOTEDIR/$CASE_ID >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID/ $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/a/a1/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case4-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single directory (Trailing slash)"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} -r source/a/a1/ $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID/a1/ $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/a/a1/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case4-3 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single directory (Wildcards)"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} -r source/a/a?/ $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID/a?/ $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/a/a?/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/*/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case4-4 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single directory (prefix)"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} -r source/a/a $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID/a $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/a/a/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/*/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case5-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: trailing slash"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} -r source/a/a1 $REMOTEDIR/$CASE_ID >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/a/a1/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case5-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: trailing slash (normalization)"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} -r source/a/a1/ $REMOTEDIR/$CASE_ID >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/a/a1/* | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case6-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: syncing up and down"
  #####################################################################
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ $CASE_ID/ >> $CASE_ID.log 2>&1
  tree $CASE_ID/source | tail -n +2 >> $CASE_ID.tree

  result=$(diff source.tree $CASE_ID.tree)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case6-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: syncing up and down (current directory)"
  #####################################################################
  cd source
  $S4CMD sync ${S4CMD_OPTS} ./ $REMOTEDIR/$CASE_ID/source >> ../$CASE_ID.log 2>&1
  cd ..
  mkdir $CASE_ID
  cd $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source ./ >> ../$CASE_ID.log 2>&1
  cd ..
  tree $CASE_ID/source | tail -n +2 >> $CASE_ID.tree

  result=$(diff source.tree $CASE_ID.tree)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function obsolete_case6-x {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: syncing up and down (--delete-removed)"
  #####################################################################
  mkdir $CASE_ID-1
  mkdir $CASE_ID-2
  cp -r source/a $CASE_ID-1/
  $S4CMD sync ${S4CMD_OPTS} $CASE_ID-1/a $REMOTEDIR/$CASE_ID-1/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID-1/a $REMOTEDIR/$CASE_ID-2/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID-2/a $CASE_ID-2/ >> $CASE_ID.log 2>&1

  rm $CASE_ID-1/a/*/*-010

  $S4CMD sync ${S4CMD_OPTS} --delete-removed $CASE_ID-1/a $REMOTEDIR/$CASE_ID-1/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} --delete-removed $REMOTEDIR/$CASE_ID-1/a $REMOTEDIR/$CASE_ID-2/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} --delete-removed $REMOTEDIR/$CASE_ID-2/a $CASE_ID-2/ >> $CASE_ID.log 2>&1

  tree $CASE_ID-1/a | tail -n +2 >> $CASE_ID.tree1
  tree $CASE_ID-2/a | tail -n +2 >> $CASE_ID.tree2

  result=$(diff $CASE_ID.tree1 $CASE_ID.tree2)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case6-3 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: dsyncing up and down"
  #####################################################################
  $S4CMD dsync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID/source >> $CASE_ID.log 2>&1
  $S4CMD dsync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ $CASE_ID/ >> $CASE_ID.log 2>&1
  tree $CASE_ID/source | tail -n +2 >> $CASE_ID.tree

  result=$(diff source.tree $CASE_ID.tree)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case6-4 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: dsyncing up and down (current directory)"
  #####################################################################
  cd source
  $S4CMD dsync ${S4CMD_OPTS} ./ $REMOTEDIR/$CASE_ID/source >> ../$CASE_ID.log 2>&1
  cd ..
  mkdir $CASE_ID
  cd $CASE_ID
  $S4CMD dsync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source ./ >> ../$CASE_ID.log 2>&1
  cd ..
  tree $CASE_ID/ | tail -n +2 >> $CASE_ID.tree

  result=$(diff source.tree $CASE_ID.tree)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case6-5 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: dsyncing up and down (--delete-removed)"
  #####################################################################
  mkdir $CASE_ID-1
  mkdir $CASE_ID-2
  cp -r source/a $CASE_ID-1/
  $S4CMD dsync ${S4CMD_OPTS} $CASE_ID-1/a $REMOTEDIR/$CASE_ID-1/a >> $CASE_ID.log 2>&1
  $S4CMD dsync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID-1/a $REMOTEDIR/$CASE_ID-2/a >> $CASE_ID.log 2>&1
  $S4CMD dsync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID-2/a $CASE_ID-2/a >> $CASE_ID.log 2>&1

  rm $CASE_ID-1/a/*/*-010

  $S4CMD dsync ${S4CMD_OPTS} --delete-removed $CASE_ID-1/a $REMOTEDIR/$CASE_ID-1/a >> $CASE_ID.log 2>&1
  $S4CMD dsync ${S4CMD_OPTS} --delete-removed $REMOTEDIR/$CASE_ID-1/a $REMOTEDIR/$CASE_ID-2/a >> $CASE_ID.log 2>&1
  $S4CMD dsync ${S4CMD_OPTS} --delete-removed $REMOTEDIR/$CASE_ID-2/a $CASE_ID-2/a >> $CASE_ID.log 2>&1

  tree $CASE_ID-1/a | tail -n +2 >> $CASE_ID.tree1
  tree $CASE_ID-2/a | tail -n +2 >> $CASE_ID.tree2

  result=$(diff $CASE_ID.tree1 $CASE_ID.tree2)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case7-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcard download"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case7-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcard download (trailing slash)"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source/ $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case8-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single file copy"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/001 $REMOTEDIR/$CASE_ID/001_copy >> $CASE_ID.log 2>&1
  $S4CMD cp ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001_copy $REMOTEDIR/$CASE_ID/001 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 >> $CASE_ID.log 2>&1

  md5sum source/001 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/001 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case8-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: recursive copy"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID-copy/ >> $CASE_ID.log 2>&1
  $S4CMD cp ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID-copy $REMOTEDIR/$CASE_ID >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case8-3 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcards copy"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID-copy/ >> $CASE_ID.log 2>&1
  $S4CMD cp ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID-copy/source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/* $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case9-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: single file move"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/001 $REMOTEDIR/$CASE_ID/001_copy >> $CASE_ID.log 2>&1
  $S4CMD mv ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001_copy $REMOTEDIR/$CASE_ID/001 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/001 $CASE_ID/001 >> $CASE_ID.log 2>&1

  md5sum source/001 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/001 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case9-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: recursive move"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID-copy/ >> $CASE_ID.log 2>&1
  $S4CMD mv ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID-copy $REMOTEDIR/$CASE_ID >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/source/*/?2/*-??1 $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case9-3 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: wildcards move"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID-copy/ >> $CASE_ID.log 2>&1
  $S4CMD mv ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID-copy/source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/* $CASE_ID/ >> $CASE_ID.log 2>&1

  md5sum source/*/?2/*-??1 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/* | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case10-1 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: get size with du"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD du ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ >> $CASE_ID.out 2> $CASE_ID.err

  s=$(cat $CASE_ID.out | cut -f1)
  if [[ "$s" -eq "12582912" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case10-2 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: get total size (experimental)"
  #####################################################################
  $S4CMD put ${S4CMD_OPTS} source/*/?2/*-??1 $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD _totalsize ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID $REMOTEDIR/$CASE_ID >> $CASE_ID.out 2> $CASE_ID.err

  s=$(cat $CASE_ID.out | cut -f1)
  if [[ "$s" -eq "25165824" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case11 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: large files put/mv/get (multipart upload) with permission"
  #####################################################################
  mkdir $CASE_ID
  large=$CASE_ID/large-source
  dd if=/dev/urandom of=$large bs=10M count=10 iflag=fullblock >> $CASE_ID.log 2>&1
  chmod 444 $large

  MULTIPART_OPT="--multipart-split-size=5242880 --max-singlepart-upload-size=10485760 --max-singlepart-upload-size=10485760 --max-singlepart-download-size=10485760"

  $S4CMD put ${S4CMD_OPTS} ${MULTIPART_OPT} $large $REMOTEDIR/$CASE_ID/large >> $CASE_ID.log 2>&1
  $S4CMD mv  ${S4CMD_OPTS} ${MULTIPART_OPT} $REMOTEDIR/$CASE_ID/large $REMOTEDIR/$CASE_ID/large2 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} ${MULTIPART_OPT} $REMOTEDIR/$CASE_ID/large2 $CASE_ID/large >> $CASE_ID.log 2>&1

  stat -c %A $large >> $CASE_ID/large.privilege
  stat -c %A $CASE_ID/large >> $CASE_ID/large_dest.privilege

  md5sum $large | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/large | cut -f1 -d' ' >> $CASE_ID.chk

  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  result_permission=$(diff $CASE_ID/large.privilege $CASE_ID/large_dest.privilege)
  if [[ ( -z "$result" ) && ( -z "$result_permission" ) ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case12 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: deletion"
  #####################################################################
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD del ${S4CMD_OPTS} -r $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD ls ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ >> $CASE_ID.out 2> $CASE_ID.err

  result=$(cat $CASE_ID.out)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case13 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: Testing file permissions"
  #####################################################################
  $S4CMD sync ${S4CMD_OPTS} source $REMOTEDIR/$CASE_ID/ >> $CASE_ID.log 2>&1
  $S4CMD sync ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID/ $CASE_ID/ >> $CASE_ID.log 2>&1
  stat -c %A source/* >> $CASE_ID/orig.privilege
  stat -c %A $CASE_ID/source/* >> $CASE_ID/dest.privilege

  result=$(diff $CASE_ID/orig.privilege $CASE_ID/dest.privilege)

  if [[ -z "$result_001" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

function case14 {
  #####################################################################
  CASE_ID=${FUNCNAME[0]}
  echo "Test $CASE_ID: Testing double slashes"
  #####################################################################
  mkdir $CASE_ID
  $S4CMD put ${S4CMD_OPTS} source/001 $REMOTEDIR/$CASE_ID//001 >> $CASE_ID.log 2>&1
  $S4CMD get ${S4CMD_OPTS} $REMOTEDIR/$CASE_ID//001 $CASE_ID/001 >> $CASE_ID.log 2>&1

  md5sum source/001 | cut -f1 -d' ' >> $CASE_ID.md5
  md5sum $CASE_ID/001 | cut -f1 -d' ' >> $CASE_ID.chk
  result=$(diff $CASE_ID.md5 $CASE_ID.chk)
  if [[ -z "$result" ]]; then
    echo "  - OK"
  else
    echo "  - Failed"
    TEST_FAILED=true
  fi
}

TEST_CASES=
if [ "$#" -ne 1 ]; then
  echo "Running all tests"
  # Search all test cases functions.
  TEST_CASES="$(grep -o -E "function\s+case[0-9-]+" $0 | cut -f2 -d' ' | xargs)"
else
  TEST_CASES="$*"
fi


echo 'Initializing...'
initialize
echo "Executing test cases with $PYTHON_VERSION"
pushd $LOCALDIR > /dev/null
for case in $TEST_CASES
do
  $case
done
popd > /dev/null

echo "Done testing"
if [[ $TEST_FAILED == true ]]; then
    exit 111
fi
