#!/bin/bash

# This is intended to run a bunch of options against compass.py and dump
# the output to a file.

if [[ $# -lt 3 ]]; then
  echo "Usage: test.sh <compass_py_loc> <scratch_dir> <test_name>"
  exit 1
fi

scratch="$2"
[[ -d $scratch ]] || echo "'$scratch' is not a directory" || exit 1
[[ -f $1 ]] || echo "'$1' is not a file" || exit 1

name="$3"

i=1

bin="python $1"
declare -a testcases=( 
                      '' 
                      '-i'
                      '-e'
                      '-a 3320'
                      '-a 3320 -i -e -l'
                      '-c US'
                      '-c US -g'
                      '-c US -A'
                      '-g -e'
                      '--almost-fast-exits-only'
                      '--fast-exits-only'
                      '-l'
                      '--almost-fast-exits-only -c DE'
                      '-t 100 -s'
                     )
 
for i in $(seq 0 "${#testcases[@]}"); do 
  $bin ${testcases[$i]} > "$scratch/$name.$i"
done


