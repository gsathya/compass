#!/usr/bin/python

import os
import sys

def colored(s,col):
  if col == "red":
    return "\033[31m" + s + "\033[0m"
  elif col == "green":
    return "\033[36m" + s + "\033[0m"
  else:
    return s

def usage():
  sys.stderr.write("Check and see if output matches between two sets of test files\n")
  sys.stderr.write("Usage: check.py <testfile_dir> <test_label_1> <test_label_2> \n")
  sys.exit(-1)
  

def run():

  if len(sys.argv) < 3:
    usage()

  filedir = sys.argv[1]
  a = sys.argv[2]
  b = sys.argv[3]
  a_files = {}
  b_files = {}
  max_test = 0


  files = os.listdir(filedir)

  for f in files:
    if f.split(".")[0] == a:
      a_files[int( f.split(".")[1] )] = f 
    if f.split(".")[0] == b:
      b_files[int(f.split(".")[1])] = f 


    if int(f.split(".")[1]) > max_test:
      max_test = int(f.split('.')[1])

  for i in xrange(1,max_test):
    sys.stdout.write("Testing '{0}.{2}' against '{1}.{2}': ".format(a,b,i))

    try: 
      a_in = open("{0}/{1}".format(filedir,a_files[i])).readlines()
      b_in = open("{0}/{1}".format(filedir,b_files[i])).readlines()
    except IOError,e:
      sys.stdout.write("{0} [{1}]\n".format(colored("Fail","red"),e)) 
    else:
      i = 0
      fail = False
      
      for comp_a,comp_b in zip(a_in,b_in):
        i += 1
        for field_a, field_b in zip(comp_a.split(),comp_b.split()):
          if field_a.lower() != field_b.lower():
            sys.stdout.write("{0} [{1}]\n".format(colored("Fail","red"),"Line {0} doesn't match.".format(i)))
            fail = True
            break

        if fail:
          break

      if not fail:
        sys.stdout.write("{0}\n".format(colored("Pass","green")))


if __name__ == "__main__":
  run()
