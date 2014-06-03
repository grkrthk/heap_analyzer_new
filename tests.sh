#!/bin/bash

echo ""
echo "Testing the extracted pages from initd image:"

cp initd_full_blocks full_blocks
python2 heap_anal_ptr_anal_updated.py

echo "" > md5s.txt

for FILE_NUMBER in `seq 0 84`; do
  md5sum $FILE_NUMBER.txt >> md5s.txt
done

diff md5s.txt md5s.initd.gold
if [ $? -ne 0 ]
then
  echo "There was an error with the pages from initd, something has gone wrong"
  exit -1
fi 

rm -f *.txt
echo "The pages extracted for initd are good."

echo ""
echo "Testing the extracted pages from rsyslogd image:"

cp rsyslogd_full_blocks full_blocks
python2 heap_anal_ptr_anal_updated.py

echo "" > md5s.txt

for FILE_NUMBER in `seq 0 33`; do
  md5sum $FILE_NUMBER.txt >> md5s.txt
done

diff md5s.txt md5s.rsyslogd.gold
if [ $? -ne 0 ]
then
  echo "There was an error with the pages from rsyslogd, something has gone wrong"
  exit -1
fi 

rm -f *.txt
echo "The pages extracted for rsyslogd are good."

#stuff
