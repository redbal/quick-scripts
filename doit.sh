#!/bin/bash
SOURCE="/home/credd/Desktop/101MEDIA/"
DEST="/home/credd/Desktop/DEST/"

function path_exists()
{
  if [ -d $1 ]
  then
    #mkdir -p $1
    return 0
  else
    return 1 
  fi
}

for i in $(ls -t $SOURCE)
do PICDATE=$(identify -format %[EXIF:DateTimeOriginal]n $SOURCE$i | cut -d' ' -f1 | cut -d':' -f1,2,3 --output-delimiter='-')
sha1sum $SOURCE$i | cut -d' ' -f1
if [ $(path_exists $PICDATE) ]
then
  echo "$DEST$PICDATE exists"
else
  echo "Making $DEST$PICDATE"
fi

done


#ssh -i .ssh/id_rsa2 -D 8080 -q -C -N tommyboy@10.1.1.1 -p 44522
