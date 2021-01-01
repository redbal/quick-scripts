'''
Picture Files Scanner (PFS)

The purpose of this script is to migrate a collection of pictures into a
sane directory structure, while weeding out duplicates.

This script will take the input of a PATH/dir. It will  traverse it,
collecting the images of file type file_extensions. These image files
are then opened to gather the original date/time it was taken and a hash of the
file is created. These datapoints are collected and stored in a local sqlite3
database for use to create a new directory structure (example):
  YEAR
      /MONTH
            /DAY
            /DAY
      /MONTH
            /DAY

The images can then been copied into the new directory structure.

# Notes for using Postgres
import psycopg2 #postgresql database
sql += VALUES(%s, %s, %s, %s, %s, %s); postgres syntax

'''
import sqlite3 #sqlite database
import argparse
import os
from exif import Image
from filehash import FileHash

FILES_DICT = {}
FILE_EXTENSION = [
    '.jpeg',
    '.jpg',
    '.JPG',
    ]

PARSER = argparse.ArgumentParser()
PARSER.add_argument("path", help="PATH for the images to process", type=str)
ARGS = PARSER.parse_args()

def check_db():
    '''
    Check connection to the datbase
    '''
    #conn = psycopg2.connect(host="postgres", database="postgres", \
        #"user="postgres", password="password")
    conn = sqlite3.connect('images.db')
    print('CONNECTED! %s\n' % conn)
    create_table(conn)
    return conn

def create_table(conn):
    '''
    Create the default entry table
    '''
    conn.execute('''CREATE TABLE IF NOT EXISTS pictures
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  filename text,
                  fullpath varchar,
                  hash varchar,
                  dtg_year text,
                  dtg_month text,
                  dtg_day text,
                  dtg TIMESTAMP DEFAULT CURRENT_TIMESTAMP);''')
    print("Creating entry table")

def insert_record(conn, entry):
    '''
    Insert an entry, aka record, to the database
    '''
    _c = conn.cursor()
    sql = '''INSERT INTO pictures (filename, fullpath, hash, dtg_year, dtg_month, dtg_day)'''
    sql += ''' VALUES(?, ?, ?, ?, ?, ?);'''
    #sql += ''' VALUES(%s, %s, %s, %s, %s, %s);''' postgres syntax
    fname = entry.split('|')[0]
    fpath = entry.split('|')[1]
    fhash = entry.split('|')[2]
    fyear = entry.split('|')[3]
    fmonth = entry.split('|')[4]
    fday = entry.split('|')[5]

    #_c.execute(sql, (fname, fpath, fhash, fyear, fmonth, fday,))
    print("[+] %s\n \t%s | %s | %s | %s | %s | %s" \
        % (sql, fname, fpath, fhash, fyear, fmonth, fday))
    conn.commit()

def get_exif_date(bfile):
    '''
    getExifDate

    Take the input bfile, open the file to extract the image date
    and hash information
    '''
    with open(bfile, 'rb') as _fh:
        
        my_image = Image(_fh)
        try:
            date_taken = my_image.datetime_original
            dtg_full = date_taken.split(':')
        except:
            dtg_full = "2000:01:01"

        dtg_y = dtg_full[0]
        dtg_m = dtg_full[1]
        dtg_d = dtg_full[2].split(' ')[0]
        return(dtg_y, dtg_m, dtg_d)

def get_pic_paths(conn):
    '''
    After scanning the images and inserting into the database, query
    the YEAR MONTH DAY values of all of them and build a dictionary of
    unique YEAR MONTH DAY combinations. These values will be used to
    create the new directory structure for the pictures.
    '''
    if conn is None:
        pass

def scan_files(conn):
    '''
    Scan through the provided directory path for files that match
    the file extensions list.

    If there is a match, attempt to extract the exif data by using
    the host OS command 'exif'.

    '''
    print("scan_files started\n")
    for root, _, files in os.walk(ARGS.path):
        for afile in files:
            print("AFILE %s " % afile)
            md5hasher = FileHash('md5')
            one_hash = md5hasher.hash_file(root + '/' + afile)
            if afile.endswith(tuple(FILE_EXTENSION)):
                dtg_y, dtg_m, dtg_d = get_exif_date((root + '/' + afile))
                dtg = dtg_y + '/' + dtg_m + '/' + dtg_d
                print("FILE: %s HASH: %s DTG: %s" % (afile, one_hash, dtg))
                entry = afile + '|' + root + '|' + one_hash + '|' + dtg_y + '|' \
                    + dtg_m + '|' + dtg_d
                insert_record(conn, entry)
            else:
                print(".", end='')

    print('')

if __name__ == "__main__":
    CONN = check_db()
    scan_files(CONN)
