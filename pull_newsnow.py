#!/usr/bin/env python

"""
This simple script will just pull down the latest newsnow.co.uk article
in the Technology/Security section and parse out the Top Stories and
Latest News sections into a string output.

No error checking, not parameter checking...just a quick hack to satisfy
a need.



The hardest part was finding the particular element in the page to parse.
"""

import requests
import lxml.html

URL = 'https://www.newsnow.co.uk/h/Technology/Security'
RESP = requests.get(URL)


if RESP.status_code == 200:
    DOC = lxml.html.fromstring(RESP.content)
    DATA = DOC.get_element_by_id("pwrap")
    for z in range(0, 1):
        b = DATA.find_class('newsfeed')[z].text_content()
        c = b.encode('utf-8')
        for item in c.splitlines():
            if item.strip():
                print(item.strip())
else:
    print("ERROR")
