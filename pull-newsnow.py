#!/usr/bin/env python

import requests
import lxml.html

URL='https://www.newsnow.co.uk/h/Technology/Security'


"""
This simple script will just pull down the latest newsnow.co.uk article
in the Technology/Security section and parse out the Top Stories and
Latest News sections into a string output.

No error checking, not parameter checking...just a quick hack to satisfy
a need.

The hardest part was finding the particular element in the page to parse.

"""

response = requests.get(URL)

if response.status_code == 200:
    doc = lxml.html.fromstring(response.content)
    data = doc.get_element_by_id("pwrap")
    for z in range(0,1):
        b = data.find_class('newsfeed')[z].text_content()
        c = b.encode('utf-8')
        for item in c.splitlines():
            if item.strip():
                print(item.strip())
else:
    print("ERROR")
