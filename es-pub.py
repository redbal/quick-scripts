from elasticsearch import helpers, Elasticsearch
import csv

es = Elasticsearch(['http://172.16.2.101:9200'])

with open('/tmp/x.csv') as f:
    reader = csv.DictReader(f)
    helpers.bulk(es, reader, index='my-index', doc_type='my-type')
