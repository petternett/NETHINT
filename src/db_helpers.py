#import pymongo

def get_db(db_name):
    db_client = pymongo.MongoClient("mongodb://root:mongopass@192.168.68.25:27017/")
    db = db_client[db_name]

    return db


def insert_pkt(db, col, pkt):
    ins = db[col].insert_one(pkt)
    return ins


def insert_pkts(db, col, pkts):
    ins = db[col].insert_many(pkts)
    return ins
