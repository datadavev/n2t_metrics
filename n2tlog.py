"""This is a simple linear log processor that parses raw logs and stores rows in an sqlite database.

"""

import datetime
import functools
import hashlib
import logging
import os
import re
import sys
import urllib.parse

import apachelogs
import click
import clickhouse_driver
import IP2Location
import sqlite3
import ua_parser.user_agent_parser

# from /apps/n2t/sv/cur/apache2/conf/httpd.conf
ACCESS_LOG_DEFINITION = '%{XFF}e %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"'
ANALYSIS_DIR = "analysis"
ANALYSIS_DB = os.path.join(os.path.abspath(ANALYSIS_DIR), "logs.sqlite3")
GEO_DB = os.path.abspath(os.path.join("geo", "IP2LOCATION-LITE-DB1.BIN"))
LOCAL_HOST = [
    "localhost",
    "127.0.0.1",
]
L = logging.getLogger("n2tlog")


def getRowId(t, ip, id_value):
    h = hashlib.sha1(f'{t}{ip}{id_value}'.encode('utf8'))
    return h.hexdigest()

class LogRecordManager:
    def __init__(self, analysis_db=ANALYSIS_DB):
        os.makedirs(ANALYSIS_DIR, exist_ok=True)
        self.cn = sqlite3.connect(analysis_db)
        self.ipdb = IP2Location.IP2Location(GEO_DB)
        self.parser = apachelogs.LogParser(ACCESS_LOG_DEFINITION)
        # This re is used to match a request to scheme, value
        self.requestre = re.compile("^.*\s/(([a-zA-Z0-9./_]*):(.*))\s.*")

    def close(self):
        self.cn.close()

    @functools.cache
    def to_country(self, ip):
        rec = self.ipdb.get_country_short(ip)
        return rec

    @functools.cache
    def parse_ua(self, ua):
        try:
            return ua_parser.user_agent_parser.Parse(ua)
        except:
            pass
        return {}

    def initialize_database(self):
        sql = """CREATE TABLE IF NOT EXISTS logs(
            id VARCHAR PRIMARY KEY,            
            t DATETIME,
            y INTEGER,
            m INTEGER,
            d INTEGER,
            msec INTEGER,
            client_ip VARCHAR,
            id_scheme VARCHAR,
            id_value VARCHAR,
            country_code VARCHAR,
            browser_family VARCHAR,
            browser_major VARCHAR,
            device_brand VARCHAR,
            device_family VARCHAR,
            device_model VARCHAR,
            os_family VARCHAR,
            os_major VARCHAR
        );"""
        csr = self.cn.cursor()
        csr.execute(sql)
        sql = "CREATE INDEX IF NOT EXISTS logs_year ON logs(y);"
        csr.execute(sql)
        sql = "CREATE INDEX IF NOT EXISTS logs_month ON logs(m);"
        csr.execute(sql)
        sql = "CREATE INDEX IF NOT EXISTS logs_day ON logs(d);"
        csr.execute(sql)
        sql = "CREATE INDEX IF NOT EXISTS logs_scheme ON logs(id_scheme);"
        csr.execute(sql)
        self.cn.commit()

    def addrows(self, rows):
        sql = (
            "INSERT INTO logs("
            "id,"
            "t,y,m,d,msec,"
            "client_ip,"
            "id_scheme,id_value,"
            "country_code,"
            "browser_family,browser_major,"
            "device_brand,device_family,device_model,"
            "os_family,os_major) VALUES ("
            "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        )
        csr = self.cn.cursor()
        try:
            csr.executemany(sql, rows)
            self.cn.commit()
            return
        except sqlite3.IntegrityError as e:
            L.warning(e)
        for row in rows:
            try:
                csr.execute(sql, row)
                self.cn.commit()
            except sqlite3.IntegrityError as e:
                L.warning("Duplicate row for %s", row[1])

    def splitRecord(self, entry) -> list:
        m = self.requestre.search(urllib.parse.unquote_plus(entry.request_line))
        if m is None:
            #L.info("No match for request: %s", entry.request_line)
            return []
        id_scheme = m.group(2).lower().strip("/")
        if ".php" in id_scheme:
            #L.info("Rejecting php match: %s", id_scheme)
            return []
        id_value = m.group(3).strip("/")
        ua = entry.headers_in.get("User-Agent", "")
        uap = self.parse_ua(ua)
        ts = entry.request_time
        msec = ts.microsecond//1000 + ts.second*1000 + ts.minute*60*1000 + ts.hour*60*60*1000
        r = [
            getRowId(entry.request_time, entry.remote_host, id_value),
            entry.request_time,
            entry.request_time.year,
            entry.request_time.month,
            entry.request_time.day,
            msec,
            entry.remote_host,
            id_scheme,
            id_value,
            self.to_country(entry.remote_host),
            uap.get("user_agent", {}).get("family", None),  # browser_family
            uap.get("user_agent", {}).get("major", None),  # browser_major
            uap.get("device", {}).get("brand", None),  # device_brand
            uap.get("device", {}).get("family", None),  # device_family
            uap.get("device", {}).get("model", None),
            uap.get("os", {}).get("family", None),
            uap.get("os", {}).get("major", None),
        ]
        return r

    def oldestLogRecord(self):
        sql = "SELECT MAX(t) FROM logs;"
        csr = self.cn.cursor()
        res = csr.execute(sql).fetchone()
        return datetime.datetime.fromisoformat(res[0])

    def parse(self, inf, max_rows=-1):
        n = 0
        batch_size = 10000
        rows = []
        ids = []
        oldest_entry = self.oldestLogRecord()
        L.info("Oldest record = %s", oldest_entry)
        nparsed = 0
        for entry in self.parser.parse_lines(inf):
            # Redirect and not localhost
            if entry.request_time >= oldest_entry:
                if entry.final_status in [302, 303] and entry.remote_host not in LOCAL_HOST:
                    record = self.splitRecord(entry)
                    if len(record) > 0:
                        if record[0] not in ids:
                            rows.append(record)
                            ids.append(record[0])
                            n += 1
                            if n % batch_size == 0:
                                L.info("Processed %s rows", n)
                                self.addrows(rows)
                                rows = []
                                ids = []
                    if max_rows > 0 and n > max_rows:
                        rows = []
                        break
            nparsed += 1
            if nparsed % batch_size == 0:
                L.info("Parsed %s rows", nparsed)
        if len(rows) > 0:
            self.addrows(rows)
        L.info("Processed %s rows", n)
        L.info("Done.")


def rekeylog(dbsrc, dbdest):
    db0 = sqlite3.connect(dbsrc)
    cur0 = db0.cursor()
    db1 = sqlite3.connect(dbdest)
    cur1 = db1.cursor()
    sqls = "SELECT * FROM logs"
    sqld = (
        "INSERT INTO logs("
        "id,"
        "t,y,m,d,msec,"
        "client_ip,"
        "id_scheme,id_value,"
        "country_code,"
        "browser_family,browser_major,"
        "device_brand,device_family,device_model,"
        "os_family,os_major) VALUES ("
        "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    )
    counter = 0
    rowset = []
    ids = []
    for row in cur0.execute(sqls):
        nrow = [
            getRowId(row[1], row[6], row[8]),
            *row[1:]
        ]
        if nrow[0] not in ids:
            rowset.append(nrow)
            ids.append(nrow[0])
        counter += 1
        if counter % 10000 == 0:
            print(f'{counter} rows processed...')
            try:
                cur1.executemany(sqld, rowset)
                db1.commit()
            except sqlite3.IntegrityError as e:
                L.warning(e)
                for nrow in rowset:
                    try:
                        cur1.execute(sqld, nrow)
                        db1.commit()
                    except sqlite3.IntegrityError as e:
                        L.error(e)
            rowset = []
            ids = []
        #try:
        #    cur1.execute(sqld, nrow)
        #    db1.commit()
        #except sqlite3.IntegrityError as e:
        #    L.warning(e)
    for nrow in rowset:
        try:
            cur1.execute(sqld, nrow)
            db1.commit()
        except sqlite3.IntegrityError as e:
            L.error(e)
    print(f'{counter} rows processed')

def toClickhouse():
    '''Load the sqlite content to clickhouse
    '''
    def vs(v):
        if v is None:
            return ''
        return v

    sdb = sqlite3.connect("analysis/logs.sqlite3")
    cc = clickhouse_driver.Client(host='localhost')
    scsr = sdb.cursor()
    rows = scsr.execute("SELECT * FROM LOGS")
    batch = []
    n = 0
    for row in rows:
        n += 1
        r = {'id':row[0],
             't': datetime.datetime.fromisoformat(row[1]),
             'y': int(row[2]),
             'm': int(row[3]),
             'd': int(row[4]),
             'msec': int(row[5]),
             'client_ip': row[6],
             'id_scheme': vs(row[7]),
             'id_value': vs(row[8]),
             'country_code': vs(row[9]),
             'browser_family': vs(row[10]),
             'browser_major': vs(row[11]),
             'device_brand': vs(row[12]),
             'device_family': vs(row[13]),
             'device_model': vs(row[14]),
             'os_family': vs(row[15]),
             'os_major': vs(row[16])
             }
        batch.append(r)
        if n % 100000 == 0:
            cc.execute(("INSERT INTO n2tlogs.logs ("
                        "id,t,y,m,d,msec,client_ip,id_scheme,id_value,country_code,browser_family,browser_major,"
                        "device_brand,device_family,device_model,os_family,os_major) "
                        "VALUES "
                        ), batch)
            print(f"Inserted {n} rows")
            batch = []
    cc.execute(("INSERT INTO n2tlogs.logs ("
                "id,t,y,m,d,msec,client_ip,id_scheme,id_value,country_code,browser_family,browser_major,"
                "device_brand,device_family,device_model,os_family,os_major) "
                "VALUES "
                ), batch)
    print(f"Inserted {n} rows")
    sdb.close()


def parseLog(fname, dbname, max_rows=-1):
    inf = None
    if fname == "-":
        inf = sys.stdin
    else:
        inf = open(fname, "r")
    try:
        manager = LogRecordManager(dbname)
        manager.initialize_database()
        manager.parse(inf, max_rows=max_rows)
    finally:
        if fname == "-":
            inf.close()

@click.command()
@click.argument("log_file")
@click.option("-d","--database", default=ANALYSIS_DB, help="Name of sqlite database")
@click.option("-m","--max_rows", default=-1, help="Maximum rows to process (default=all)")

def main(log_file, database, max_rows):
    logging.basicConfig(level=logging.INFO)
    parseLog(log_file, database)


if __name__ == "__main__":
    # feed me like: ssh -t n2t-prod "cat /apps/n2t/sv/cv2/apache2/logs/SOME-ACCESS-LOG" | python n2tlog.py -
    main()
    #toClickhouse()
    #dbsrc = './analysis/logs.sqlite3'
    #dbdst = './analysis/logs1.sqlite3'
    #mgr = LogRecordManager(dbdst)
    #mgr.initialize_database()
    #mgr.close()
    #rekeylog(dbsrc,dbdst)
