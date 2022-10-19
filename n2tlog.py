import functools
import logging
import os
import re
import sys
import urllib.parse

import apachelogs
import click
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


class LogRecordManager:
    def __init__(self, analysis_db=ANALYSIS_DB):
        os.makedirs(ANALYSIS_DIR, exist_ok=True)
        self.cn = sqlite3.connect(analysis_db)
        self.ipdb = IP2Location.IP2Location(GEO_DB)
        self.parser = apachelogs.LogParser(ACCESS_LOG_DEFINITION)
        # This re is used to match a request to scheme, value
        self.requestre = re.compile("^.*\s/(([a-zA-Z0-9./_]*):(.*))\s.*")

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
            id BIGINT PRIMARY KEY,
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
            "t,y,m,d,msec,"
            "client_ip,"
            "id_scheme,id_value,"
            "country_code,"
            "browser_family,browser_major,"
            "device_brand,device_family,device_model,"
            "os_family,os_major) VALUES ("
            "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
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
            L.info("No match for request: %s", entry.request_line)
            return []
        id_scheme = m.group(2).lower().strip("/")
        if ".php" in id_scheme:
            L.info("Rejecting php match: %s", id_scheme)
            return []
        id_value = m.group(3).strip("/")
        ua = entry.headers_in.get("User-Agent", "")
        uap = self.parse_ua(ua)
        ts = entry.request_time
        msec = ts.microsecond//1000 + ts.second*1000 + ts.minute*60*1000 + ts.hour*60*60*1000
        r = [
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

    def parse(self, inf, max_rows=-1):
        n = 0
        batch_size = 100000
        rows = []
        for entry in self.parser.parse_lines(inf):
            # Redirect and not localhost
            if entry.final_status == 302 and entry.remote_host not in LOCAL_HOST:
                n += 1
                record = self.splitRecord(entry)
                if len(record) > 0:
                    rows.append(record)
                if n % batch_size == 0:
                    L.info("Processed %s rows", n)
                    self.addrows(rows)
                    rows = []
                if max_rows > 0 and n > max_rows:
                    rows = []
                    break
        self.addrows(rows)
        L.info("Processed %s rows", n)
        L.info("Done.")


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
