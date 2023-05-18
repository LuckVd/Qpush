import asyncio
import datetime
import logging
import sqlite3

from obj import vuln_obj

lock = asyncio.Lock()

def conn_db():
    con = sqlite3.connect("cve_db.db")
    cursor = con.cursor()
    return cursor,con


def insertTo(sql):
    cursor,con = conn_db()
    try:
        cursor.execute(sql)
        cursor.close()
        con.commit()
        con.close()
    except Exception as e:
        print(e)


def insertall(results_list):
    cursor,con = conn_db()
    try:
        for results in results_list:
            for result in results:
                if is_not_exist(cursor,result):
                    logging.log(logging.INFO,"insert "+result.name)
                    cursor.execute(result.pr())
        cursor.close()
        con.commit()
        con.close()
    except Exception as e:
        print(e)


def is_not_exist(cursor,one:vuln_obj):

    try:
        if one.cve:
            sql = "select * from vul_info where cve=?"
            cursor.execute(sql,(str(one.cve),))
        elif one.cnvd:
            sql = "select * from vul_info where cnvd=?"
            cursor.execute(sql, (str(one.cnvd),))
        elif one.name:
            sql = "select * from vul_info where name=?"
            cursor.execute(sql, (str(one.name),))
        info = cursor.fetchone()
        if info == None:
            return True
        return False
    except Exception as e:
        error_msg = "[x]ERROR: " + str(e)
        print(error_msg)
        return False