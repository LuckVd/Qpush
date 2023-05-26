import sqlite3

con = sqlite3.connect("cve_db.db")
cursor = con.cursor()

cursor.execute(
    'create table vul_info(name TEXT, url TEXT, danger_level TEXT, type TEXT, cve TEXT, cnvd TEXT, find_time TEXT, release_time TEXT, update_time TEXT, influence TEXT, exp TEXT, poc TEXT, version TEXT, description TEXT, product TEXT, ref TEXT, origin TEXT )')
cursor.close()
con.commit()
con.close()
# import obj
#
# vulobj = obj.vuln_obj()
# vulobj.cnnvd="123"
#
# vulobj.pr()
#
# for attr in vars(vulobj):
#     print(attr)