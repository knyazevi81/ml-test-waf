import datetime
import sqlite3
import pandas as pd
import json
import os
from Request.Request import Request


class DBController(object):
    def __init__(self):
        self.conn = sqlite3.connect("../logs/traffics.db")
        self.conn.row_factory = sqlite3.Row
    
    def save(self, obj: Request) -> None:
        if not isinstance(obj, Request):
            raise TypeError("Object should be a WAF.Request.Request!!!")
        
        # Save the request to the database
        cursor = self.conn.cursor()
        obj.timestamp = datetime.datetime.now()
        cursor.execute("INSERT INTO logs (timestamp, origin, host, request, method, body, headers) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (obj.timestamp, obj.origin, obj.host, obj.request, obj.method, obj.body, json.dumps(obj.headers)))
        obj.id = cursor.lastrowid
        # Save the whole request to a json file for later review
        file_name = str(obj.id) + '.json'
        file_path = os.path.join('../logs/requests', file_name)
        with open(file_path, 'w') as f:
            json.dump(json.loads(obj.to_json()), f)
        # Save the threat type
        for threat, location in obj.threats.items():
            cursor.execute("INSERT INTO threats (log_id, threat_type, location) VALUES (?, ?, ?)", (obj.id, threat, location))
        self.conn.commit()

    def __create_entry(self, row) -> dict:
        # Create a dictionary from the row for the DataFrame
        entry = dict(row)
        entry['Link'] = '[Review](http://127.0.0.1:8050/review/'+str(entry['id'])+')'
        return entry

    def read_all(self) -> pd.DataFrame:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id")
        results = cursor.fetchall()
        data = [self.__create_entry(row) for row in results]
        return pd.DataFrame(data)

    def __create_single_entry(self, row) -> list:
        return [row['threat_type'], row['location']]

    def read_request(self, id: str) -> tuple:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs AS l JOIN threats AS t ON l.id = t.log_id WHERE l.id = ?", (id,))
        results = cursor.fetchall()
        log = dict()
        if len(results) != 0:
            log['timestamp'] = results[0]['timestamp']
            log['origin'] = results[0]['origin']
            log['host'] = results[0]['host']
            log['request'] = results[0]['request']
            log['method'] = results[0]['method']
        data = [self.__create_single_entry(row) for row in results]
        return log, data

    def close(self):
        self.conn.close()
