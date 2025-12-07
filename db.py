import sqlite3
import uuid

PEER_FIELDS = {'id', 'nickname', 'address', 'pubkey', 'privkey', 'sharedkey', 'expiration'}

class ChatDB:
    def __init__(self, db_name="chat.db"):
        self.db_name = db_name
        self.conn = None
        self.cursor = None
        self.connect()
        self.create_tables()

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            print(f"Errore di connessione al database: {e}")

    def close(self):
        if self.conn:
            self.cursor.close()
            self.conn.close()  

    ### --- TABLES --- ###

    def create_tables(self):
        # Creazione della tabella 'peers' (utenti)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS peers (
                id TEXT UNIQUE PRIMARY KEY,
                nickname TEXT UNIQUE,
                address TEXT UNIQUE,
                pubkey BYTES,
                privkey BYTES,
                sharedkey BYTES,
                expiration INTEGER,
                FOREIGN KEY (nickname) REFERENCES peers (nickname),
                FOREIGN KEY (address) REFERENCES peers (address)
            );
        """)
        self.conn.commit()

        # Creazione della tabella 'chats' (messaggi)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                dest_id TEXT NOT NULL,
                message BYTES NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES peers (id),
                FOREIGN KEY (dest_id) REFERENCES peers (id)
            );
        """)
        self.conn.commit()

        # Creazione della tabella 'pending' (messaggi)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending (
                dest_id TEXT NOT NULL,
                message BYTES NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (dest_id) REFERENCES peers (id)
            );
        """)
        self.conn.commit()

        # Creazione della tabella 'handshakes' (handshakes)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS handshakes (
                key_id TEXT PRIMARY KEY UNIQUE,
                primarykey BYTES NOT NULL,
                expiration INTEGER NOT NULL
            );
        """)
        self.conn.commit()

    ### --- PEERS --- ###

    def get_peers(self):
        self.cursor.execute("SELECT id, nickname, address FROM peers")
        return self.cursor.fetchall()
    
    def get_peer(self, selector: str = 'id', selector_value = '', return_fields: set = {'id', 'nickname', 'address', 'pubkey', 'privkey', 'sharedkey', 'expiration'}):
        if selector not in PEER_FIELDS or not return_fields.issubset(PEER_FIELDS):
            return None
        fields_str = ", ".join(return_fields)
        self.cursor.execute(f"SELECT {fields_str} FROM peers WHERE {selector} = ?", (selector_value,))
        return self.cursor.fetchone()

    def set_peer(self, nickname, peer_address, peer_pubkey, privkey, sharedkey, expiration):
        try:
            self.cursor.execute("INSERT INTO peers (nickname, address, pubkey, privkey, sharedkey, expiration) VALUES (?, ?, ?, ?, ?, ?)",
                                (nickname, peer_address, peer_pubkey, privkey, sharedkey, expiration))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            print(f"Error: peer '{nickname}' already exists.")
            return False
        
    def update_peer(self, selector: str = 'id', selector_value = '', fields: set = {'id', 'nickname', 'address', 'pubkey', 'privkey', 'sharedkey', 'expiration'}, values: tuple = ()):
        if selector not in PEER_FIELDS or not fields.issubset(PEER_FIELDS):
            return False
        fields_str = " = ?, ".join(fields)
        self.cursor.execute(f"UPDATE peers SET {fields_str} = ? WHERE {selector} = ?",
                                                    (*values, selector_value))
        self.conn.commit()

        if self.cursor.rowcount == 0:
            return False
        else:
            return True

    def del_peer(self, selector: str = 'id', selector_value=None):
        if selector not in PEER_FIELDS:
            return False
        self.cursor.execute(f"DELETE FROM peers WHERE {selector} = ?", (selector_value,))
        self.conn.commit()
        return self.cursor.rowcount > 0
    
    ### --- CHATS --- ###

    def get_chat(self, peer_id):
        self.cursor.execute("""
            SELECT T1.nickname AS source_nickname, T2.nickname AS dest_nickname, C.message, C.timestamp
            FROM chats AS C
            JOIN peers AS T1 ON C.source_id = T1.id
            JOIN peers AS T2 ON C.dest_id = T2.id
            WHERE C.source_id = ? OR C.dest_id = ?
            ORDER BY C.timestamp ASC;
        """, (peer_id, peer_id))
        return self.cursor.fetchall()

    def update_chat(self, source_id, dest_id, message, timestamp):
        self.cursor.execute("""
            INSERT INTO chats (source_id, dest_id, message, timestamp) 
            VALUES (?, ?, ?, ?);
        """, (source_id, dest_id, message, timestamp))
        self.conn.commit()
        return True

    def delete_chat(self, peer_id):
        # Per eliminare l'intera conversazione con un peer specifico
        self.cursor.execute("""
            DELETE FROM chats
            WHERE source_id = ? OR dest_id = ?;
        """, (peer_id, peer_id))
        self.conn.commit()
        return self.cursor.rowcount > 0

    ### --- PENDING --- ###

    def set_pending(self, dest_id, message, timestamp):
        self.cursor.execute("INSERT INTO pending (dest_id, message, timestamp) VALUES (?, ?, ?)",
                            (dest_id, message, timestamp))
        self.conn.commit()
        return True

    def get_pending(self):
        self.cursor.execute("SELECT * FROM pending")
        return self.cursor.fetchall()
    
    ### --- HANDSHAKES --- ###

    def set_primary_key(self, key_id, address, primarykey, expiration):
        try:
            self.cursor.execute("INSERT INTO handshakes (key_id, address, primarykey, expiration) VALUES (?, ?, ?, ?)",
                                (key_id, address, primarykey, expiration))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            print(f"Error: handshake with key_id '{key_id}' already exists.")
            return False

    def get_primary_key(self, key_id):
        self.cursor.execute("SELECT primarykey, expiration FROM handshakes WHERE key_id = ?", (key_id,))

    def delete_primary_key(self, key_id):
        self.cursor.execute("DELETE FROM handshakes WHERE key_id = ?", (key_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0