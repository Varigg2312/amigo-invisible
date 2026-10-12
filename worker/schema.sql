CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS people (
  name TEXT PRIMARY KEY,
  pos INTEGER DEFAULT 0,
  pin_hash TEXT, salt TEXT,
  pub TEXT, wrapped TEXT,
  carta TEXT,
  updated INTEGER DEFAULT 0,
  fails INTEGER DEFAULT 0,
  lock_until INTEGER DEFAULT 0,
  assignment TEXT
);
INSERT OR IGNORE INTO kv(k,v) VALUES ('cfg','{"event":"Amigo Invisible 2026","budget":"20","date":"2026-12-24","missions":true,"excl":[]}');
INSERT OR IGNORE INTO kv(k,v) VALUES ('drawn','0');
INSERT OR IGNORE INTO people(name,pos) VALUES ('Angel',0),('Itziar',1),('Carlos',2),('Miguel',3),('Jesús',4),('Vari',5);
