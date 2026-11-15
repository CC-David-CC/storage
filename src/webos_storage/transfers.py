"""Durable transfer reservations and backpressure shared by account and service.

Payload bytes are reserved before transfer, including failed/cancelled attempts.
Reservations survive restart; active slots expire rather than resetting quotas.
Rates count application payload bytes, not TLS/IP overhead. A process restart
can restore only one bounded pacing burst, never the persistent daily allowance.
"""
import asyncio
from dataclasses import dataclass
import secrets
import time
from .policy import Denied, integer
from .user_store import registered

class AllowanceExceeded(Denied):
    pass

TABLES = {
    'gateway_transfer_metadata': 'CREATE TABLE gateway_transfer_metadata (version INTEGER PRIMARY KEY CHECK(version=1))',
    'gateway_usage': 'CREATE TABLE gateway_usage (day INTEGER NOT NULL, subject TEXT NOT NULL, bytes INTEGER NOT NULL CHECK(bytes>=0), PRIMARY KEY(day,subject))',
    'gateway_active_uses': 'CREATE TABLE gateway_active_uses (id TEXT PRIMARY KEY, subject TEXT NOT NULL, day INTEGER NOT NULL, reserved INTEGER NOT NULL CHECK(reserved>=0), expires INTEGER NOT NULL)',
}

def check_schema(db):
    if db.execute('SELECT version FROM gateway_transfer_metadata').fetchall() != [(1,)]:
        raise ValueError('Transfer metadata unavailable')
    for name, sql in TABLES.items():
        if db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?', ('table', name)).fetchone() != (sql,):
            raise ValueError('Transfer schema changed; retain state for recovery')

def initialize_transfers(store):
    with store.lock(), store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        existing = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} & TABLES.keys()
        if not existing:
            for sql in TABLES.values():db.execute(sql)
            db.execute('INSERT INTO gateway_transfer_metadata VALUES(1)')
        check_schema(db);db.commit()

@dataclass(frozen=True)
class Transfer:
    id: str
    subject: str
    deadline: int

class Quotas:
    def __init__(self, store, *, daily_bytes=50*1024**3, shared_daily_bytes=200*1024**3,
                 bytes_per_use=192*1024*1024, concurrent_uses=2, shared_concurrent_uses=4):
        self.store=store
        self.daily=integer(daily_bytes,1,1<<40);self.shared=integer(shared_daily_bytes,self.daily,1<<40)
        self.per_use=integer(bytes_per_use,1,1<<30);self.concurrent=integer(concurrent_uses,1,8)
        self.shared_concurrent=integer(shared_concurrent_uses,self.concurrent,32)
        with store.lock(),store.db() as db:check_schema(db)

    def _reserve(self, db, subject, day, amount):
        integer(amount,0,self.per_use)
        for owner,limit in [(subject,self.daily),('*',self.shared)]:
            row=db.execute('SELECT bytes FROM gateway_usage WHERE day=? AND subject=?',(day,owner)).fetchone()
            if (row[0] if row else 0)+amount>limit:raise AllowanceExceeded('Daily transfer allowance reached')
        for owner in [subject,'*']:
            db.execute('INSERT INTO gateway_usage VALUES(?,?,?) ON CONFLICT(day,subject) DO UPDATE SET bytes=bytes+excluded.bytes',(day,owner,amount))

    def begin(self, principal, amount):
        registered(principal);integer(amount,0,self.per_use)
        with self.store.lock(),self.store.db() as db:
            now=int(self.store.clock());day=now//86400
            if principal.deadline<=now:raise Denied('Expired transfer identity')
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM gateway_active_uses WHERE expires<=?',(now,))
            db.execute('DELETE FROM gateway_usage WHERE day<?',(day-7,))
            if db.execute('SELECT count(*) FROM gateway_active_uses').fetchone()[0]>=self.shared_concurrent or db.execute('SELECT count(*) FROM gateway_active_uses WHERE subject=?',(principal.sub,)).fetchone()[0]>=self.concurrent:
                raise AllowanceExceeded('Concurrent transfer allowance reached')
            self._reserve(db,principal.sub,day,amount)
            id=secrets.token_urlsafe(32);db.execute('INSERT INTO gateway_active_uses VALUES(?,?,?,?,?)',(id,principal.sub,day,amount,principal.deadline));db.commit()
        return Transfer(id,principal.sub,principal.deadline)

    def extend(self, transfer, amount):
        integer(amount,0,self.per_use)
        with self.store.lock(),self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT subject,day,reserved,expires FROM gateway_active_uses WHERE id=?',(transfer.id,)).fetchone()
            if row is None or row[0]!=transfer.subject or row[3]<=self.store.clock() or row[2]+amount>self.per_use:
                raise Denied('Expired or oversized transfer')
            self._reserve(db,row[0],row[1],amount)
            db.execute('UPDATE gateway_active_uses SET reserved=reserved+? WHERE id=?',(amount,transfer.id));db.commit()

    def finish(self, transfer):
        with self.store.lock(),self.store.db() as db:
            db.execute('DELETE FROM gateway_active_uses WHERE id=? AND subject=?',(transfer.id,transfer.subject))

class Pacer:
    def __init__(self, *, per_second=4*1024*1024, shared_per_second=8*1024*1024, burst=65536,
                 monotonic=time.monotonic, sleep=asyncio.sleep):
        self.per_second=integer(per_second,1,16*1024*1024)
        self.shared_per_second=integer(shared_per_second,1,64*1024*1024)
        self.burst=integer(burst,1,65536);self.clock=monotonic;self.sleep=sleep
        self.states={};self.lock=asyncio.Lock()

    async def wait(self, subject, amount, deadline):
        integer(amount,0,self.burst)
        while True:
            async with self.lock:
                now=self.clock()
                if now>=deadline:raise TimeoutError('Transfer deadline reached')
                buckets=[]
                for key,rate in [(subject,self.per_second),('*',self.shared_per_second)]:
                    if key not in self.states:
                        if len(self.states)>1024:raise Denied('Pacing capacity reached')
                        self.states[key]=[float(self.burst),now]
                    state=self.states[key];state[0]=min(self.burst,state[0]+max(0,now-state[1])*rate);state[1]=now
                    buckets.append((state,rate))
                delay=max(max(0,(amount-state[0])/rate) for state,rate in buckets)
                if delay<=0:
                    for state,_ in buckets:state[0]-=amount
                    return
                if now+delay>=deadline:raise TimeoutError('Transfer cannot finish within its deadline')
            await self.sleep(delay)
