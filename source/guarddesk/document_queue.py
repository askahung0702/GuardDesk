"""Bounded admission for new copy candidates; never evict existing events.

The ownership ledger and outbox insert commit together. ACKed IDs are pruned
with indexed lookups over at most MAX_PENDING entries, without reading payloads.
Overflow counters persist in the existing state table and a single gap event is
queued when capacity returns. This does not impose a new quota on other events.
"""
import time
MAX_PENDING=4096
MAX_BATCH=64
MAX_BUFFER=256


class CandidateQueue:
    def __init__(self,agent):
        self.agent=agent;self.buffer=[];self.overflow=0;self.initialized=False
        self.report={'status':'idle','pending_limit':MAX_PENDING}
        self.next_check=0
        self.trace_loss=0

    def initialize(self):
        with self.agent.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS document_copy_outbox(event_id TEXT PRIMARY KEY)')
            row=db.execute("SELECT value FROM state WHERE key='document_copy_overflow'").fetchone()
            lost=db.execute("SELECT value FROM state WHERE key='document_trace_loss'").fetchone()
        gap=int(row[0]) if row else 0
        loss=int(lost[0]) if lost else 0
        self.report={'status':'backlog_full' if gap or loss else 'idle','pending_limit':MAX_PENDING,'suppressed_candidates_unreported':gap,'native_loss_counter_unreported':loss}
        self.initialized=True

    def add(self,details,occurred,kind='file.copy_candidate'):
        if kind not in ('file.opened','file.copy_candidate'):raise ValueError('Unsupported document event')
        if len(self.buffer)<MAX_BUFFER:self.buffer.append((details,occurred,kind))
        else:self.overflow+=1

    def trace_gap(self,count):self.trace_loss+=max(0,int(count))

    def flush(self):
        unresolved=self.report.get('suppressed_candidates_unreported') or self.report.get('native_loss_counter_unreported')
        if not self.buffer and not self.overflow and not self.trace_loss and (not unresolved or time.monotonic()<self.next_check):return self.report
        batch=self.buffer[:MAX_BATCH];overflow=self.overflow;trace_loss=self.trace_loss
        with self.agent.db() as db:
            if not self.initialized:
                db.execute('CREATE TABLE IF NOT EXISTS document_copy_outbox(event_id TEXT PRIMARY KEY)')
            db.execute('DELETE FROM document_copy_outbox WHERE NOT EXISTS (SELECT 1 FROM outbox WHERE outbox.event_id=document_copy_outbox.event_id)')
            pending=db.execute('SELECT count(*) FROM document_copy_outbox').fetchone()[0]
            available=max(0,MAX_PENDING-pending)
            row=db.execute("SELECT value FROM state WHERE key='document_copy_overflow'").fetchone()
            lost=db.execute("SELECT value FROM state WHERE key='document_trace_loss'").fetchone()
            gap=int(row[0]) if row else 0
            loss=(int(lost[0]) if lost else 0)+trace_loss
            if (gap or loss) and available:
                event_id=self.agent.queue('agent.audit_gap',{'source':'windows_etw_file_io','reason':'bounded_document_collection','suppressed_candidates':gap,'native_loss_counter_delta':loss},'warning',db=db)
                db.execute('INSERT INTO document_copy_outbox VALUES (?)',(event_id,))
                pending+=1;available-=1
                gap=0;loss=0
            accepted=0
            for details,occurred,kind in batch[:available]:
                event_id=self.agent.queue(kind,details,'info',db=db,occurred=occurred)
                if event_id:
                    db.execute('INSERT INTO document_copy_outbox VALUES (?)',(event_id,));accepted+=1
            gap+=max(0,len(batch)-available)+overflow
            db.execute("INSERT OR REPLACE INTO state VALUES('document_copy_overflow',?)",(str(gap),))
            db.execute("INSERT OR REPLACE INTO state VALUES('document_trace_loss',?)",(str(loss),))
        # Only consume memory after the entire transaction committed. A database
        # failure leaves this bounded batch available for the next attempt.
        self.initialized=True;del self.buffer[:len(batch)];self.overflow-=overflow;self.trace_loss-=trace_loss
        self.next_check=time.monotonic()+5
        self.report={'status':'backlog_full' if gap or loss else 'bounded_queue','pending_document_events':pending+accepted,'suppressed_candidates_unreported':gap,'native_loss_counter_unreported':loss,'pending_limit':MAX_PENDING}
        return self.report
