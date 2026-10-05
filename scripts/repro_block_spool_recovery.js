'use strict';

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const Module = require('module');

const EXPECTED = 'bb6d5214f2f5de3b7464587cc1b2949d221dcd18';
const root = path.resolve(process.argv[2] || 'wam-coin');
const out = path.resolve(process.argv[3] || 'security-reports/block-spool-recovery-finding.json');
const head = cp.execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], {encoding:'utf8'}).trim();
if (head !== EXPECTED) throw new Error(`expected ${EXPECTED}, got ${head}`);

const origLoad = Module._load;
Module._load = function(req, parent, isMain) {
  if (req === '../native' || req === './native' || /[\\/]native$/.test(req)) {
    return {hash: async()=>Buffer.alloc(32,0xff), configure:()=>({}), selfTest:()=> 'mock', seedForHeight:()=>Buffer.alloc(32)};
  }
  return origLoad(req, parent, isMain);
};

const JobManager = require(path.join(root, 'pool/lib/jobManager'));
const ShareProcessor = require(path.join(root, 'pool/lib/shareProcessor'));
const quiet = {info(){},warn(){},error(){},debug(){}};

class Redis {
  constructor(){ this.h=new Map(); this.l=new Map(); this.s=new Map(); }
  hash(k){ if(!this.h.has(k)) this.h.set(k,new Map()); return this.h.get(k); }
  async hset(k,f,v){ this.hash(k).set(String(f),String(v)); return 1; }
  async hget(k,f){ return this.hash(k).get(String(f)) ?? null; }
  async hgetall(k){ return Object.fromEntries(this.hash(k)); }
  async lrange(k,a,b){ const x=this.l.get(k)||[]; return x.slice(a,b<0?undefined:b+1); }
  async del(k){ this.h.delete(k); this.l.delete(k); this.s.delete(k); return 1; }
  pipeline(){
    const ops=[], self=this;
    return {
      hset(...a){ops.push(['hset',a]);return this;},
      del(...a){ops.push(['del',a]);return this;},
      incrby(k,n){ops.push(['incrby',[k,n]]);return this;},
      async exec(){
        for(const [op,a] of ops){
          if(op==='hset') await self.hset(...a);
          else if(op==='del') await self.del(...a);
          else if(op==='incrby'){ const [k,n]=a; self.s.set(k,String(Number(self.s.get(k)||0)+Number(n))); }
        }
        return ops.map(()=>[null,1]);
      }
    };
  }
}

function spool(entry){
  const live=new Map([[entry.hash,entry]]);
  return {
    live,
    store:{
      async put(h,e){live.set(h,e);},
      async remove(h){live.delete(h);},
      async all(){return [...live.values()];}
    }
  };
}

function sp(redis){
  const x=new ShareProcessor(redis,{},{
    redisPrefix:'wam', rewardMode:'pplns', pplnsMultiplier:2,
    startDifficulty:1000, poolFeePercent:1
  },quiet);
  x.setNetworkDifficulty(0.0039);
  return x;
}

async function acceptedCase(){
  const redis=new Redis();
  const p=sp(redis);
  const e={height:20001,hash:'11'.repeat(32),hex:'deadbeef',worker:'alice',foundAt:Date.now()-1000};
  const q=spool(e);
  const jm=new JobManager({submitBlock:async()=>({accepted:true,reasons:[],results:[{ok:true,error:null,result:null}]})},{},quiet);
  jm._spoolStore=q.store;
  const seen=[]; let rec=Promise.resolve(null);
  jm.on('block', x=>{seen.push(x);rec=p.recordBlock(x);});
  const drain=await jm.drainSpool();
  const recordResult=await rec;
  const failedRaw=await redis.hget('wam:blocks:failed',e.hash);
  const pendingRaw=await redis.hget('wam:blocks:pending',e.hash);
  const failed=failedRaw?JSON.parse(failedRaw):null;
  const ev=seen[0]||null;
  const reproduced=drain.settled===1 && q.live.size===0 && seen.length===1 &&
    ev && ev.distributableValue===undefined && ev.coinbaseValue===undefined &&
    ev.devFeeAmount===undefined && recordResult===null && pendingRaw===null &&
    failed && /blockValue.*undefined/.test(String(failed.error||''));
  return {id:'accepted-after-restart',reproduced,observed:{
    settled:drain.settled,spoolRemoved:q.live.size===0,blockEvents:seen.length,
    emittedKeys:ev?Object.keys(ev).sort():[],pendingRecordCreated:pendingRaw!==null,
    failedRecordCreated:!!failed,failedError:failed?failed.error:null
  }};
}

async function duplicateCase(){
  const e={height:20002,hash:'22'.repeat(32),hex:'cafebabe',worker:'bob',foundAt:Date.now()-1000};
  const q=spool(e);
  const jm=new JobManager({submitBlock:async()=>({
    accepted:false,reasons:['mock: duplicate'],
    results:[{ok:true,error:null,result:'duplicate'}]
  })},{},quiet);
  jm._spoolStore=q.store;
  const seen=[]; jm.on('block',x=>seen.push(x));
  const drain=await jm.drainSpool();
  const reproduced=drain.settled===1 && q.live.size===0 && seen.length===0;
  return {id:'duplicate-after-restart',reproduced,observed:{
    settled:drain.settled,spoolRemoved:q.live.size===0,blockEvents:seen.length
  }};
}

(async()=>{
  const a=await acceptedCase();
  const b=await duplicateCase();
  const report={
    schema:'wam-security-block-spool-recovery-repro/v1',
    target:{repository:'wamcoin-core-dev/wam-coin',expectedCommit:EXPECTED,observedCommit:head},
    cases:[a,b],
    result:a.reproduced&&b.reproduced?'REPRODUCED':'NOT_REPRODUCED'
  };
  fs.mkdirSync(path.dirname(out),{recursive:true});
  fs.writeFileSync(out,JSON.stringify(report,null,2)+'\n');
  console.log(JSON.stringify(report,null,2));
  process.exit(report.result==='REPRODUCED'?0:1);
})().catch(e=>{console.error(e.stack||e.message);process.exit(2);});
