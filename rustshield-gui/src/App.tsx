import { useState, useEffect, useCallback, useRef, CSSProperties } from "react";
const E = "http://127.0.0.1:7878";
const PER = 50;

// ── Types ───────────────────────────────────────────────────────────────
interface Status   { status:string; engine_version:string; uptime_secs:number; watch_paths:string[]; drives:string[]; }
interface Progress  { active:boolean; cancelled:boolean; phase:string; current_file:string; current_root:string; current_root_index:number; total_roots:number; files_scanned:number; threats_found:number; elapsed_secs:number; }
interface Detection{ file_path:string; sha256:string; verdict:string; timestamp:string; }
interface PagedDet { items:Detection[]; total:number; page:number; per_page:number; }
interface ScanRes  { files_scanned:number; threats_found:number; cancelled:boolean; }
interface RepDet   { file_path:string; sha256:string; verdict:string; timestamp:string; }
interface Report   { engine_version:string; scan_path:string; files_scanned:number; threats_found:number; duration_secs:number; cancelled:boolean; detections:RepDet[]; }
interface QItem    { id:number; sha256:string; threat_name:string; original_path:string; quarantine_path:string; quarantined_at:string; }
interface ExcItem  { id:number; sha256?:string; file_path?:string; file_name:string; reason?:string; added_at:string; }
type ScanType = "quick"|"full"|"custom";
type View     = "home"|"scan"|"history"|"quarantine"|"exceptions";

// ── Tokens ──────────────────────────────────────────────────────────────
const C = {
  bg:"#08090e", panel:"#0d0f1a", card:"#111422",
  border:"#1c1f32", line:"#181b2c",
  accent:"#3b6ef8", accentDim:"#12205a",
  green:"#10b981", greenDim:"#061813", greenBd:"#0d3324",
  red:"#ef4444",   redDim:"#160909",   redBd:"#3b1212",
  amber:"#f59e0b", amberDim:"#151005",
  text:"#e8eaf2",  sub:"#7b80a0",      muted:"#3d425e",
};

// ── Icons ────────────────────────────────────────────────────────────────
const Ic = ({d,size=16,color=C.sub,sw=1.6}:{d:string|string[];size?:number;color?:string;sw?:number}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round">
    {(Array.isArray(d)?d:[d]).map((p,i)=><path key={i} d={p}/>)}
  </svg>
);
const I = {
  shieldOk:  ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z","m9 12 2 2 4-4"],
  shieldOff: ["M19.7 14c.2-.6.3-1.3.3-2V5l-8-3-3.2 1.2","M14.7 4.7 19 6v6c0 .8-.1 1.6-.4 2.3","M6 6H5v6c0 6 8 10 8 10 2.3-.9 4.3-2.2 5.8-3.8","m2 2 20 20"],
  shield:    "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  scan:      ["M3 7V5a2 2 0 0 1 2-2h2","M17 3h2a2 2 0 0 1 2 2v2","M21 17v2a2 2 0 0 1-2 2h-2","M7 21H5a2 2 0 0 1-2-2v-2","M9 12h6","M12 9v6"],
  history:   ["M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8","M3 3v5h5","M12 7v5l4 2"],
  lock:      ["M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2z","M7 11V7a5 5 0 0 1 10 0v4"],
  list:      ["M8 6h13","M8 12h13","M8 18h13","M3 6h.01","M3 12h.01","M3 18h.01"],
  check:     "M20 6 9 17l-5-5",
  x:         "M18 6 6 18M6 6l12 12",
  alert:     ["M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z","M12 9v4","M12 17h.01"],
  folder:    "M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z",
  refresh:   ["M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8","M21 3v5h-5","M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16","M8 16H3v5"],
  zap:       "M13 2 3 14h9l-1 8 10-12h-9l1-8z",
  clock:     ["M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z","M12 6v6l4 2"],
  chevDown:  "M6 9l6 6 6-6",
  download:  ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4","M7 10l5 5 5-5","M12 15V3"],
  trash:     ["M3 6h18","M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"],
  undo:      ["M3 7v6h6","M21 17a9 9 0 0 0-9-9 9 9 0 0 0-6 2.3L3 13"],
  plus:      "M12 5v14M5 12h14",
  eye:       ["M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z","M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0"],
  hdd:       ["M22 12H2","M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z","M6 16h.01","M10 16h.01"],
};

// ── Utilities ─────────────────────────────────────────────────────────────
function buildReport(r:Report, started:string, completed:string): string {
  const ln="─".repeat(60), dl="═".repeat(60);
  const p=(s:string,w:number)=>s.padEnd(w), rp=(s:string,w:number)=>s.padStart(w);
  const hdr = [dl,"  RUSTSHIELD SECURITY SCAN REPORT",dl,"",
    `  ${p("Engine:",18)} ${r.engine_version}`,
    `  ${p("Started:",18)} ${started}`,
    `  ${p("Completed:",18)} ${completed}`,
    `  ${p("Target:",18)} ${r.scan_path}`,
    `  ${p("Duration:",18)} ${r.duration_secs.toFixed(1)}s`,
    `  ${p("Status:",18)} ${r.cancelled?"Cancelled by user":"Completed"}`,
    "",ln,"",
    `  ${p("Files scanned:",18)} ${rp(r.files_scanned.toLocaleString(),8)}`,
    `  ${p("Threats found:",18)} ${rp(r.threats_found.toLocaleString(),8)}`,
    `  ${p("Clean files:",18)} ${rp((r.files_scanned-r.threats_found).toLocaleString(),8)}`,
    "",ln,
  ].join("\n");
  const body = r.detections.length===0 ? "\n  No threats detected.\n" :
    "\n  DETECTIONS\n\n"+r.detections.map((d,i)=>{
      const fn2 = d.file_path.split(/[/\\]/).pop()??d.file_path;
      return [`  [${i+1}] ${d.verdict.toUpperCase()}  —  ${fn2}`,
        `      Path   : ${d.file_path}`,`      SHA256 : ${d.sha256}`,
        `      Action : ${d.verdict==="malicious"?"Quarantined automatically":"Flagged for review"}`,
        `      Time   : ${d.timestamp}`].join("\n");
    }).join("\n\n")+"\n";
  return hdr+body+[ln,`  Generated at ${completed}  |  RustShield Final Year Capstone`,dl].join("\n");
}
function dlText(name:string, txt:string) {
  const b=new Blob([txt],{type:"text/plain;charset=utf-8"}),u=URL.createObjectURL(b),a=document.createElement("a");
  a.href=u; a.download=name; a.click(); URL.revokeObjectURL(u);
}

// ── Modal ──────────────────────────────────────────────────────────────────
function Modal({title,body,yesLabel,noLabel,onYes,onNo,onCancel}:{title:string;body:string;yesLabel:string;noLabel:string;onYes:()=>void;onNo:()=>void;onCancel:()=>void}) {
  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,.65)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={onCancel}>
      <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:12,padding:28,maxWidth:420,width:"90%",boxShadow:"0 20px 60px rgba(0,0,0,.5)"}} onClick={e=>e.stopPropagation()}>
        <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:12}}>
          <div style={{width:34,height:34,borderRadius:8,background:`${C.amber}18`,border:`1px solid ${C.amber}30`,display:"flex",alignItems:"center",justifyContent:"center"}}>
            <Ic d={I.alert} size={16} color={C.amber}/>
          </div>
          <div style={{fontSize:15,fontWeight:600}}>{title}</div>
        </div>
        <p style={{fontSize:13,color:C.sub,lineHeight:1.6,marginBottom:22}}>{body}</p>
        <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
          <button onClick={onCancel} style={{padding:"8px 16px",borderRadius:7,border:`1px solid ${C.border}`,background:"transparent",color:C.sub,cursor:"pointer",fontSize:12}}>Cancel</button>
          <button onClick={onNo}    style={{padding:"8px 16px",borderRadius:7,border:`1px solid ${C.border}`,background:C.card,color:C.text,cursor:"pointer",fontSize:12}}>{noLabel}</button>
          <button onClick={onYes}   style={{padding:"8px 16px",borderRadius:7,border:"none",background:C.accent,color:"#fff",cursor:"pointer",fontSize:12,fontWeight:500}}>{yesLabel}</button>
        </div>
      </div>
    </div>
  );
}

// ── Small components ───────────────────────────────────────────────────────
function Toggle({on,onChange}:{on:boolean;onChange:(v:boolean)=>void}) {
  return (
    <button onClick={()=>onChange(!on)} style={{width:40,height:22,borderRadius:11,border:"none",cursor:"pointer",padding:0,background:on?C.green:C.muted,transition:"background .2s",position:"relative"}}>
      <span style={{position:"absolute",top:3,left:on?21:3,width:16,height:16,borderRadius:"50%",background:"#fff",transition:"left .2s"}}/>
    </button>
  );
}
function VBadge({v}:{v:string}) {
  const cfg = v==="malicious"?{bg:C.redDim,bd:C.redBd,c:C.red,i:I.x}
    : v==="suspicious"?{bg:C.amberDim,bd:"#3d2a06",c:C.amber,i:I.alert}
    : {bg:C.greenDim,bd:C.greenBd,c:C.green,i:I.check};
  return (
    <span style={{display:"inline-flex",alignItems:"center",gap:4,fontSize:10,padding:"2px 7px",borderRadius:4,fontWeight:600,background:cfg.bg,border:`1px solid ${cfg.bd}`,color:cfg.c}}>
      <Ic d={cfg.i} size={9} color={cfg.c} sw={2.5}/>{v}
    </span>
  );
}

// ── History table ──────────────────────────────────────────────────────────
function HistTable({items,total,loading,onMore}:{items:Detection[];total:number;loading:boolean;onMore:()=>void}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(()=>{
    const el=ref.current; if(!el) return;
    const obs=new IntersectionObserver(([e])=>{ if(e.isIntersecting&&!loading) onMore(); },{threshold:.1});
    obs.observe(el); return ()=>obs.disconnect();
  },[loading,onMore]);
  const threats = items.filter(d=>d.verdict!=="clean");
  const th:CSSProperties={padding:"9px 16px",textAlign:"left",fontSize:10,color:C.muted,fontWeight:500,letterSpacing:".06em",textTransform:"uppercase",borderBottom:`1px solid ${C.line}`,background:C.panel};
  const td:CSSProperties={padding:"10px 16px",fontSize:12,borderBottom:`1px solid ${C.line}`};
  if(!threats.length&&!loading) return <div style={{textAlign:"center",padding:"60px 0",color:C.muted,fontSize:13}}>No threats detected yet</div>;
  return (
    <div style={{border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
      <table style={{width:"100%",borderCollapse:"collapse"}}>
        <thead><tr>
          <th style={th}>File</th><th style={{...th,width:100}}>Verdict</th>
          <th style={{...th,width:170}}>SHA-256</th><th style={{...th,width:140}}>Detected</th>
        </tr></thead>
        <tbody>{threats.map((d,i)=>(
          <tr key={i} style={{background:i%2===1?"#0c0e18":"transparent"}}>
            <td style={{...td,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:260}} title={d.file_path}>
              <span style={{display:"flex",alignItems:"center",gap:6}}>
                <Ic d={I.alert} size={11} color={d.verdict==="malicious"?C.red:C.amber}/>
                {d.file_path.split(/[/\\]/).pop()??"—"}
              </span>
            </td>
            <td style={td}><VBadge v={d.verdict}/></td>
            <td style={{...td,fontFamily:"monospace",fontSize:10,color:C.muted}}>{d.sha256.slice(0,18)}…</td>
            <td style={{...td,fontSize:11,color:C.muted}}>{new Date(d.timestamp).toLocaleString([],{dateStyle:"short",timeStyle:"short"})}</td>
          </tr>
        ))}</tbody>
      </table>
      <div ref={ref} style={{padding:12,textAlign:"center",color:C.muted,fontSize:12}}>
        {loading&&"Loading…"}
        {!loading&&threats.length<total&&(
          <button onClick={onMore} style={{padding:"6px 16px",borderRadius:6,border:`1px solid ${C.border}`,background:C.card,color:C.sub,cursor:"pointer",fontSize:12,display:"inline-flex",alignItems:"center",gap:6}}>
            <Ic d={I.chevDown} size={12} color={C.sub}/> Load more ({total-threats.length} remaining)
          </button>
        )}
        {!loading&&threats.length>=total&&total>0&&<span>All {total} detection{total!==1?"s":""} loaded</span>}
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────
export default function App() {
  const [view,      setView]      = useState<View>("home");
  const [status,    setStatus]    = useState<Status|null>(null);
  const [offline,   setOffline]   = useState(false);
  const [rtpOn,     setRtpOn]     = useState(true);
  const [showPaths, setShowPaths] = useState(false);

  const [dets,      setDets]      = useState<Detection[]>([]);
  const [detTotal,  setDetTotal]  = useState(0);
  const [detPage,   setDetPage]   = useState(0);
  const [detLoad,   setDetLoad]   = useState(false);

  const [scanType,  setScanType]  = useState<ScanType>("quick");
  const [custPath,  setCustPath]  = useState("C:\\Users\\");
  const [scanning,  setScanning]  = useState(false);
  const [progress,  setProgress]  = useState<Progress|null>(null);
  const [lastRes,   setLastRes]   = useState<ScanRes|null>(null);
  const [lastAt,    setLastAt]    = useState<string|null>(null);
  const [startedAt, setStartedAt] = useState("");
  const [report,    setReport]    = useState<Report|null>(null);

  const [qItems,    setQItems]    = useState<QItem[]>([]);
  const [excItems,  setExcItems]  = useState<ExcItem[]>([]);
  const [modal,     setModal]     = useState<{item:QItem}|null>(null);
  const [toast,     setToast]     = useState<{msg:string;ok:boolean}|null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval>|null>(null);
  const showToast = (msg:string, ok=true) => { setToast({msg,ok}); setTimeout(()=>setToast(null),3500); };

  // drive letters from status
  const drives    = status?.drives??[];
  const watchPaths= status?.watch_paths??[];
  const online    = !offline&&status?.status==="running";
  const malCount  = dets.filter(d=>d.verdict==="malicious").length;
  const suspCount = dets.filter(d=>d.verdict==="suspicious").length;
  const curFile   = progress?.current_file?.split(/[/\\]/).pop()??"";

  // Scan presets — sub-label for "full" is derived inside component where drives is available
  const presets = [
    {id:"quick" as ScanType, label:"Quick scan", sub:watchPaths.length ? `${watchPaths.length} key locations` : "User folders", path:"__QUICK__"},
    {id:"full"  as ScanType, label:"Full scan",  sub: drives.length ? drives.join(", ") : "All detected drives", path:"__FULL__"},
    {id:"custom"as ScanType, label:"Custom",     sub:"Choose a folder",       path:""},
  ];

  // ── Fetchers ─────────────────────────────────────────────────────────────
  const fetchStatus = useCallback(async()=>{
    try{ const r=await fetch(`${E}/status`); setStatus(await r.json()); setOffline(false); }
    catch{ setOffline(true); }
  },[]);

  const fetchDetsPage = useCallback(async(page:number, append=false)=>{
    setDetLoad(true);
    try{
      const r=await fetch(`${E}/detections?page=${page}&per_page=${PER}`);
      const d:PagedDet=await r.json();
      setDets(p=>append?[...p,...d.items]:d.items); setDetTotal(d.total); setDetPage(page);
    }catch{}finally{ setDetLoad(false); }
  },[]);

  const fetchQuarantine = useCallback(async()=>{
    try{ const r=await fetch(`${E}/quarantine`); setQItems(await r.json()); }catch{}
  },[]);

  const fetchExceptions = useCallback(async()=>{
    try{ const r=await fetch(`${E}/exceptions`); setExcItems(await r.json()); }catch{}
  },[]);

  useEffect(()=>{
    fetchStatus(); fetchDetsPage(0); fetchQuarantine(); fetchExceptions();
    const a=setInterval(fetchStatus,5000);
    const b=setInterval(()=>fetchDetsPage(0),15000);
    return()=>{ clearInterval(a); clearInterval(b); };
  },[fetchStatus,fetchDetsPage,fetchQuarantine,fetchExceptions]);

  const loadMore = useCallback(()=>{
    if(!detLoad&&dets.filter(d=>d.verdict!=="clean").length<detTotal) fetchDetsPage(detPage+1,true);
  },[detLoad,dets,detTotal,detPage,fetchDetsPage]);

  // ── Scan ──────────────────────────────────────────────────────────────────
  const startPoll = () => {
    if(pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async()=>{
      try{
        const r=await fetch(`${E}/scan/progress`); const p:Progress=await r.json(); setProgress(p);
        if(!p.active){ clearInterval(pollRef.current!); pollRef.current=null; }
      }catch{}
    },300);
  };

  const handleScan = async() => {
    const preset = presets.find(p=>p.id===scanType)!;
    const path   = scanType==="custom" ? custPath : preset.path;
    const s = new Date().toLocaleString();
    setStartedAt(s); setScanning(true); setProgress(null); setLastRes(null); setReport(null);
    startPoll();
    try{
      const r=await fetch(`${E}/scan`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path})});
      const res:ScanRes=await r.json(); setLastRes(res);
      const c=new Date().toLocaleString(); setLastAt(c);
      const rr=await fetch(`${E}/scan/report`); const rep:Report|null=await rr.json(); setReport(rep);
      fetchDetsPage(0); fetchQuarantine();
    }catch{}
    finally{ setScanning(false); }
  };

  const handleCancel = async() => {
    try{ await fetch(`${E}/scan/cancel`,{method:"POST"}); }catch{}
    if(pollRef.current){ clearInterval(pollRef.current); pollRef.current=null; }
    setScanning(false);
  };

  // ── Quarantine & exceptions ───────────────────────────────────────────────
  const handleRestore = async(item:QItem, addException:boolean) => {
    setModal(null);
    try{
      const r=await fetch(`${E}/quarantine/restore`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:item.id,add_exception:addException})});
      const res=await r.json();
      if(res.success){ showToast(`Restored: ${item.original_path.split(/[/\\]/).pop()}`); if(addException) showToast("Added to exceptions"); fetchQuarantine(); fetchExceptions(); }
      else showToast(`Restore failed: ${res.message}`,false);
    }catch{ showToast("Restore failed",false); }
  };

  const handleAddException = async(item:QItem) => {
    const fname=item.original_path.split(/[/\\]/).pop()??"";
    try{
      await fetch(`${E}/exceptions`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({sha256:item.sha256,file_path:item.original_path,file_name:fname,reason:"Added manually by user"})});
      showToast("Added to exceptions"); fetchExceptions();
    }catch{ showToast("Failed to add exception",false); }
  };

  const handleRemoveException = async(id:number) => {
    try{ await fetch(`${E}/exceptions/${id}`,{method:"DELETE"}); fetchExceptions(); showToast("Exception removed"); }
    catch{ showToast("Failed to remove exception",false); }
  };

  // ── Table cell styles ─────────────────────────────────────────────────────
  const hdrSt:CSSProperties = {padding:"9px 16px",textAlign:"left",fontSize:10,color:C.muted,fontWeight:500,letterSpacing:".06em",textTransform:"uppercase",borderBottom:`1px solid ${C.line}`,background:C.panel};
  const cellSt:CSSProperties= {padding:"10px 16px",fontSize:12,borderBottom:`1px solid ${C.line}`};

  // ── Nav ───────────────────────────────────────────────────────────────────
  const nav = [
    {id:"home"       as View, label:"Home",      d:I.shield,  badge:undefined as number|undefined},
    {id:"scan"       as View, label:"Scan",      d:I.scan,    badge:undefined},
    {id:"history"    as View, label:"History",   d:I.history, badge:detTotal||undefined},
    {id:"quarantine" as View, label:"Quarantine",d:I.lock,    badge:qItems.length||undefined},
    {id:"exceptions" as View, label:"Exceptions",d:I.list,    badge:excItems.length||undefined},
  ];

  return (
    <div style={{display:"flex",height:"100vh",background:C.bg,color:C.text,fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",fontSize:14}}>

      {/* Modal */}
      {modal&&<Modal
        title="Restore quarantined file"
        body={`"${modal.item.original_path.split(/[/\\]/).pop()}" was quarantined as "${modal.item.threat_name}". Would you also like to add it to exceptions so it won't be flagged again?`}
        yesLabel="Restore + add exception"
        noLabel="Just restore"
        onYes={()=>handleRestore(modal.item,true)}
        onNo={()=>handleRestore(modal.item,false)}
        onCancel={()=>setModal(null)}
      />}

      {/* Toast */}
      {toast&&(
        <div style={{position:"fixed",bottom:24,right:24,zIndex:999,padding:"10px 18px",borderRadius:8,fontSize:13,fontWeight:500,background:toast.ok?C.greenDim:C.redDim,border:`1px solid ${toast.ok?C.greenBd:C.redBd}`,color:toast.ok?C.green:C.red,boxShadow:"0 8px 24px rgba(0,0,0,.4)"}}>
          {toast.msg}
        </div>
      )}

      {/* ── Sidebar ── */}
      <aside style={{width:210,background:C.panel,borderRight:`1px solid ${C.border}`,display:"flex",flexDirection:"column",flexShrink:0}}>
        <div style={{padding:"20px 18px 16px",borderBottom:`1px solid ${C.line}`}}>
          <div style={{display:"flex",alignItems:"center",gap:10,marginBottom:10}}>
            <div style={{width:32,height:32,borderRadius:8,background:`linear-gradient(135deg,${C.accent},#1e4fd9)`,display:"flex",alignItems:"center",justifyContent:"center"}}>
              <Ic d={I.shield} size={16} color="#fff" sw={2}/>
            </div>
            <div>
              <div style={{fontWeight:600,fontSize:14}}>RustShield</div>
              {status&&<div style={{fontSize:10,color:C.muted}}>v{status.engine_version}</div>}
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11}}>
            <span style={{width:6,height:6,borderRadius:"50%",background:online?C.green:C.red,boxShadow:`0 0 6px ${online?C.green:C.red}`}}/>
            <span style={{color:online?C.green:C.red}}>{online?"Engine running":"Offline"}</span>
          </div>
        </div>

        <nav style={{flex:1,padding:"8px 8px",overflowY:"auto"}}>
          {nav.map(n=>{const a=view===n.id; return(
            <button key={n.id} onClick={()=>setView(n.id)} style={{display:"flex",alignItems:"center",gap:9,width:"100%",padding:"9px 11px",border:"none",cursor:"pointer",borderRadius:7,marginBottom:2,fontSize:13,fontWeight:a?500:400,background:a?`${C.accent}18`:"transparent",color:a?C.accent:C.sub}}>
              <Ic d={n.d} size={14} color={a?C.accent:C.sub} sw={a?2:1.6}/>
              {n.label}
              {n.badge&&n.badge>0&&<span style={{marginLeft:"auto",fontSize:10,background:`${C.accent}22`,color:C.accent,padding:"1px 6px",borderRadius:10}}>{n.badge}</span>}
            </button>
          );})}
        </nav>

        <div style={{padding:"12px 18px",borderTop:`1px solid ${C.line}`,fontSize:10,color:C.muted,lineHeight:1.7}}>
          Final Year Capstone<br/><span style={{color:`${C.accent}80`}}>Rust · YARA-X · Tauri v2</span>
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{flex:1,overflowY:"auto",padding:"28px 32px"}}>

        {/* HOME */}
        {view==="home"&&(
          <div style={{display:"flex",flexDirection:"column",gap:14}}>
            {/* Status banner */}
            <div style={{padding:"20px 24px",borderRadius:12,background:online&&rtpOn?C.greenDim:C.redDim,border:`1px solid ${online&&rtpOn?C.greenBd:C.redBd}`,display:"flex",alignItems:"center",gap:16}}>
              <div style={{width:44,height:44,borderRadius:10,background:`${online&&rtpOn?C.green:C.red}18`,border:`1px solid ${online&&rtpOn?C.greenBd:C.redBd}`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                <Ic d={online&&rtpOn?I.shieldOk:I.shieldOff} size={22} color={online&&rtpOn?C.green:C.red} sw={1.6}/>
              </div>
              <div style={{flex:1}}>
                <div style={{fontSize:16,fontWeight:600,color:online&&rtpOn?C.green:C.red,marginBottom:2}}>
                  {online&&rtpOn?"Your device is protected":!online?"Engine is offline":"Real-time protection paused"}
                </div>
                <div style={{fontSize:12,color:C.sub}}>
                  {online&&rtpOn?`Monitoring ${watchPaths.length} system location${watchPaths.length!==1?"s":""} · hash + YARA-X + PE heuristics`:!online?"Run: cd rustshield && cargo run":"Enable real-time protection below"}
                </div>
              </div>
              <button onClick={()=>setView("scan")} style={{padding:"8px 18px",borderRadius:7,border:"none",background:C.accent,color:"#fff",cursor:"pointer",fontSize:12,fontWeight:500,flexShrink:0}}>Scan now</button>
            </div>

            {/* Cards */}
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
              {/* RTP card */}
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:18}}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8}}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}><Ic d={I.zap} size={14} color={rtpOn?C.accent:C.muted}/><span style={{fontSize:13,fontWeight:500}}>Real-time protection</span></div>
                  <Toggle on={rtpOn} onChange={setRtpOn}/>
                </div>
                {watchPaths.length>0?(
                  <div>
                    <div style={{fontSize:11,color:C.sub,marginBottom:6}}>Monitoring {watchPaths.length} location{watchPaths.length!==1?"s":""}</div>
                    <button onClick={()=>setShowPaths(p=>!p)} style={{display:"flex",alignItems:"center",gap:4,fontSize:10,color:C.accent,background:"none",border:"none",cursor:"pointer",padding:0}}>
                      <Ic d={I.eye} size={11} color={C.accent}/>{showPaths?"Hide paths":"Show paths"}
                    </button>
                    {showPaths&&(
                      <div style={{marginTop:8,borderRadius:6,background:C.bg,border:`1px solid ${C.border}`,padding:"6px 10px",maxHeight:120,overflowY:"auto"}}>
                        {watchPaths.map((p,i)=><div key={i} style={{fontSize:10,color:C.muted,fontFamily:"monospace",padding:"2px 0",borderBottom:i<watchPaths.length-1?`1px solid ${C.line}`:"none"}}>{p}</div>)}
                      </div>
                    )}
                  </div>
                ):(
                  <div style={{fontSize:11,color:C.muted}}>{rtpOn?"No watchable paths found":"Monitoring paused"}</div>
                )}
              </div>

              {/* Last scan card */}
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:18}}>
                <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}><Ic d={I.clock} size={14} color={C.muted}/><span style={{fontSize:13,fontWeight:500}}>Last scan</span></div>
                {lastRes?(
                  <>
                    <div style={{fontSize:12,fontWeight:500,color:lastRes.cancelled?C.amber:lastRes.threats_found>0?C.red:C.green,marginBottom:2}}>
                      {lastRes.cancelled?`Cancelled — ${lastRes.threats_found} threat(s) found`:lastRes.threats_found>0?`${lastRes.threats_found} threat(s) found`:"No threats found"}
                    </div>
                    <div style={{fontSize:11,color:C.sub,marginBottom:10}}>{lastAt} · {lastRes.files_scanned.toLocaleString()} files</div>
                    {report&&<button onClick={()=>dlText(`rustshield-${Date.now()}.txt`,buildReport(report,startedAt,lastAt??""))} style={{display:"flex",alignItems:"center",gap:6,padding:"6px 12px",borderRadius:6,border:`1px solid ${C.border}`,background:C.bg,color:C.sub,cursor:"pointer",fontSize:11}}>
                      <Ic d={I.download} size={12} color={C.sub}/> Download report
                    </button>}
                  </>
                ):(
                  <div style={{fontSize:11,color:C.sub}}>No scan run yet</div>
                )}
              </div>
            </div>

            {/* Stats */}
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12}}>
              {[{l:"Total detections",v:detTotal,c:C.accent},{l:"Malicious quarantined",v:malCount,c:C.red},{l:"Suspicious flagged",v:suspCount,c:C.amber}].map(s=>(
                <div key={s.l} style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:"16px 18px"}}>
                  <div style={{fontSize:28,fontWeight:700,color:s.c}}>{s.v}</div>
                  <div style={{fontSize:11,color:C.sub,marginTop:3}}>{s.l}</div>
                </div>
              ))}
            </div>

            {/* Recent threats */}
            {dets.filter(d=>d.verdict!=="clean").slice(0,3).length>0&&(
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10}}>
                <div style={{padding:"12px 16px",borderBottom:`1px solid ${C.line}`,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                  <span style={{fontSize:12,fontWeight:500}}>Recent threats</span>
                  <button onClick={()=>setView("history")} style={{fontSize:11,color:C.accent,background:"none",border:"none",cursor:"pointer"}}>See all</button>
                </div>
                {dets.filter(d=>d.verdict!=="clean").slice(0,3).map((d,i,a)=>(
                  <div key={i} style={{padding:"10px 16px",borderBottom:i<a.length-1?`1px solid ${C.line}`:"none",display:"flex",alignItems:"center",gap:12}}>
                    <Ic d={I.alert} size={12} color={d.verdict==="malicious"?C.red:C.amber}/>
                    <span style={{flex:1,fontSize:12,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{d.file_path.split(/[/\\]/).pop()}</span>
                    <VBadge v={d.verdict}/>
                    <span style={{fontSize:10,color:C.muted,minWidth:80,textAlign:"right"}}>{new Date(d.timestamp).toLocaleDateString()}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* SCAN */}
        {view==="scan"&&(
          <div style={{display:"flex",flexDirection:"column",gap:14,maxWidth:580}}>
            <div>
              <h1 style={{fontSize:18,fontWeight:600,marginBottom:3}}>Scan</h1>
              <p style={{fontSize:12,color:C.sub}}>SHA-256 signatures → YARA-X rules → PE structural heuristics</p>
            </div>

            {!scanning&&(
              <>
                {/* Scan type selector */}
                <div style={{display:"flex",gap:8}}>
                  {presets.map(p=>{const sel=scanType===p.id; return(
                    <button key={p.id} onClick={()=>setScanType(p.id)} style={{flex:1,padding:"12px 8px",borderRadius:8,cursor:"pointer",background:sel?`${C.accent}18`:C.card,border:`1px solid ${sel?C.accent:C.border}`,textAlign:"center"}}>
                      <div style={{fontSize:12,fontWeight:500,color:sel?C.accent:C.text}}>{p.label}</div>
                      <div style={{fontSize:10,color:C.muted,marginTop:2}}>{p.sub}</div>
                    </button>
                  );})}
                </div>

                {scanType==="custom"&&(
                  <div style={{position:"relative"}}>
                    <div style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)"}}>
                      <Ic d={I.folder} size={13} color={C.muted}/>
                    </div>
                    <input value={custPath} onChange={e=>setCustPath(e.target.value)} style={{width:"100%",padding:"10px 14px 10px 32px",background:C.card,border:`1px solid ${C.border}`,borderRadius:7,color:C.text,fontSize:12,outline:"none",fontFamily:"monospace"}}/>
                  </div>
                )}

                <button onClick={handleScan} disabled={offline} style={{padding:"11px",borderRadius:8,border:"none",background:offline?C.muted:C.accent,color:"#fff",cursor:offline?"not-allowed":"pointer",fontSize:13,fontWeight:500,display:"flex",alignItems:"center",justifyContent:"center",gap:8}}>
                  <Ic d={I.scan} size={14} color="#fff"/>{offline?"Engine offline":"Start scan"}
                </button>
              </>
            )}

            {/* Live progress */}
            {scanning&&(
              <div style={{background:C.card,border:`1px solid ${C.border}`,borderRadius:10,padding:24}}>
                {/* Sweep bar */}
                <div style={{height:2,borderRadius:1,background:C.border,marginBottom:20,overflow:"hidden"}}>
                  <div style={{height:"100%",background:`linear-gradient(90deg,${C.accent},#6b9cff,${C.accent})`,backgroundSize:"200%",animation:"sweep 1.2s linear infinite"}}/>
                </div>

                {/* Location/drive tiles — shown for multi-root scans in dirs phase */}
                {progress&&progress.total_roots>1&&progress.phase!=="processes"&&(
                  <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:6,marginBottom:16,flexWrap:"wrap",maxWidth:480,margin:"0 auto 16px"}}>
                    {Array.from({length:progress.total_roots},(_,i)=>{
                      const done = i < progress.current_root_index-1;
                      const curr = i === progress.current_root_index-1;
                      // For full scan use drive letter; for quick scan use short folder name
                      const getLabel = (): string => {
                        if (scanType === "full") return drives[i]?.charAt(0) ?? String(i+1);
                        const path = watchPaths[i] ?? "";
                        const last = path.replace(/\\/g,"/").split("/").filter(Boolean).pop() ?? "";
                        const MAP: Record<string,string> = {
                          Downloads:"DL", Desktop:"Dsk", Documents:"Doc",
                          Temp:"Tmp", Startup:"Run", ProgramData:"Sys", Public:"Pub", Startup2:"Str",
                        };
                        return MAP[last] ?? last.slice(0,3).toUpperCase() || String(i+1);
                      };
                      return (
                        <div key={i} title={watchPaths[i]??drives[i]??""} style={{width:34,height:34,borderRadius:7,fontSize:10,fontWeight:600,display:"flex",alignItems:"center",justifyContent:"center",background:done?`${C.accent}25`:curr?C.accent:`${C.muted}18`,color:done?C.accent:curr?"#fff":C.muted,border:`1px solid ${curr?C.accent:done?`${C.accent}40`:C.border}`,cursor:"default"}}>
                          {getLabel()}
                        </div>
                      );
                    })}
                    <span style={{fontSize:11,color:C.sub,marginLeft:4}}>
                      {scanType==="full"?"Drive":"Location"} {progress.current_root_index}/{progress.total_roots}
                    </span>
                  </div>
                )}

                {/* Process scan phase indicator */}
                {progress&&progress.phase==="processes"&&(
                  <div style={{textAlign:"center",marginBottom:14,padding:"8px 16px",borderRadius:8,background:`${C.accent}12`,border:`1px solid ${C.accentDim}`}}>
                    <div style={{fontSize:12,color:C.accent,fontWeight:500,marginBottom:3}}>
                      Scanning running processes
                    </div>
                    <div style={{fontSize:10,color:C.muted}}>{progress.current_root}</div>
                  </div>
                )}

                {/* Counter */}
                <div style={{textAlign:"center",marginBottom:14}}>
                  <div style={{fontSize:40,fontWeight:700,color:C.accent,lineHeight:1}}>{(progress?.files_scanned??0).toLocaleString()}</div>
                  <div style={{fontSize:11,color:C.sub,marginTop:4}}>files scanned</div>
                </div>

                {/* Current file */}
                {curFile&&<div style={{fontSize:11,color:C.muted,textAlign:"center",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",padding:"0 8px"}}>{curFile}</div>}

                {/* Threats found counter */}
                {progress&&progress.threats_found>0&&(
                  <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:6,marginTop:12,fontSize:12,color:C.red,fontWeight:500}}>
                    <Ic d={I.alert} size={13} color={C.red}/>{progress.threats_found} threat{progress.threats_found!==1?"s":""} detected
                  </div>
                )}

                {/* Elapsed time */}
                {(progress?.elapsed_secs??0)>0&&(
                  <div style={{textAlign:"center",fontSize:10,color:C.muted,marginTop:8}}>{progress!.elapsed_secs}s elapsed</div>
                )}

                {/* Cancel button */}
                <div style={{textAlign:"center",marginTop:18}}>
                  <button onClick={handleCancel} style={{display:"inline-flex",alignItems:"center",gap:6,padding:"7px 20px",borderRadius:7,border:`1px solid ${C.redBd}`,background:C.redDim,color:C.red,cursor:"pointer",fontSize:12,fontWeight:500}}>
                    <Ic d={I.x} size={12} color={C.red} sw={2.5}/> Cancel scan
                  </button>
                </div>
              </div>
            )}

            {/* Result */}
            {lastRes&&!scanning&&(
              <div style={{padding:"16px 18px",borderRadius:8,background:lastRes.cancelled?C.amberDim:lastRes.threats_found>0?C.redDim:C.greenDim,border:`1px solid ${lastRes.cancelled?"#3d2a06":lastRes.threats_found>0?C.redBd:C.greenBd}`}}>
                <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:report?12:0}}>
                  <Ic d={lastRes.cancelled?I.alert:lastRes.threats_found>0?I.alert:I.shieldOk} size={20} color={lastRes.cancelled?C.amber:lastRes.threats_found>0?C.red:C.green}/>
                  <div>
                    <div style={{fontWeight:500,fontSize:13,color:lastRes.cancelled?C.amber:lastRes.threats_found>0?C.red:C.green}}>
                      {lastRes.cancelled?`Scan cancelled — ${lastRes.threats_found} threat(s) found`:lastRes.threats_found>0?`${lastRes.threats_found} threat(s) found and quarantined`:"Scan complete — no threats found"}
                    </div>
                    <div style={{fontSize:11,color:C.sub,marginTop:2}}>{lastRes.files_scanned.toLocaleString()} files · {report?.duration_secs.toFixed(1)}s</div>
                  </div>
                </div>
                {report&&<button onClick={()=>dlText(`rustshield-${Date.now()}.txt`,buildReport(report,startedAt,lastAt??""))} style={{display:"flex",alignItems:"center",gap:7,padding:"8px 14px",borderRadius:6,cursor:"pointer",background:`${C.accent}18`,border:`1px solid ${C.accentDim}`,color:C.accent,fontSize:12,fontWeight:500}}>
                  <Ic d={I.download} size={13} color={C.accent}/> Download scan report (.txt)
                </button>}
              </div>
            )}
          </div>
        )}

        {/* HISTORY */}
        {view==="history"&&(
          <>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
              <div>
                <h1 style={{fontSize:18,fontWeight:600,marginBottom:3}}>Threat history {detTotal>0&&<span style={{fontSize:13,fontWeight:400,color:C.sub}}>{detTotal} total</span>}</h1>
                <p style={{fontSize:12,color:C.sub}}>Malicious = quarantined · Suspicious = flagged for review</p>
              </div>
              <div style={{display:"flex",gap:8}}>
                {report&&<button onClick={()=>dlText(`rustshield-${Date.now()}.txt`,buildReport(report,startedAt,lastAt??""))} style={{display:"flex",alignItems:"center",gap:6,padding:"7px 13px",background:`${C.accent}18`,border:`1px solid ${C.accentDim}`,color:C.accent,borderRadius:7,cursor:"pointer",fontSize:12}}>
                  <Ic d={I.download} size={12} color={C.accent}/> Report
                </button>}
                <button onClick={()=>fetchDetsPage(0)} style={{display:"flex",alignItems:"center",gap:6,padding:"7px 13px",background:C.card,border:`1px solid ${C.border}`,color:C.sub,borderRadius:7,cursor:"pointer",fontSize:12}}>
                  <Ic d={I.refresh} size={12} color={C.sub}/> Refresh
                </button>
              </div>
            </div>
            <HistTable items={dets} total={detTotal} loading={detLoad} onMore={loadMore}/>
          </>
        )}

        {/* QUARANTINE */}
        {view==="quarantine"&&(
          <>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
              <div>
                <h1 style={{fontSize:18,fontWeight:600,marginBottom:3}}>Quarantine {qItems.length>0&&<span style={{fontSize:13,fontWeight:400,color:C.sub}}>{qItems.length} file{qItems.length!==1?"s":""}</span>}</h1>
                <p style={{fontSize:12,color:C.sub}}>Isolated malicious files — restore to move back to original location</p>
              </div>
              <button onClick={fetchQuarantine} style={{display:"flex",alignItems:"center",gap:6,padding:"7px 13px",background:C.card,border:`1px solid ${C.border}`,color:C.sub,borderRadius:7,cursor:"pointer",fontSize:12}}>
                <Ic d={I.refresh} size={12} color={C.sub}/> Refresh
              </button>
            </div>
            {qItems.length===0?(
              <div style={{textAlign:"center",padding:"60px 0",color:C.muted,fontSize:13}}>
                <Ic d={I.lock} size={28} color={C.muted}/><div style={{marginTop:10}}>Quarantine is empty</div>
              </div>
            ):(
              <div style={{border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
                <table style={{width:"100%",borderCollapse:"collapse"}}>
                  <thead><tr>
                    <th style={hdrSt}>File</th>
                    <th style={{...hdrSt,width:160}}>Threat</th>
                    <th style={{...hdrSt,width:130}}>Quarantined</th>
                    <th style={{...hdrSt,width:200}}>Actions</th>
                  </tr></thead>
                  <tbody>{qItems.map((item,i)=>(
                    <tr key={item.id} style={{background:i%2===1?"#0c0e18":"transparent"}}>
                      <td style={{...cellSt,maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}} title={item.original_path}>
                        <div style={{fontSize:12,fontWeight:500}}>{item.original_path.split(/[/\\]/).pop()}</div>
                        <div style={{fontSize:10,color:C.muted,marginTop:2,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{item.original_path}</div>
                      </td>
                      <td style={cellSt}><span style={{fontSize:11,padding:"2px 8px",borderRadius:4,background:C.redDim,border:`1px solid ${C.redBd}`,color:C.red}}>{item.threat_name}</span></td>
                      <td style={{...cellSt,fontSize:11,color:C.muted}}>{new Date(item.quarantined_at).toLocaleString([],{dateStyle:"short",timeStyle:"short"})}</td>
                      <td style={cellSt}>
                        <div style={{display:"flex",gap:6}}>
                          <button onClick={()=>setModal({item})} style={{display:"flex",alignItems:"center",gap:5,padding:"5px 10px",borderRadius:6,border:`1px solid ${C.border}`,background:C.card,color:C.text,cursor:"pointer",fontSize:11}}>
                            <Ic d={I.undo} size={12} color={C.sub}/> Restore
                          </button>
                          <button onClick={()=>handleAddException(item)} style={{display:"flex",alignItems:"center",gap:5,padding:"5px 10px",borderRadius:6,border:`1px solid ${C.accentDim}`,background:`${C.accent}10`,color:C.accent,cursor:"pointer",fontSize:11}}>
                            <Ic d={I.plus} size={12} color={C.accent}/> Exception
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* EXCEPTIONS */}
        {view==="exceptions"&&(
          <>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:20}}>
              <div>
                <h1 style={{fontSize:18,fontWeight:600,marginBottom:3}}>Exceptions {excItems.length>0&&<span style={{fontSize:13,fontWeight:400,color:C.sub}}>{excItems.length} rule{excItems.length!==1?"s":""}</span>}</h1>
                <p style={{fontSize:12,color:C.sub}}>Files and hashes in this list are skipped by all detection layers</p>
              </div>
              <button onClick={fetchExceptions} style={{display:"flex",alignItems:"center",gap:6,padding:"7px 13px",background:C.card,border:`1px solid ${C.border}`,color:C.sub,borderRadius:7,cursor:"pointer",fontSize:12}}>
                <Ic d={I.refresh} size={12} color={C.sub}/> Refresh
              </button>
            </div>
            {excItems.length===0?(
              <div style={{textAlign:"center",padding:"60px 0",color:C.muted,fontSize:13}}>
                <Ic d={I.list} size={28} color={C.muted}/><div style={{marginTop:10}}>No exceptions — all files are scanned</div>
              </div>
            ):(
              <div style={{border:`1px solid ${C.border}`,borderRadius:10,overflow:"hidden"}}>
                <table style={{width:"100%",borderCollapse:"collapse"}}>
                  <thead><tr>
                    <th style={hdrSt}>File / path</th>
                    <th style={{...hdrSt,width:160}}>SHA-256</th>
                    <th style={{...hdrSt,width:180}}>Reason</th>
                    <th style={{...hdrSt,width:100}}>Added</th>
                    <th style={{...hdrSt,width:80}}></th>
                  </tr></thead>
                  <tbody>{excItems.map((ex,i)=>(
                    <tr key={ex.id} style={{background:i%2===1?"#0c0e18":"transparent"}}>
                      <td style={cellSt}>
                        <div style={{fontSize:12,fontWeight:500}}>{ex.file_name}</div>
                        {ex.file_path&&<div style={{fontSize:10,color:C.muted,marginTop:2,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",maxWidth:220}}>{ex.file_path}</div>}
                      </td>
                      <td style={{...cellSt,fontFamily:"monospace",fontSize:10,color:C.muted}}>{ex.sha256?ex.sha256.slice(0,16)+"…":"—"}</td>
                      <td style={{...cellSt,fontSize:11,color:C.sub}}>{ex.reason??"—"}</td>
                      <td style={{...cellSt,fontSize:11,color:C.muted}}>{new Date(ex.added_at).toLocaleDateString()}</td>
                      <td style={cellSt}>
                        <button onClick={()=>handleRemoveException(ex.id)} style={{display:"flex",alignItems:"center",gap:4,padding:"4px 8px",borderRadius:5,border:`1px solid ${C.redBd}`,background:C.redDim,color:C.red,cursor:"pointer",fontSize:10}}>
                          <Ic d={I.trash} size={11} color={C.red}/> Remove
                        </button>
                      </td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            )}
          </>
        )}
      </main>

      <style>{`
        *{box-sizing:border-box;}
        button{transition:filter .15s;}
        button:hover:not(:disabled){filter:brightness(1.1);}
        input:focus{border-color:${C.accent}!important;outline:none;}
        ::-webkit-scrollbar{width:4px;}
        ::-webkit-scrollbar-thumb{background:${C.border};border-radius:2px;}
        @keyframes sweep{0%{background-position:200% 0}100%{background-position:-200% 0}}
      `}</style>
    </div>
  );
}
