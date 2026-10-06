"use client";
import {useEffect,useState} from 'react';
import Shell from '../../components/Shell';
import {api} from '../../lib/api';
import {Loading,ErrorBox} from '../../components/Ui';

export default function Reports(){
 const [ss,setSs]=useState<any[]>(); const [e,setE]=useState(''); const [msg,setMsg]=useState(''); const [busy,setBusy]=useState('');
 useEffect(()=>{api.scans().then(setSs).catch(x=>setE(x.message))},[]);
 async function generate(scanId:string,fmt:string){
   const key=`${scanId}:${fmt}`; setBusy(key); setMsg(`Generating ${fmt.toUpperCase()} report…`); setE('');
   try{
     const queued=await api.generateReport(scanId,fmt);
     for(let i=0;i<30;i++){
       await new Promise(r=>setTimeout(r,2000));
       const result=await api.getReport(scanId,fmt);
       if(result.kind==='json' && result.data.status==='FAILED') throw new Error(result.data.error||'Report generation failed');
       if(result.kind==='blob'){
         const url=URL.createObjectURL(result.blob); const a=document.createElement('a'); a.href=url; a.download=`cybersentinel-${scanId}.${fmt}`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
         setMsg(`${fmt.toUpperCase()} report generated successfully.`); return;
       }
       if(result.kind==='json' && (result.data.status==='COMPLETED' || result.data.security_score || result.data.executive_summary)){
         const blob=new Blob([JSON.stringify(result.data.report??result.data,null,2)],{type:'application/json'}); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=`cybersentinel-${scanId}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); setMsg('JSON report generated successfully.'); return;
       }
     }
     setMsg(`Report queued: ${queued.report_id}. It is still processing; open Reports again to download it.`);
   }catch(err:any){setE(err.message)}finally{setBusy('')}
 }
 return <Shell><div className="space-y-5"><div><div className="text-2xl font-black glow">Reports</div><div className="muted text-sm">Generate and download JSON, CSV, HTML or PDF from completed scans.</div></div>{e&&<ErrorBox error={e}/>} {msg&&<div className="text-[#00ff88] text-sm">{msg}</div>} {!ss?<Loading/>:<div className="space-y-2">{ss.length?ss.map(s=><div className="panel p-4 flex flex-wrap gap-2 justify-between items-center" key={s.id}><div>{s.profile}<div className="muted text-xs">{s.status} · score {s.final_score??'—'}</div></div><div className="flex gap-2">{['json','csv','html','pdf'].map(fmt=><button key={fmt} className="btn" disabled={s.status!=='COMPLETED'||!!busy} onClick={()=>generate(s.id,fmt)}>{busy===`${s.id}:${fmt}`?'…':fmt.toUpperCase()}</button>)}</div></div>):<div className="panel p-8 text-center muted">No scans available for reporting.</div>}</div>}</div></Shell>
}
