"use client";
import {useEffect,useState} from 'react';
import Shell from '../../components/Shell';
import {api} from '../../lib/api';
import {Loading,ErrorBox} from '../../components/Ui';

export default function Cloudflare(){
  const [status,setStatus]=useState<any>();
  const [zones,setZones]=useState<any[]>([]);
  const [scans,setScans]=useState<any[]>([]);
  const [scanId,setScanId]=useState('');
  const [selected,setSelected]=useState<any>(); const [events,setEvents]=useState<any>();
  const [form,setForm]=useState({token:'',account_id:'',zone_id:'',label:'Cloudflare'});
  const [error,setError]=useState('');
  const [loading,setLoading]=useState(false);
  useEffect(()=>{
    api.cfStatus().then(setStatus).catch(()=>setStatus({connected:false}));
    api.scans().then(setScans).catch(()=>{});
  },[]);
  async function connect(){setLoading(true);setError('');try{await api.cfConnect(form);setStatus(await api.cfStatus());setZones(await api.cfZones())}catch(e:any){setError(e.message)}finally{setLoading(false)}}
  async function loadZones(){try{setError('');setZones(await api.cfZones())}catch(e:any){setError(e.message)}}
  async function selectZone(zone:any){try{setError('');const sec=await api.cfSecurity(zone.id,scanId||undefined);setSelected({zone,sec});try{setEvents(await api.cfSecurityEvents(zone.id,1))}catch(e:any){setEvents({error:e.message})}}catch(e:any){setError(e.message)}}
  return <Shell><div className="space-y-6">
    <div><div className="text-2xl font-black glow">Cloudflare Security Posture</div><div className="muted text-sm">Read-only assessment using API tokens; secrets never enter the browser after submission.</div></div>
    {error&&<ErrorBox error={error}/>} 
    <div className="panel p-5"><div className="font-bold mb-3">Connection</div><div className="grid md:grid-cols-4 gap-3"><input type="password" placeholder="API token" value={form.token} onChange={e=>setForm({...form,token:e.target.value})}/><input placeholder="Account ID (optional)" value={form.account_id} onChange={e=>setForm({...form,account_id:e.target.value})}/><input placeholder="Zone ID (optional)" value={form.zone_id} onChange={e=>setForm({...form,zone_id:e.target.value})}/><button className="btn btn-primary" disabled={loading} onClick={connect}>{loading?'Testing…':'Test & connect'}</button></div><div className="muted text-xs mt-3">Status: {status?.connected?'CONNECTED':'NOT CONNECTED'}</div></div>
    <div className="panel p-5"><div className="font-bold mb-3">Observed web behavior comparison</div><select value={scanId} onChange={e=>{setScanId(e.target.value);setSelected(undefined)}}><option value="">No scan comparison</option>{scans.filter(x=>x.status==='COMPLETED').map(x=><option value={x.id} key={x.id}>{x.profile} · {x.final_score??'—'}</option>)}</select><div className="muted text-xs mt-2">Selecting a completed scan lets the security endpoint compare observed HTTPS/HSTS evidence with Cloudflare configuration.</div></div>
    <div className="grid lg:grid-cols-2 gap-4"><div className="panel p-5"><div className="font-bold mb-3">Zones</div>{zones.map(x=><button key={x.id} className="block w-full text-left border border-[#17352a] rounded-lg p-3 mb-2" onClick={()=>selectZone(x)}>{x.name} · {x.status}</button>)}<button className="btn mt-2" onClick={loadZones}>{zones.length?'Refresh zones':'Load zones'}</button></div><div className="space-y-4"><Posture selected={selected}/><div className="panel p-5"><div className="font-bold mb-3">Security Events · last hour</div>{events?<pre className="text-xs whitespace-pre-wrap muted overflow-auto max-h-[400px]">{JSON.stringify(events,null,2)}</pre>:<div className="muted text-sm">Select a zone to query Cloudflare GraphQL Security Events.</div>}</div></div></div>
  </div></Shell>
}
function Posture({selected}:{selected:any}){return <div className="panel p-5"><div className="font-bold mb-3">Observed posture</div>{selected?<pre className="text-xs whitespace-pre-wrap muted overflow-auto max-h-[500px]">{JSON.stringify(selected.sec,null,2)}</pre>:<div className="muted text-sm">Select a zone to retrieve DNS, settings, rulesets and any requested scan comparison.</div>}</div>}
