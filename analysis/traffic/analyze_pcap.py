"""SecureX PCAP summary and deterministic abnormal-traffic rules.
Run: python analyze_pcap.py capture.pcap [--packet-rate 200] [--burst-bytes 500000]
"""
import argparse, collections, json, time
try:
    import pyshark
except ImportError:
    raise SystemExit('Install first: pip install pyshark')
p=argparse.ArgumentParser();p.add_argument('pcap');p.add_argument('--packet-rate',type=int,default=200);p.add_argument('--burst-bytes',type=int,default=500000);a=p.parse_args()
t=time.perf_counter();cap=pyshark.FileCapture(a.pcap,keep_packets=False);packets=[]
for x in cap:
    try:
        ts=float(x.sniff_timestamp); packets.append({'time':ts,'source':x.ip.src if hasattr(x,'ip') else 'n/a','destination':x.ip.dst if hasattr(x,'ip') else 'n/a','protocol':x.highest_layer,'bytes':int(x.length),'source_port':getattr(getattr(x,'tcp',None),'srcport',getattr(getattr(x,'udp',None),'srcport','')),'destination_port':getattr(getattr(x,'tcp',None),'dstport',getattr(getattr(x,'udp',None),'dstport',''))})
    except (AttributeError,ValueError): pass
cap.close();seconds=max((packets[-1]['time']-packets[0]['time']) if len(packets)>1 else 1,1);volume=sum(x['bytes'] for x in packets);by_second=collections.Counter(int(x['time']) for x in packets);flags=[]
if max(by_second.values(),default=0)>a.packet_rate: flags.append(f'Packet-rate rule: {max(by_second.values())}/s exceeds {a.packet_rate}/s')
if volume/seconds>a.burst_bytes: flags.append(f'Traffic burst rule: {volume/seconds:.0f} B/s exceeds {a.burst_bytes} B/s')
print(json.dumps({'status':'ABNORMAL / FLAGGED' if flags else 'NORMAL','rules_triggered':flags,'packet_count':len(packets),'traffic_volume_bytes':volume,'duration_seconds':seconds,'protocols':collections.Counter(x['protocol'] for x in packets),'processing_ms':round((time.perf_counter()-t)*1000,2),'packets':packets[:200]},indent=2,default=dict))
