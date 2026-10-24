"""Saved manager semantic audit extracted from the preserved independent auditor.

The original helper functions are loaded from audit_manager.py. The function body
below retains the graph/event semantic suffix unchanged. Historical source/runtime
pin and bytecode provenance checks before that suffix are deliberately not run.
"""
def audit_saved_manager():
 p=read(EXP/'PLAN.json')
 sup=read(EXP/'run02/SUPERVISOR.json')
 r=read(EXP/'run02/output/RESULT.json')
 events=read_jsonl(EXP/'run02/output/EVENTS.jsonl')
 caches=[]
 oldplan=read(P58/'PLAN.json');graphs={k:read(v['path']) for k,v in oldplan['graphs'].items()};nodes={k:{n['id']:n for n in g['nodes']} for k,g in graphs.items()}
 model_checks={k:bit_table_model(oldplan['graphs'][k]) for k in ['native','normalized']}
 old=closure(graphs['native'],['0','1'],True)
 for route in ['source','saved_native']:
  cert=r['fresh_old_gate'][route];need(all(cert[k]==old[k] is True for k in ['complete','source_coverage','source_safety','strict','cooperative']),'fresh old gate independently passes '+route)
 need(len(old['nodes'])==50 and len(old['edges'])==238,'old initialized closure has 50 nodes / 238 legal edges')
 need(len(events)==r['event_count']==69 and [e['seq'] for e in events]==list(range(69)) and all(e['pid']==sup['pid']==r['pid'] for e in events),'69 sequential events bind one worker PID')
 need(all(a['monotonic_ns']<b['monotonic_ns'] for a,b in zip(events,events[1:])),'event timestamps strictly monotonic')
 need([e['boundary_id'] for e in r['episodes']]==p['boundary_order'],'all three frozen boundaries executed in declared order')
 results=[];ids=[]
 for episode,boundary in zip(r['episodes'],oldplan['boundaries']):
  bid=boundary['id'];ev=[e for e in events if e['runtime']['boundary_id']==bid];before=episode['before'];ids.append((before['plant_identity'],before['state_object_identity']))
  prefix=len(boundary['prefix_node_ids'])-1
  want=['episode_boot']+['step_committed']*prefix+['boundary_paused_and_environment_changed']+['candidate_attempt_begin','candidate_attempt_decision']*2+['controller_installed','resumed']+['step_committed']*12+['manager_episode_completed']
  need([e['event'] for e in ev]==want,bid+' exact sequential attempt/install/continuation event order')
  need(all(e['runtime']['plant_identity']==ids[-1][0] and e['runtime']['state_object_identity']==ids[-1][1] for e in ev),bid+' same runtime and same state object throughout')
  boot=ev[0]['runtime'];need(boot['ticks']==0 and boot['controller']['node_id']=='0' and boot['controller']['rank']==0 and boot['contract_mode']=='old_no_b1' and boot['source_state']=={k:nodes['native']['0']['valuation'][k] for k in FIELDS},bid+' exact old initialized boot')
  for i,e in enumerate(ev):
   snap=e['runtime'];state=snap['source_state'];ctrl=snap['controller'];gn=ctrl['graph'];node=nodes[gn][ctrl['node_id']]
   assert state=={k:node['valuation'][k] for k in FIELDS} and ctrl['rank']==node['rank'] and ctrl['original_initial_flag']==node['initial']
   assert ctrl['graph_sha256']==oldplan['graphs'][gn]['sha256']
   if e['event']=='step_committed':
    prior=e['before'];assert prior==ev[i-1]['runtime'];src=nodes[gn][prior['controller']['node_id']]
    assert ctrl['instance_identity']==prior['controller']['instance_identity'] and ctrl['node_id'] in src['successors']
    assert e['offered_env']=={k:state[k] for k in ENV} and envok(prior['source_state'],state,prior['contract_mode']=='old_no_b1') and sysok(prior['source_state'],state)
    assert snap['ticks']==prior['ticks']+1 and not prior['paused'] and snap['epoch']==prior['epoch'] and snap['contract_mode']==prior['contract_mode']
  need(True,bid+' every committed transition independently satisfies exact graph edge, rank, ENV/SYS and monitor update')
  need([e['runtime']['controller']['node_id'] for e in ev[:prefix+1]]==boundary['prefix_node_ids'],bid+' actually executed frozen old prefix')
  pause=ev[prefix+1];need(pause['runtime']==before and before['source_state']==boundary['source_state'] and pause['before']==ev[prefix]['runtime'] and before['source_state']==pause['before']['source_state'],bid+' model change preserves full ten-field reached state')
  need(before['paused'] and before['epoch']==1 and before['contract_mode']=='normal' and before['source_state'][AUX[2]]=='S1' and before['source_state']['f3']=='false' and before['source_state']['c']=='false',bid+' genuinely unanswered m3 retained while paused')
  attempts=episode['attempts'];need([a['candidate'] for a in attempts]==p['candidate_order'][:2] and [a['decision'] for a in attempts]==['WITHHOLD_NONCOOPERATIVE','PASS'],bid+' fixed priority WITHHOLD then first PASS')
  closure_rows=[]
  for j,a in enumerate(attempts):
   desc=boundary['candidates'][j];assert all(a[k]==desc[k] for k in ['candidate','graph','root','rank'])
   ce=closure(graphs[a['graph']],[a['root']],False);closure_rows.append({k:v for k,v in ce.items() if k not in ['nodes','edges']})
   for route in ['source_certificate','saved_native_certificate']:
    cert=a[route];assert all(cert[k]==ce[k] for k in ['complete','source_coverage','source_safety','strict','cooperative'])
    assert (cert['reachable_state_count'],cert['reachable_edge_count'])==(len(ce['nodes']),len(ce['edges'])) if route=='source_certificate' else (cert['reachable_node_count'],cert['edge_count'])==(len(ce['nodes']),len(ce['edges']))
   assert a['source_certificate']['reachable_nodes']==ce['nodes']
   assert a['source_certificate']['derived_edges_sha256']==hashlib.sha256(json.dumps(sorted(ce['edges']),sort_keys=True,separators=(',',':')).encode()).hexdigest()
   assert a['before']==a['after']==before and a['post_update_commits_before_selection']==0
   begins=ev[prefix+2+2*j];decision=ev[prefix+3+2*j];assert begins['runtime']==decision['runtime']==before and decision['attempt']==a
   assert nodes[a['graph']][a['root']]['rank']==a['rank'] and {k:nodes[a['graph']][a['root']]['valuation'][k] for k in FIELDS}==before['source_state']
   phases=[t['stage'] for t in r['timings'] if t.get('boundary')==bid and t.get('candidate')==a['candidate']]
   assert phases==['fresh_source_correspondence_and_exact_root','fresh_source_complete_graph','fresh_saved_native_complete_graph','paused_candidate_complete_check']
  need(True,bid+' both fresh graph checks independently rederived, exact roots and paused state preserved')
  need(episode['unattempted']==[dict(candidate='saved_preference',reason='NOT_ATTEMPTED_AFTER_FIRST_PASS')] and episode['selected_candidate']=='saved_normalized',bid+' later preference not attempted after first complete PASS')
  install=ev[prefix+6];resume=ev[prefix+7];assert install['event']=='controller_installed' and resume['event']=='resumed'
  assert install['before']==before and install['runtime']['source_state']==before['source_state'] and install['runtime']['ticks']==before['ticks'] and install['runtime']['paused']
  assert install['runtime']['controller']['instance_identity']!=before['controller']['instance_identity']
  normalized=dict(install['runtime']);normalized['paused']=False;assert resume['runtime']==normalized==episode['install_snapshot']==episode['trail'][0]
  assert install['certified_root']['root_id']==boundary['candidates'][1]['root'] and install['certified_root']['rank']==boundary['candidates'][1]['rank']
  commits=[e for e in ev if e['event']=='step_committed' and e['phase']=='frozen_twelve_input_continuation']
  assert [e['runtime'] for e in commits]==episode['trail'][1:] and len(commits)==12 and episode['post_update_commits']==12
  bits=[''.join('1' if e['offered_env'][k]=='true' else '0' for k in ENV) for e in commits];assert bits==p['workloads'][bid]
  assert episode['offered_inputs']==[e['offered_env'] for e in commits]
  trail=episode['trail'];states=[x['source_state'] for x in trail];last=states[-1]
  metrics=dict(old_m3_response_step=next((i for i,s in enumerate(states[1:],1) if s['f3']=='true' and s['c']=='false'),None),old_m3_clear_step=next((i for i,s in enumerate(states[1:],1) if s[AUX[2]]=='S0'),None),final_genuinely_pending=[i+1 for i,a in enumerate(AUX) if last[a]=='S1' and last[FLOORS[i]]=='false' and last['c']=='false'],cancel_used=any(s['c']=='true' for s in states),executed_self_loop=trail[-1]['controller']['node_id']==trail[-2]['controller']['node_id'] and states[-1]==states[-2])
  metrics['fair_self_loop']=metrics['executed_self_loop'] and all(last[a]=='S0' for a in AUX)
  need(metrics==episode['observations'] and metrics['old_m3_response_step']==1 and metrics['old_m3_clear_step']==2 and metrics['fair_self_loop'] and not metrics['cancel_used'] and not metrics['final_genuinely_pending'],bid+' twelve frozen commits respond/clear at 1/2 and end in repeatable fair self-loop')
  assert episode['final']==trail[-1]==ev[-1]['runtime'] and episode['status']=='EXECUTED_FAIR_SELF_LOOP'
  results.append(dict(boundary=bid,closures=closure_rows,observations=metrics,post_update_commits=12))
 need(len(set(x[0] for x in ids))==len(set(x[1] for x in ids))==3,'distinct runtime/state objects across boundaries and retained objects within each boundary')
 return dict(status='PASS_INDEPENDENT_SEQUENTIAL_MANAGER_AUDIT',episodes=results,source_predicate_checks=model_checks,observed_worker_wall_seconds=sup['wall_seconds'],observed_process_peak_rss_bytes=r['process_peak_rss_bytes'],observed_supervisor_sampled_peak_rss_bytes=sup['sampled_peak_rss_bytes'],native_calls=0,synthesis_calls=0,scientific_worker_reruns=0,event_count=69,bytecode_cache_checks=len(caches),scope=['Independent finite graph reachability, input coverage, safety and SCC checks over saved graph records; no winning-region synthesis.','All 1,048,576 full source-state pairs are checked with independent Python integer truth tables and a separate native-node parser.','Events, exact object identities and code call sites support one sequential paused manager per boundary; no prior episode verdict is used as proof.','Python/process execution provenance and native exporter metadata remain trust boundaries. Timings are one observed instrumented run, not benchmark estimates.','The earlier launch01 failed before worker exec; only unsupported address-space limit and run directory were amended with parent authorization.'])
