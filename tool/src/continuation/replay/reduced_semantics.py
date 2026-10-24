"""Saved reduced-query binding extracted from the preserved independent auditor.

No native solver or fixed-point recomputation is invoked. BooleanAudit and the
semantic query/output binding statements are unchanged. Historical source/runtime
pins and process resource provenance are outside this portable semantic scope.
"""
from functools import lru_cache
from itertools import product
class BooleanAudit:
    def __init__(self, d): self.d = d
    @lru_cache(None)
    def neg(self, x):
        if x < 2: return 1-x
        v,l,h = self.d.nodes[x]
        return self.d.mk(v,self.neg(l),self.neg(h))
    @lru_cache(None)
    def both(self, x, y):
        if x == 0 or y == 0: return 0
        if x == 1: return y
        if y == 1 or x == y: return x
        vx,lx,hx = self.d.nodes[x]; vy,ly,hy = self.d.nodes[y]
        if vx < vy: return self.d.mk(vx,self.both(lx,y),self.both(hx,y))
        if vy < vx: return self.d.mk(vy,self.both(x,ly),self.both(x,hy))
        return self.d.mk(vx,self.both(lx,ly),self.both(hx,hy))
    def either(self,x,y): return self.neg(self.both(self.neg(x),self.neg(y)))
    def allof(self, values):
        r=1
        for v in values: r=self.both(r,v)
        return r
    def anyof(self, values):
        r=0
        for v in values: r=self.either(r,v)
        return r
    def exists(self, root, variables):
        @lru_cache(None)
        def walk(u):
            if u < 2: return u
            v,l,h=self.d.nodes[u];lo,hi=walk(l),walk(h)
            return self.either(lo,hi) if v in variables else self.d.mk(v,lo,hi)
        return walk(root)
    def cube(self, assignment):
        r=1
        for bit,b in sorted(assignment.items(), reverse=True):
            r=self.d.mk(bit,0,r) if b else self.d.mk(bit,r,0)
        return r
    def count(self, root, variables):
        variables=tuple(sorted(variables)); pos={b:i for i,b in enumerate(variables)}
        need(self.d.support(root) <= set(variables), 'count support contains current variables only')
        @lru_cache(None)
        def visit(u, offset):
            if u < 2: return u * 2**(len(variables)-offset)
            v,l,h=self.d.nodes[u];k=pos[v]
            return 2**(k-offset)*(visit(l,k+1)+visit(h,k+1))
        return visit(root,0)


def audit_saved_reduced_query():
    prep=read(EXP/'PREPARATION.json')
    m=raw.Model('new-original'); d=m.dag; b=BooleanAudit(d)
    need(len(m.fields)==14 and len(m.env)==10 and len(m.sys)==4 and '~envHelp' not in m.names,
         'full 14-field original universe without helper',dict(fields=[f['name'] for f in m.fields]))
    need(len(m.justices['ENV'])==3 and len(m.justices['SYS'])==5,'original ordered justice counts 3 ENV / 5 SYS')
    def domain(fields,phase):
        return b.allof(b.anyof(b.cube(m.enc[f['name'],v,phase]) for v in f['values']) for f in fields)
    D=domain(m.fields,'current'); DE=domain(m.env,'next'); DS=domain(m.sys,'next')
    need(D==m.formulas['domain'] and DE==m.formulas['domain_ENV_next'] and DS==m.formulas['domain_SYS_next'],
         'independently constructed complete typed domains equal frozen native domains')
    sysnext={v for f in m.sys for v in f['next_bits']}; envnext={v for f in m.env for v in f['next_bits']}
    hasreply=b.exists(b.both(m.formulas['rhoS'],DS),sysnext)
    badinput=b.exists(b.both(DE,b.neg(hasreply)),envnext)
    F=b.both(D,b.neg(badinput))
    prime={c:n for f in m.fields for c,n in zip(f['current_bits'],f['next_bits'])}
    @lru_cache(None)
    def primed(u):
        if u<2:return u
        v,l,h=d.nodes[u]
        return d.mk(prime[v],primed(l),primed(h))
    boundary=read(raw.CERT/'BOUNDARY.json')['boundary']; layout={k:boundary[k] for k in raw.COORDS}
    L=b.cube(m.bits(layout)); Q=b.both(D,L); root=b.cube(m.full(boundary))
    rawS=b.both(m.formulas['rhoS'],primed(F)); S=b.allof([rawS,Q,primed(Q)])
    need(b.allof([Q,m.formulas['rhoE'],b.neg(primed(L))])==0,'Q is closed under every original-legal typed ENV input')
    counts=dict(D=b.count(D,m.cbits),Q=b.count(Q,m.cbits),F=b.count(F,m.cbits),FQ=b.count(b.both(F,Q),m.cbits))
    need(counts==dict(D=75000000,Q=4800,F=71812500,FQ=4596),'complete-domain and typed-quantifier counts',counts)
    need(b.both(root,Q)==root and b.both(root,F)==root and b.count(root,m.cbits)==1,
         'exact all-field pending singleton in Q and F')
    need(boundary['request']=='S2' and b.both(root,m.formulas['thetaS'])==0,'pending S2 root fails original SYS initializer')
    expected={'F_current':F,'query_domain':Q,'pending_full_state':root,'reduced_rhoS_raw':rawS,'solver_rhoS':S,'solver_rhoE':m.formulas['rhoE']}
    for label,u in expected.items():
        r=prep['functions'][label];actual=d.parse(EXP/'prepared'/r['file'],r,m.model['bdd_variable_count'])
        need(actual==u,'prepared '+label+' exact independent Boolean identity')
    out=EXP/'single_attempt/native_result';result=read(out/'RESULT.json');model=read(out/'model.json');proc=read(EXP/'single_attempt/PROCESS.json')
    for key in ['fields','public_fields','all_current_bits','all_next_bits','bdd_variable_count','bdd_variable_order']:
        need(model[key]==m.model[key],'native metadata equality: '+key)
    for key,r in model['original_bdds'].items():
        need(d.parse(out/r['file'],r,model['bdd_variable_count'])==m.formulas[key],'regenerated original predicate equality: '+key)
    for owner in ['ENV','SYS']:
        need(len(model['original_justices'][owner])==len(m.justices[owner]),'native '+owner+' justice roster')
        for i,r in enumerate(model['original_justices'][owner]):
            need(d.parse(out/r['file'],r,model['bdd_variable_count'])==m.justices[owner][i],f'native ordered {owner} justice {i}')
    for label,u in expected.items():
        r=result[label]
        need(d.parse(out/r['file'],r,model['bdd_variable_count'])==u,'executed saved query '+label+' exact independent identity')
    need(result['helper_used'] is False and result['private_memory_used'] is False and
         result['source_initializers_changed'] is False and result['source_or_monitor_reset'] is False,
         'native report no helper/private phase/initializer replacement/monitor reset')
    need(result['native_strict_solver_calls']==1 and result['raw_four_fixed_point_calls']==0,
         'one strict GR1Game call; zero raw four-fixed-point calls')
    need(result['strict_memory_complete'] and result['status']=='PASS_COMPLETE' and proc['returncode']==0 and
         proc['status']=='COMPLETE_CANDIDATE_REQUIRES_BINDING_AUDIT' and not proc['reasons'] and not proc['termination_events'] and
         'teardown_exception' not in result,'normal completed native result and complete memory')
    W={}
    for key in ['raw','Q','FQ']:
        r=result['winning_region_'+key];W[key]=d.parse(out/r['file'],r,model['bdd_variable_count'])
        need(d.support(W[key])<=m.cbits,'native W '+key+' has no next-field support')
    need(W['Q']==b.both(W['raw'],Q) and W['FQ']==b.allof([W['raw'],Q,F]),'saved W intersections exactly match raw W, Q and F')
    free=[f for f in m.fields if f['name'] not in layout]
    states=[{**layout,**dict(zip([f['name'] for f in free],vals))} for vals in product(*(f['values'] for f in free))]
    need(len(states)==4800 and len(free)==8,'independent complete 4800-state enumeration, eight free fields')
    region=lambda u:{raw.statekey(s) for s in states if d.evaluate(u,m.full(s))}
    selected=region(W['FQ']);prior=read(PRIOR/'independent_audit/new_explicit_regions.json')
    prior_all={raw.statekey(s) for s in prior['states']};prior_wf={raw.statekey(prior['states'][i]) for i in prior['W_F_ids']}
    need({raw.statekey(s) for s in states}==prior_all,'full state universes match by names and typed values, not indices')
    need(selected==prior_wf,'native FQW equals the entire prior explicit WF set, not merely count',dict(agreement_states=4800,winner_states=len(selected)))
    need(not d.evaluate(W['raw'],m.full(boundary)) and not d.evaluate(W['FQ'],m.full(boundary)) and
         not result['pending_state_strict_winning'] and not result['pending_state_in_FQW'],'pending root excluded independently and in native receipt')
    region_counts={k:b.count(v,m.cbits) for k,v in W.items()}
    need(b.both(W['FQ'],b.neg(F))==0,'reported reduced WF excludes all outside-F states')
    region_counts={k:b.count(v,m.cbits) for k,v in W.items()}
    return dict(status='PASS_SAVED_REDUCED_QUERY_AND_FULL_REGION_AGREEMENT',counts=counts,
                native_region_counts=region_counts,exact_state_membership_agreement=4800,
                pending_in_F=True,pending_native_W=False,pending_native_FQW=False,
                native_solver_calls_in_this_replay=0,fixed_point_recomputations_in_this_replay=0)
