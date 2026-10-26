"""Distinct finite saved-certificate verification: NEVER computes a fixed point."""
import itertools
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent
P=H.parent.parent
C=P/'independent_correspondence'
sys.path.insert(0,str(C))
import audit_core as c
import prior_binding as p
import strict_membership as membership
MODES={'original':'A','syntactic':'B','first_flip':'C','complete':'D'}


def load_dag(folder, model, ref):
    file=folder/ref['file']; c.require(file.name==ref['file'],'BDD reference path')
    c.require(c.pin(file)['sha256']==ref['sha256'] and file.stat().st_size==ref['bytes'],'BDD pin')
    dag=p.DAG.raw(file.read_text(),model['bdd_variable_count'],model['bdd_variable_order'])
    c.require(len(dag.nodes)==ref['node_count'] and sorted(dag.support())==ref['support'],'BDD metadata')
    return dag


def verify_snapshots(bundle):
    r=c.read(bundle.folder/'RESULT.json')
    c.require(r['status']=='PASS_COMPLETE' and r['strict_memory_complete'] is True and r['native_strict_solver_calls']==1,'complete native strict result')
    originals={k:bundle.forms[k] for k in ('thetaE','thetaS','rhoE','rhoS')}
    for owner in ('ENV','SYS'): originals.update({owner+'_justice_'+str(i):root for i,root in enumerate(bundle.justices[owner])})
    normalized=dict(originals)
    for owner in ('ENV','SYS'):
        if not bundle.justices[owner]:normalized[owner+'_justice_0']=1
    for phase in ('before_constructor','after_constructor','after_solve'):
        actual={k:bundle.load(v) for k,v in r['full_model_'+phase].items()}
        c.require(actual==(originals if phase=='before_constructor' else normalized),'native snapshot mutation beyond empty-justice TRUE padding')
    return r


def classify_f(b,q,f):
    if f==0:return 'EMPTY'
    if f==q:return 'DOMAIN'
    return 'DECLINED_INTERMEDIATE_F'


def expected_false(kind, source_member):
    if kind=='EMPTY':return False
    if kind in ('DOMAIN','SOURCE'):return source_member
    raise ValueError('no exact WF certificate for intermediate F')


def check(variant, mode, output):
    # Import already-qualified primitive functions only. Never call strict(), fixed(), or audit_arm().
    base=P/'native_preparation'; ident='OBSTACLE_'+variant.upper();folder=base/'execution'/ident/mode/'native_result'
    sm=c.read(base/'exports'/ident/'native_result/model.json');a=c.Arena(sm);b=a.b
    source=c.Bundle(base/'exports'/ident/'native_result',a)
    original=c.Bundle(base/'execution'/ident/'original/native_result',a)
    c.require(source.forms==original.forms and source.justices==original.justices,'source fresh/export exact primitives')
    verify_snapshots(original)
    selected=original if mode=='original' else c.Bundle(folder,a,True)
    native=verify_snapshots(selected)
    gates={'source_export_primitives_equal':True,'all_snapshots_only_empty_justice_TRUE_padding':True}
    f_kind='SOURCE'; f=None
    if mode!='original':
        more,qd=c.correspondence(source,selected);gates.update(more)
        edge_mask=b.conj(a.q,a.den,a.dsn)
        gates['postflip_SYS_typed_total']=b.conj(edge_mask,qd['S11'])==edge_mask
        # Typed S11 total gives a response for every legal E11; D is itself a
        # postflip CPre fixed point. Greatest fixed point U is exactly D.
        if not all(gates.values()):return {'status':'DECLINED_QUADRANT_CERTIFICATE','gates':gates,'fixedpoint_calls':0}
        f=a.ops(qd['E01'],qd['S01']).cpre(a.q)  # exactly ONE predecessor, no iteration
        f_kind=classify_f(b,a.q,f)
        if mode=='first_flip':
            prior=c.Bundle(base/'execution'/ident/'syntactic/native_result',a,True);bqd=c.quadrants(prior)
            gates['C_ENV_all_quadrants_unchanged']=all(qd['E'+ij]==bqd['E'+ij] for ij in ('00','01','10','11'))
            gates['C_SYS_other_quadrants_unchanged']=all(qd['S'+ij]==bqd['S'+ij] for ij in ('00','10','11'))
            gates['C_SYS01_typed_total']=b.conj(edge_mask,qd['S01'])==edge_mask
            gates['C_init_justice_unchanged']=all(selected.forms[k]==prior.forms[k] for k in ('thetaE','thetaS')) and selected.justices==prior.justices
        if mode=='complete':
            envmask=b.conj(a.q,a.den)
            gates['D_complete_ENV']=all(b.conj(envmask,qd['E'+ij])==envmask for ij in ('01','11')) and qd['E10']==0
            gates['D_complete_SYS_release']=all(b.conj(edge_mask,qd['S'+ij])==edge_mask for ij in ('01','10','11'))
        if not all(gates.values()) or f_kind.startswith('DECLINED'):
            return {'status':'DECLINED_NO_EXACT_WF_CERTIFICATE','gates':gates,'F_kind':f_kind,'fixedpoint_calls':0}
    # The independent equation evaluator completed before native execution;
    # saved source W is an external, non-circular input to this certificate.
    peer_path=P/('independent_source/run_'+variant+'/data/SOURCE_RESULT.json');peer=c.read(peer_path)
    freeze=c.read(base/'INPUT_PROJECTION_FREEZE.json');sr=next(x for x in freeze['source_rows'] if x['phase']==variant)
    c.require(peer['status']=='COMPLETE' and peer['source_sha256']==sr['original_source']['sha256'],'peer original source identity')
    source_ids=set(peer['winning_ids']);c.require(len(source_ids)==peer['winning_count'] and source_ids<=set(range(6272)),'source W IDs')
    model=selected.model;dags={k:load_dag(folder,model,native[k]) for k in ('winning_region_raw','winning_region_typed','winning_region_source_view')}
    domain=load_dag(folder,model,model['original_bdds']['domain'])
    current=sorted(model['all_current_bits']); source_names={f['name'] for f in sm['fields']}; source_current={bit for f in model['fields'] if f['name'] in source_names for bit in f['current_bits']}
    helper_fields=[x for x in model['fields'] if x['name'] not in {f['name'] for f in sm['fields']}]
    c.require(len(helper_fields)==(mode!='original'),'helper roster')
    helper=helper_fields[0] if helper_fields else None
    for dag in dags.values():c.require(dag.support()<=set(current),'W next support')
    c.require(dags['winning_region_source_view'].support()<=source_current,'source view helper or next support')
    # Check raw/typed/source-view relations over all BOOLEAN current encodings,
    # including invalid integer encodings; no BDD construction or solver.
    for values in itertools.product((False,True),repeat=len(current)):
        bits=dict(zip(current,values));raw=dags['winning_region_raw'].point(bits);typed=dags['winning_region_typed'].point(bits)
        c.require(typed==(raw and domain.point(bits)),'raw typed domain binding')
        hb=dict(bits)
        if helper:hb.update({int(k):v for k,v in helper['encoding']['false']['current'].items()})
        c.require(dags['winning_region_source_view'].point(bits)==dags['winning_region_typed'].point(hb),'source-view helper-false binding')
    rows=[];alltyped=[];counts={'helper_false':0,'helper_true':0};mismatches=[]
    for sid,state in enumerate(membership.states()):
        vals={k:(str(v).lower() if isinstance(v,bool) else str(v)) for k,v in state.items()}
        answers={}
        for hv in ((False,True) if helper else (False,)):
            values=dict(vals)
            if helper:values[helper['name']]=str(hv).lower()
            bits=p.encode(model,values);actual=dags['winning_region_typed'].point(bits)
            expected=True if hv else expected_false(f_kind,sid in source_ids)
            key='helper_true' if hv else 'helper_false';answers[key]=actual;counts[key]+=actual
            if actual!=expected:mismatches.append({'state_id':sid,'helper':hv,'actual':actual,'expected':expected})
        alltyped.append({'state_id':sid,**answers})
    roster=c.read(freeze['all98_boundary']['path'])
    c.require(len(roster['rows'])==98,'all98')
    for r in roster['rows']:
        sid=membership.state_id(r['source_state']);rows.append(dict(r,independent_equation_source_W=sid in source_ids,**alltyped[sid],initializer_reapplied=False,filtered=False))
    # Explicit current-state initialization quantification from saved primitive
    # DAGs and W, keeping new source initializers exactly as authored.
    thetae=load_dag(folder,model,model['original_bdds']['thetaE']);thetas=load_dag(folder,model,model['original_bdds']['thetaS'])
    envfields=[x for x in model['fields'] if x['owner']=='ENV']; envnames=[x['name'] for x in envfields];covered={};allowed=set()
    for val in p.valuations(model):
        bits=p.encode(model,val);ek=tuple(val[k] for k in envnames)
        if thetae.point(bits):
            allowed.add(ek)
            if thetas.point(bits) and dags['winning_region_typed'].point(bits):covered[ek]=True
    initial=all(covered.get(k,False) for k in allowed)
    gates['native_actual_initializer_matches_enumeration']=initial==native['actual_initializer_realizable']
    status='PASS_SAVED_CERTIFICATE' if not mismatches and all(gates.values()) else 'MISMATCH_SAVED_CERTIFICATE'
    output.mkdir(parents=True,exist_ok=False)
    result={'status':status,'variant':variant,'mode':mode,'gates':gates,'U_certificate':'DOMAIN_BY_TYPED_POSTFLIP_SYS_TOTAL' if helper else 'N/A','F_certificate':f_kind,'WF_certificate':'EMPTY_BY_OUTER_F_INTERSECTION' if f_kind=='EMPTY' else ('SOURCE_W_BECAUSE_F_EQUALS_DOMAIN' if helper else 'PRE_NATIVE_INDEPENDENT_SOURCE_EQUATIONS'),'native_typed_counts':counts,'mismatches':mismatches,'all_typed_state_checks':6272*(2 if helper else 1),'all_boolean_mask_checks':2**len(current),'one_step_predecessor_calls':int(helper is not None),'fixedpoint_calls':0,'native_calls':0,'prior_fixedpoint_audit_status':'UNKNOWN_BDD_NODE_CAP_UNCHANGED','claim':'Distinct theorem-based saved certificate plus explicit source-W comparison; NOT independently recomputed transformed fixed points','peer_source_result':c.pin(peer_path),'native_result':c.pin(folder/'RESULT.json'),'primitive_input_pins':[x for z in (source,original,selected) for x in z.pins],'canonical_primitive_nodes':len(b.nodes),'actual_initializer_realizable_by_enumeration':initial}
    c.save(output/'CERTIFICATE.json',result);c.save(output/'ALL98_MEMBERSHIP.json',{'count':98,'none_filtered':True,'rows':rows,'certificate_status':status})
    c.save(output/'ALL_TYPED_MEMBERSHIP.json',{'typed_source_count':6272,'rows':alltyped})
    return result
