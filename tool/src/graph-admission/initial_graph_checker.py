"""Static, original-initializer controller certificates. No native solver or runtime.

The source-to-BDD compiler is an explicit trust boundary. All typed initial
ENV choices, graph safety/input coverage and fairness are checked independently.
"""
from collections import defaultdict, deque
import hashlib
import importlib.util
from itertools import product
import json
from pathlib import Path
import re
import sys

import math
import posixpath
import zipfile
sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parent
_bdd_spec = importlib.util.spec_from_file_location("original_initializer_bdd_core", BASE / "vendor/bdd_core.py")
_bdd_module = importlib.util.module_from_spec(_bdd_spec)
_bdd_spec.loader.exec_module(_bdd_module)
BDD, Invalid, ResourceRefusal, require = (_bdd_module.BDD, _bdd_module.Invalid, _bdd_module.ResourceRefusal, _bdd_module.require)

BASE = Path(__file__).resolve().parent
FREEZE_SHA256 = "1241fba7deec2762bf571c8646c90b7c504ea5171bd38cbf723c638a682a57ad"
MAX_CARRIER = 4096
INIT = {"quantifier":"forall_ENV_exists_SYS_AUX", "source_initializers_preserved":True, "private_memory_policy":"rank0"}
GRAPH_SHA256 = "3da6d64631bd88ae0bda4ad71ccc37c46f48de233a51dcc843a476e391981d45"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_STATES = 32768
MAX_EDGES = 1000000
MAX_INPUT_CHECKS = 4000000


class ControllerDefect(Invalid):
    """An actual complete emitted response violates a controller obligation."""
    def __init__(self, defects):
        self.defects = defects
        super().__init__("Complete raw controller fails original safety/input/response obligations")


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha(path):
    return sha_bytes(path.read_bytes())


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        require(k not in result, "Duplicate JSON key: " + k)
        result[k] = v
    return result


def file_bytes(path, limit=MAX_JSON_BYTES):
    require(path.is_file() and not path.is_symlink(), "Expected regular non-symlink file: " + path.name)
    if path.stat().st_size > limit:
        raise ResourceRefusal("File byte budget exceeded: " + path.name)
    return path.read_bytes()


def read_json(path):
    return json.loads(file_bytes(path).decode("utf-8"), object_pairs_hook=unique_object)


def pinned_file(base, ref, basename=True):
    require(isinstance(ref, dict), "Missing file pin")
    name = ref.get("file")
    require(type(name) is str and name and not Path(name).is_absolute(), "Relative file pin required")
    require(name == Path(name).as_posix() and "\\" not in name, "Noncanonical relative file pin")
    parts = Path(name).parts
    require(all(p not in ("", ".", "..") for p in parts) and (not basename or len(parts) == 1),
            "Unsafe file pin")
    path = base
    for part in parts:
        path = path / part
        require(not path.is_symlink(), "Symlink in file pin")
    raw = file_bytes(path)
    require(type(ref.get("bytes")) is int and ref["bytes"] == len(raw), "File byte pin mismatch: " + name)
    require(type(ref.get("sha256")) is str and ref["sha256"] == sha_bytes(raw), "File SHA mismatch: " + name)
    return path


def exact_list(xs, expected, label):
    require(isinstance(xs, list) and all(type(x) is int for x in xs)
            and len(xs) == len(set(xs)) and set(xs) == set(expected), label)


def bit_map(value, expected, label):
    require(isinstance(value, dict) and set(value) == {str(v) for v in expected}
            and all(type(x) is bool for x in value.values()), label)
    return {int(k): v for k, v in value.items()}


def identity(data, profile, pipeline=None):
    for k in ("fixture_id", "case_id", "variant"):
        require(data.get(k) == profile[k], "Identity mismatch: " + k)
    if pipeline is not None:
        require(data.get("pipeline") == pipeline, "Pipeline mismatch")
        require(data.get("solver") == ("3fp" if pipeline in ("original_strict", "v_restricted_strict") else "4fp"), "Solver mismatch")

def pin_path(ref):
    path = Path(ref['path'])
    require(path.is_file() and not path.is_symlink(), 'Frozen path type')
    raw = path.read_bytes()
    require(len(raw) == ref['bytes'] and sha_bytes(raw) == ref['sha256'], 'Frozen path drift: ' + str(path))
    return path


def load_profile(fixture):
    freeze_path = BASE / 'SOURCE_FREEZE.json'
    require(sha(freeze_path) == FREEZE_SHA256, 'Source freeze drift')
    freeze = read_json(freeze_path)
    roster_path = pin_path(freeze['roster'])
    archive = pin_path(freeze['archive'])
    for dep in freeze['vendor']:
        pinned_file(BASE, dep, basename=False)
    rows = read_json(roster_path)['unique_inputs']
    matches = [r for r in rows if r['id'] == fixture]
    require(len(matches) == 1, 'Fixture outside unique frozen population')
    row = matches[0]
    source_root = Path(freeze['source_root'])
    top = source_root / row['path']
    require(top.stat().st_size == row['bytes'] and sha(top) == row['sha256'], 'Top-level source pin')
    seen, todo, closure = set(), [row['path']], []
    with zipfile.ZipFile(archive) as z:
        while todo:
            name = todo.pop()
            if name in seen: continue
            require(not name.startswith('/') and '..' not in Path(name).parts and '\\' not in name, 'Unsafe source import')
            seen.add(name)
            raw = z.read(name)
            copy = source_root / name
            require(not copy.is_symlink() and copy.read_bytes() == raw, 'Source/import differs from archive: ' + name)
            closure.append({'entry': name, 'path': str(copy), 'sha256': sha_bytes(raw), 'bytes': len(raw)})
            # The pinned corpus uses literal imports. Strings/comments are lexed
            # together so comment-like text inside an import is not discarded.
            tokens = re.findall(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\S', raw.decode('utf-8-sig'), re.S)
            tokens = [t for t in tokens if not t.startswith(('/*','//'))]
            for i, token in enumerate(tokens):
                if token != 'import': continue
                require(i+1 < len(tokens) and tokens[i+1][0] in ('"', "'"), 'Unsupported nonliteral import')
                target = tokens[i+1][1:-1]
                require('\\' not in target, 'Unsupported escaped import')
                todo.append(posixpath.normpath(posixpath.join(posixpath.dirname(name), target)))
    case, variant = fixture.rsplit('__', 1)
    return {'fixture_id':fixture, 'case_id':case, 'variant':variant,
            'source': {'path':str(top), 'bytes':row['bytes'], 'sha256':row['sha256']},
            'bindings':{'freeze_sha256':FREEZE_SHA256, 'roster':freeze['roster'], 'archive':freeze['archive'], 'closure':closure}}


class Context:
    def __init__(self, directory, profile, model):
        self.directory, self.profile, self.model = directory, profile, model
        require(model.get('schema') == 'k7-native-model-export-v1', 'Model schema')
        identity(model, profile)
        self.b = BDD(model['bdd_variable_count'])
        exact_list(model.get('bdd_variable_order'), range(self.b.n), 'Model variable order')
        self.fields = model['fields']
        require(isinstance(self.fields,list) and len(self.fields)<=32, 'Field roster/cap')
        self.by_name, self.current, self.next, self.env_next, self.sys_next = {}, [], [], [], []
        self.prime, self.unprime, self.enc = {}, {}, {}
        carrier = 1
        for field in self.fields:
            name, owner, role = field['name'], field['owner'], field['role']
            require(type(name) is str and name and name not in self.by_name, 'Duplicate/empty field')
            require(owner in ('ENV','SYS') and role in ('ENV','SYS','AUX')
                    and ((owner,role) in (('ENV','ENV'),('SYS','SYS'),('SYS','AUX'))), 'Owner/role mismatch or unsupported ENV auxiliary')
            values = field['values']
            require(isinstance(values,list) and values and all(type(v) is str for v in values)
                    and len(values)==len(set(values)) and type(field['domain_size']) is int
                    and field['domain_size']==len(values), 'Typed value roster')
            carrier *= len(values)
            if carrier > MAX_CARRIER: raise ResourceRefusal('Typed carrier budget exceeded')
            cb, nb = field['current_bits'], field['next_bits']
            require(isinstance(cb,list) and isinstance(nb,list) and len(cb)==len(nb) and cb, 'Bit pairing')
            exact_list(cb, cb, 'Current bits'); exact_list(nb, nb, 'Next bits')
            require(all(0<=x<self.b.n for x in cb+nb), 'Bit outside BDD manager')
            require(not set(cb+nb)&set(self.current+self.next) and not set(cb)&set(nb), 'Overlapping bits')
            require(set(field['encoding'])==set(values), 'Encoding roster')
            codes = set(); self.enc[name] = {}
            for value in values:
                enc = field['encoding'][value]
                c=bit_map(enc['current'],cb,'Current encoding'); n=bit_map(enc['next'],nb,'Next encoding')
                code=tuple(c[v] for v in cb)
                require(code==tuple(n[v] for v in nb) and code not in codes, 'Noninjective/mismatched value encoding')
                codes.add(code); self.enc[name][value]=(c,n)
            self.by_name[name]=field
            self.current.extend(cb); self.next.extend(nb)
            (self.env_next if owner=='ENV' else self.sys_next).extend(nb)
            self.prime.update(zip(cb,nb)); self.unprime.update(zip(nb,cb))
        self.carrier = carrier
        require(set(self.current+self.next)==set(range(self.b.n)), 'Unaccounted native bit/helper')
        exact_list(model['all_current_bits'],self.current,'Current bit union')
        exact_list(model['all_next_bits'],self.next,'Next bit union')
        self.env=[f['name'] for f in self.fields if f['owner']=='ENV']
        self.sys=[f['name'] for f in self.fields if f['owner']=='SYS']
        self.public={o:[f['name'] for f in self.fields if f['role']==o] for o in ('ENV','SYS')}
        require(model['public_fields']==self.public, 'Public field roster')
        self.current_env=[x for f in self.fields if f['owner']=='ENV' for x in f['current_bits']]
        self.current_sys=[x for f in self.fields if f['owner']=='SYS' for x in f['current_bits']]
        self.refs={}
        self.domain=self.b.conj(*(self.domain_of(f,False) for f in self.fields))
        self.domain_ec=self.b.conj(*(self.domain_of(f,False) for f in self.fields if f['owner']=='ENV'))
        self.domain_sc=self.b.conj(*(self.domain_of(f,False) for f in self.fields if f['owner']=='SYS'))
        self.domain_en=self.b.conj(*(self.domain_of(f,True) for f in self.fields if f['owner']=='ENV'))
        self.domain_sn=self.b.conj(*(self.domain_of(f,True) for f in self.fields if f['owner']=='SYS'))
        limits={'thetaE':self.current_env,'thetaS':self.current,'rhoE':self.current+self.env_next,'rhoS':self.current+self.next}
        self.formulas={k:self.read_bdd(model['original_bdds'][k],v) for k,v in limits.items()}
        self.justices={o:[self.read_bdd(r,self.current) for r in model['original_justices'][o]] for o in ('ENV','SYS')}

    def domain_of(self, field, prime):
        return self.b.disj(*(self.literal(field['name'],v,prime) for v in field['values']))

    def literal(self, name, value, prime=False):
        return self.b.cube(self.enc[name][value][int(prime)])

    def read_bdd(self, ref, allowed=None):
        path=pinned_file(self.directory,ref)
        key=(path.name,ref['sha256'])
        if key not in self.refs: self.refs[key]=self.b.read_native(file_bytes(path,8*1024*1024))
        u,meta=self.refs[key]
        exact_list(ref.get('support'),self.b.support(u),'Saved BDD support metadata')
        require(type(ref.get('node_count')) is int and ref['node_count']==meta['node_count'],'Saved BDD node count')
        require(type(ref.get('zero')) is bool and ref['zero']==(u==0)
                and type(ref.get('one')) is bool and ref['one']==(u==1),'Saved BDD constant metadata')
        require(meta['order'] is None or meta['order']==self.model['bdd_variable_order'],'Saved BDD order/model mismatch')
        if allowed is not None: require(self.b.support(u)<=set(allowed),'BDD forbidden support: '+path.name)
        return u

    def equal(self, ref, expected, label, allowed=None):
        require(self.read_bdd(ref,allowed)==expected,label+' differs from independent equation')

    def valuation(self, value, label, names=None):
        names=list(self.by_name) if names is None else names
        require(isinstance(value,dict) and set(value)==set(names)
                and all(type(value[k]) is str and value[k] in self.enc[k] for k in names),label+' valuation/domain')
        return value

    def bits(self,value,prime=False):
        out={}
        for name,v in value.items(): out.update(self.enc[name][v][int(prime)])
        return out

    def cube(self,value,prime=False): return self.b.cube(self.bits(value,prime))

    def audit_model(self):
        m,p,b=self.model,self.profile,self.b
        require(m['input']['sha256']==p['source']['sha256'] and m['input']['bytes']==p['source']['bytes'],'Model source pin')
        require(Path(m['input']['path']).samefile(p['source']['path']),'Model source location')
        for key,u,bits in [('domain',self.domain,self.current),('domain_ENV_next',self.domain_en,self.env_next),('domain_SYS_next',self.domain_sn,self.sys_next)]:
            self.equal(m['original_bdds'][key],u,'Typed '+key,bits)
        for key,domain in [('thetaE',self.domain_ec),('thetaS',self.domain_sc),('rhoE',self.domain_en),('rhoS',self.domain_sn)]:
            require(b.conj(self.formulas[key],b.neg(domain))==0,'Predicate admits untyped owned value: '+key)
        inv=m['source_inventory']
        for phase in ('parsed','translated'):
            for owner in ('ENV','SYS','AUX'):
                player=inv[phase][owner]
                require(isinstance(player['variables'],list) and isinstance(player['constraints'],list) and isinstance(player['patterns'],list),'Source inventory structure')
                for c in player['constraints']: require('spec_ast' in c and 'trace_id' in c,'Constraint provenance')
                for c in player['patterns']: require('actuals_ast' in c and 'trace_id' in c,'Pattern provenance')
        for owner in ('ENV','SYS'):
            # Array/define translation can change concrete field names. Parsed
            # declarations are retained, while translated variables bind fields.
            names=[v['name'] for v in inv['translated'][owner]['variables']]
            require(len(names)==len(set(names)) and set(names)==set(self.public[owner]),'Translated public field identity')
        aux=[v['name'] for v in inv['translated']['AUX']['variables']]
        require(len(aux)==len(set(aux)) and set(aux)=={f['name'] for f in self.fields if f['role']=='AUX'},'Translated AUX identity')
        native=inv['native_behaviors']
        for owner,key in [('ENV','env_justice_count'),('SYS','sys_justice_count')]:
            require(native[key]==len(self.justices[owner]),'Native justice roster')
        return {'status':'PASS','typed_carrier':self.carrier,'field_count':len(self.fields),
                'ENV_justice_count':len(self.justices['ENV']),'SYS_justice_count':len(self.justices['SYS']),
                'source_formula_equivalence':'NOT_INDEPENDENTLY_COMPILED',
                'trust_boundary':'Pinned source/imports and shared translated BDDs; independent typed encoding, support and exact domain audit.'}

    def viability(self):
        b,f=self.b,self.formulas
        alive=b.exists(f['rhoE'],self.env_next)
        v,rounds=self.domain,0
        while True:
            if rounds>self.carrier: raise ResourceRefusal('V iteration budget exceeded')
            response=b.exists(b.conj(f['rhoS'],b.rename(v,self.prime)),self.sys_next)
            pre=b.forall(b.implies(f['rhoE'],response),self.env_next)
            nxt=b.conj(self.domain,alive,pre)
            require(b.conj(nxt,b.neg(v))==0,'V iteration not descending')
            rounds+=1
            if nxt==v:return v,alive,rounds
            v=nxt

    def audit_normalization(self,result,pipeline):
        b=self.b
        self.v,alive,rounds=self.viability()
        self.equal(result['V'],self.v,'Greatest viable set',self.current)
        self.equal(result['alive'],alive,'Alive',self.current)
        norm=result['normalization']; copies=len(self.justices['ENV']) if pipeline=='normalized_kind' else 0
        require(norm.get('V_restriction') is True and norm.get('helper_added') is False and type(norm.get('ENV_justice_copies')) is int and norm['ENV_justice_copies']==copies,'Normalization declaration')
        self.equal(norm['restricted_rhoS'],b.conj(self.formulas['rhoS'],self.v,b.rename(self.v,self.prime)),'Restricted SYS relation')
        self.equal(result['residual_thetaE'],self.formulas['thetaE'],'Preserved ENV initializer',self.current_env)
        self.equal(result['residual_thetaS'],b.conj(self.formulas['thetaS'],self.v),'Restricted original SYS initializer',self.current)
        expected={'ENV':self.justices['ENV'],'SYS':self.justices['SYS']+(self.justices['ENV'] if copies else [])}
        self.rank_size=len(expected['SYS']) or 1
        for owner in ('ENV','SYS'):
            refs=result['preconstructor_justices'][owner]
            require(len(refs)==len(expected[owner]),'Preconstructor justice roster')
            for ref,u in zip(refs,expected[owner]):self.equal(ref,u,'Preconstructor justice',self.current)
            if result['native_solver_called']:
                refs=result['solver_input_justices'][owner]; padded=expected[owner] or [1]
                require(len(refs)==len(padded),'Constructor TRUE padding/order')
                for ref,u in zip(refs,padded):self.equal(ref,u,'Solver justice',self.current)
        return {'status':'PASS','V_fixed_point_iterations':rounds,'V_empty':self.v==0,'source_ENV_justice_copies':copies,'source_initializers_preserved':True}

    def audit_quantification(self,result,region):
        b=self.b
        witness=b.conj(self.formulas['thetaS'],self.v,region)
        missing=b.conj(self.formulas['thetaE'],b.neg(b.exists(witness,self.current_sys)))
        q=result['original_initial_quantification']
        self.equal(q['system_witness'],witness,'Original initial system witness',self.current)
        self.equal(q['missing_environment_initials'],missing,'Missing original ENV initials',self.current_env)
        exact_list(q['env_quantified_bits'],self.current_env,'Initial ENV quantified bits')
        exact_list(q['sys_quantified_bits'],self.current_sys,'Initial SYS/AUX quantified bits')
        verdict=(missing==0)
        require(type(q.get('verdict')) is bool and q['verdict']==verdict,'Original initial quantification verdict')
        require(type(result.get('initial_in_region')) is bool and result['initial_in_region']==verdict,'Initial region verdict')
        if result['native_solver_called']:
            require(type(result.get('native_residual_initial_verdict')) is bool and result['native_residual_initial_verdict']==verdict,'Native initial quantification verdict')
        return {'status':'PASS','verdict':verdict,'quantifier':'forall_ENV_exists_SYS_AUX'}




def graph_analyzer():
    path = BASE / "vendor/graph_fairness.py"
    require(sha(path) == GRAPH_SHA256, "Reviewed graph fairness checker drift")
    spec = importlib.util.spec_from_file_location("k7_reviewed_graph_fairness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.analyze_graph


def analyze_controller(ctx, data, pipeline):
    require(data.get("schema") == "released-concrete-controller-export-v2", "Controller schema")
    identity(data, ctx.profile, pipeline)
    require(data.get("complete") is True and data.get("controller_certified") is False, "Raw controller status")
    require(data.get("entry_mode") == "original_initializer" and data.get("initialization") == INIT,
            "Original initializer mode/contract")
    require(data.get("entry_valuation") is None and data.get("entry_bits") is None
            and data.get("replay_sha256") is None, "Unexpected factual entry/replay")
    require("entry_projections" not in data, "Unexpected entry projections")
    require(type(data.get("rank_domain_size")) is int and data["rank_domain_size"] == ctx.rank_size, "Rank domain")
    nodes = data["nodes"]
    require(isinstance(nodes, list) and nodes, "Controller state roster")
    if len(nodes) > MAX_STATES: raise ResourceRefusal("Controller state budget exceeded")
    by_id, identities, flat, starts, initial_failures = {}, set(), [], [], []
    required = {"id", "native_id", "rank", "rank_class", "rank_info", "initial", "valuation", "bits", "successors"}
    for node in nodes:
        require(isinstance(node, dict) and set(node) == required, "Controller node schema")
        sid = node["id"]
        require(type(sid) is str and re.fullmatch(r"0|[1-9][0-9]*", sid) is not None and sid not in by_id,
                "Native state ID")
        require(type(node["native_id"]) is int and str(node["native_id"]) == sid, "Native ID correspondence")
        rank = node["rank"]
        require(type(rank) is int and 0 <= rank < ctx.rank_size, "Native rank range")
        require(node["rank_class"] == "tau.smlab.syntech.games.gr1.GR1RankInfo"
                and node["rank_info"] == f"System Justice {rank}", "Native rank identity")
        require(type(node["initial"]) is bool, "Native initial flag")
        val = ctx.valuation(node["valuation"], "Controller node")
        require(bit_map(node["bits"], ctx.current, "Controller node bits") == ctx.bits(val), "Controller node bits mismatch")
        key = (rank, tuple(val[k] for k in ctx.by_name))
        require(key not in identities, "Duplicate valuation/controller-memory identity")
        identities.add(key)
        require(isinstance(node["successors"], list) and all(type(t) is str for t in node["successors"]), "Raw successor vector")
        flat.extend([[sid, t] for t in node["successors"]])
        if len(flat) > MAX_EDGES: raise ResourceRefusal("Controller edge budget exceeded")
        if node["initial"]:
            starts.append(sid)
            if rank != 0:
                initial_failures.append({"kind":"INITIAL_PRIVATE_MEMORY_NOT_RANK0", "state":sid, "rank":rank})
            if not ctx.b.evaluate(ctx.b.conj(ctx.formulas["thetaE"], ctx.formulas["thetaS"], ctx.v), ctx.bits(val)):
                initial_failures.append({"kind":"ORIGINAL_INITIALIZER_OR_V_VIOLATION", "state":sid, "valuation":val})
        by_id[sid] = node
    if not starts: initial_failures.append({"kind":"NO_INITIAL_NODE"})
    env_initials = {xs for xs in product(*(ctx.by_name[k]["values"] for k in ctx.env))
                    if ctx.b.evaluate(ctx.formulas["thetaE"], ctx.bits(dict(zip(ctx.env, xs))))}
    actual_initials = [tuple(by_id[sid]["valuation"][k] for k in ctx.env) for sid in starts]
    if len(actual_initials) != len(set(actual_initials)):
        duplicates = sorted({xs for xs in actual_initials if actual_initials.count(xs)>1})
        initial_failures.append({"kind":"DUPLICATE_INITIAL_ENV_RESPONSE", "inputs":[dict(zip(ctx.env,xs)) for xs in duplicates]})
    for kind, missing in (("MISSING_INITIAL_ENV_RESPONSE", env_initials-set(actual_initials)),
                          ("ILLEGAL_INITIAL_ENV_RESPONSE", set(actual_initials)-env_initials)):
        if missing: initial_failures.append({"kind":kind, "inputs":[dict(zip(ctx.env,xs)) for xs in sorted(missing)]})
    require(data["api_state_order"] == list(by_id) and data["edges"] == flat, "Raw API vector/edge correspondence")
    for k, n in (("api_state_count", len(nodes)), ("api_transition_count", len(flat)), ("exported_edge_count", len(flat))):
        require(type(data.get(k)) is int and data[k] == n, "API count mismatch: " + k)
    require(len({tuple(e) for e in flat}) == len(flat) and all(t in by_id for _, t in flat), "Duplicate/dangling raw edge")
    if initial_failures: raise ControllerDefect(initial_failures)
    parent, queue = {sid: None for sid in starts}, deque(starts)
    while queue:
        u = queue.popleft()
        for t in by_id[u]["successors"]:
            if t not in parent: parent[t] = u; queue.append(t)
    require(set(parent) == set(by_id), "Unreachable emitted state")
    env_inputs = list(product(*(ctx.by_name[k]["values"] for k in ctx.env)))
    if len(env_inputs)*len(nodes) > MAX_INPUT_CHECKS: raise ResourceRefusal("Legal input enumeration budget exceeded")
    counts, failures = {}, []
    for sid, node in by_id.items():
        v = node["valuation"]
        current = ctx.bits(v)
        legal = {xs for xs in env_inputs if ctx.b.evaluate(ctx.formulas["rhoE"], current | ctx.bits(dict(zip(ctx.env, xs)), True))}
        counts[sid] = len(legal)
        responses = defaultdict(list)
        for tid in node["successors"]:
            w = by_id[tid]["valuation"]
            responses[tuple(w[k] for k in ctx.env)].append(tid)
            if not ctx.b.evaluate(ctx.formulas["rhoS"], current | ctx.bits(w, True)):
                failures.append({"kind": "ORIGINAL_SYS_SAFETY", "source": sid, "target": tid})
        for kind, bad in (("MISSING_LEGAL_INPUT", legal-set(responses)), ("ILLEGAL_ENV_EDGE", set(responses)-legal)):
            if bad: failures.append({"kind": kind, "source": sid, "inputs": [dict(zip(ctx.env, xs)) for xs in sorted(bad)]})
        for xs, targets in responses.items():
            if len(targets) != 1:
                failures.append({"kind": "NONDETERMINISTIC_RESPONSE_OR_MEMORY", "source": sid,
                                 "input": dict(zip(ctx.env, xs)), "targets": targets})
        if not ctx.b.evaluate(ctx.v, current):
            failures.append({"kind": "V_INVARIANCE", "source": sid})
    if failures:
        raise ControllerDefect(failures)
    graph = {"states": list(by_id), "edges": flat, "starts": starts}
    for owner, key in (("ENV", "env_justice"), ("SYS", "sys_justice")):
        graph[key] = [[sid for sid, node in by_id.items() if ctx.b.evaluate(u, ctx.bits(node["valuation"]))]
                      for u in ctx.justices[owner]]
    fair = graph_analyzer()(graph)
    witnesses = []
    if not fair["nonconflicting"]["pass"]:
        bad = set(fair["nonconflicting"]["failing_states"])
        terminal = next((sid for sid in parent if sid in bad and counts[sid] == 0), next(sid for sid in parent if sid in bad))
        ids, cursor = [], terminal
        while cursor is not None: ids.append(cursor); cursor = parent[cursor]
        ids.reverse()
        witnesses.append({"kind": "REACHABLE_ENV_DEADEND" if counts[terminal] == 0 else "NO_FAIR_CONTINUATION",
                          "prefix": [{"id": sid, "rank": by_id[sid]["rank"], "valuation": by_id[sid]["valuation"],
                                      "legal_ENV_input_count": counts[sid]} for sid in ids],
                          "all_bad_states": fair["nonconflicting"]["failing_states"]})
    witnesses.extend(fair["strict_liveness"]["counterexamples"])
    return {"initial_state_count": len(starts), "initial_ENV_count": len(env_initials), "initial_coverage": "PASS",
            "state_count": len(nodes), "edge_count": len(flat), "legal_input_count": sum(counts.values()),
            "structural_safety_coverage_determinism": "PASS", "strict_controller_pass": fair["strict_liveness"]["pass"],
            "nonconflicting_pass": fair["nonconflicting"]["pass"],
            "kind_controller_pass": fair["strict_liveness"]["pass"] and fair["nonconflicting"]["pass"],
            "witnesses": witnesses, "fairness": fair, "graph": graph}


def base_certificate(fixture,pipeline):
    return {'schema':'original-initializer-independent-graph-certificate-v1','status':'INVALID',
            'fixture_id':fixture,'pipeline':pipeline,'entry_mode':'original_initializer',
            'checker_sha256':sha(Path(__file__)),'source_freeze_sha256':FREEZE_SHA256,
            'model_sha256':None,'result_sha256':None,'controller_sha256':None,
            'strict_controller_pass':None,'nonconflicting_pass':None,'kind_controller_pass':None,
            'witnesses':[],'failure_stage':'SOURCE_BINDING','refusal_scope':'QUALIFICATION_INTEGRITY',
            'model_validated':False,'controller_defects':[],
            'trust_boundary':'Static exact exported graph; shared parser-translated BDDs. Historical native invocation and runtime execution are not established by saved JSON.'}


def _check_arm(directory,fixture,pipeline,cert):
    require(pipeline in ('v_restricted_strict','normalized_kind'),'Unknown pipeline')
    require(directory.is_dir() and not directory.is_symlink(),'Arm directory type')
    profile=load_profile(fixture)
    cert['source_bindings']=profile['bindings']
    result=read_json(directory/'result.json')
    cert['result_sha256']=sha(directory/'result.json')
    require(result.get('schema')=='k7-native-admission-production-v1','Result schema')
    identity(result,profile,pipeline)
    require(result.get('teardown')=='COMPLETED' and result.get('controller_certified') is False,'Native completion receipt')
    require(result.get('input_sha256')==profile['source']['sha256'],'Result/source pin')
    require(result.get('entry_mode')=='original_initializer' and result.get('initialization')==INIT,'Result initialization contract')
    for key in ('entry_valuation','entry_bits','replay_export','replay_sha256','trace_sha256'):
        require(result.get(key) is None,'Unexpected factual replay field: '+key)
    require('entry_projections' not in result,'Unexpected entry projection')
    mp=pinned_file(directory,result['model_export']); model=read_json(mp)
    cert['model_sha256']=sha(mp)
    cert['failure_stage']='ORIGINAL_MODEL_CHECK'
    ctx=Context(directory,profile,model)
    cert['original_model_audit']=ctx.audit_model()
    cert['model_validated']=True
    env_empty=ctx.formulas['thetaE']==0
    joint_empty=ctx.b.conj(ctx.formulas['thetaE'],ctx.formulas['thetaS'])==0
    for key,value in [('initial_ENV_empty',env_empty),('initial_joint_empty',joint_empty)]:
        require(type(result.get(key)) is bool and result[key]==value,'Original initializer emptiness: '+key)
    cert['initializer_audit']={'ENV_empty':env_empty,'joint_empty':joint_empty}
    cert['failure_stage']='NATIVE_RESULT_BOUNDARY'
    status=result['status']
    require(status in ('COMPLETE_VACUOUS_INITIALIZER','COMPLETE_EMPTY_V_REJECTION','COMPLETE_REGION_REJECTION',
                      'COMPLETE_CONTROLLER_EXPORTED','COMPLETE_EXTRACTION_OR_EXPORT_FAILURE'),'Incomplete native production: '+str(status))
    if env_empty:
        require(status=='COMPLETE_VACUOUS_INITIALIZER' and joint_empty,'Vacuous initializer status')
        require(result.get('native_solver_called') is False and result.get('controller_extraction_called') is False
                and result.get('controller_export') is None and result.get('initial_in_region') is True,'Vacuous execution boundary')
        cert.update(status='VALID_VACUOUS_INITIALIZER',failure_stage=None,refusal_scope='VACUOUS_INITIALIZER')
        return ctx,result,None
    require(status!='COMPLETE_VACUOUS_INITIALIZER','Nonempty initializer marked vacuous')
    require(type(result.get('native_solver_called')) is bool,'Solver invocation field type')
    cert['failure_stage']='NORMALIZATION_CHECK'
    cert['normalization_audit']=ctx.audit_normalization(result,pipeline)
    if status=='COMPLETE_EMPTY_V_REJECTION':
        require(ctx.v==0 and result['native_solver_called'] is False and result.get('controller_extraction_called') is False
                and result.get('controller_export') is None,'Empty V execution boundary')
        ctx.equal(result['final_region'],0,'Empty V final region',ctx.current)
        cert['initial_quantification_audit']=ctx.audit_quantification(result,0)
        require(result['initial_in_region'] is False,'Empty V initial rejection')
        cert.update(status='VALID_SEMANTIC_REFUSAL',refusal_kind='EMPTY_V_INDEPENDENTLY_CHECKED',failure_stage=None,refusal_scope='CANDIDATE_SEMANTIC')
        return ctx,result,None
    require(result['native_solver_called'] is True,'Missing native call receipt')
    cert['failure_stage']='NATIVE_REGION_CHECK'
    w=ctx.read_bdd(result['native_W'],ctx.current)
    region=ctx.b.conj(w,ctx.v)
    ctx.equal(result['final_region'],region,'Final region',ctx.current)
    q=ctx.audit_quantification(result,region)
    cert['initial_quantification_audit']=q
    if status=='COMPLETE_REGION_REJECTION':
        require(not q['verdict'] and result.get('controller_extraction_called') is False and result.get('controller_export') is None,'Unsupported native region refusal')
        cert.update(status='VALID_SEMANTIC_REFUSAL',refusal_kind='SOURCE_BOUND_NATIVE_REGION_REFUSAL',failure_stage=None,
                    refusal_scope='CANDIDATE_SEMANTIC',refusal_claim='Native negative region bound and internally checked; independent unrealizability is not claimed.')
        return ctx,result,None
    require(q['verdict'] and result.get('controller_extraction_called') is True,'Extraction without positive initial region')
    if status=='COMPLETE_EXTRACTION_OR_EXPORT_FAILURE':
        require(type(result.get('extraction_exception')) is str and result.get('controller_export') is None,'Missing extraction failure receipt')
        cert.update(status='INVALID',refusal_kind='TECHNICAL_EXTRACTION_OR_EXPORT_FAILURE',failure_stage='NATIVE_EXTRACTION_OR_EXPORT',refusal_scope='CANDIDATE_TECHNICAL')
        return ctx,result,None
    cert['failure_stage']='CONTROLLER_BINDING'
    cp=pinned_file(directory,result['controller_export']); controller=read_json(cp)
    cert['controller_sha256']=sha(cp)
    ref=result['controller_export']
    require(ref.get('complete') is True and all(type(ref.get(k)) is int and ref[k]==controller.get(k)
            for k in ('api_state_count','api_transition_count','exported_edge_count')),'Controller completeness counts')
    require(controller.get('model_sha256')==cert['model_sha256'] and controller.get('replay_sha256') is None,'Controller model binding')
    cert['failure_stage']='CONTROLLER_CHECK'
    proof=analyze_controller(ctx,controller,pipeline)
    for key in ('strict_controller_pass','nonconflicting_pass','kind_controller_pass','witnesses'):cert[key]=proof[key]
    cert.update(status='VALID_EXPORT_CERTIFICATE',controller_audit=proof,failure_stage=None,refusal_scope=None)
    return ctx,result,controller


def check_arm(arm_directory,expected_fixture_id,expected_pipeline):
    cert=base_certificate(expected_fixture_id,expected_pipeline)
    try:
        _check_arm(Path(arm_directory),expected_fixture_id,expected_pipeline,cert)
    except ControllerDefect as error:
        cert.update(status='INVALID',error=str(error),refusal_scope='CANDIDATE_CONTROLLER',controller_defects=error.defects,witnesses=error.defects)
    except ResourceRefusal as error:
        cert.update(status='RESOURCE_REFUSAL',error=str(error),refusal_scope='CANDIDATE_TECHNICAL')
    except (Invalid,OSError,UnicodeError,json.JSONDecodeError,KeyError,TypeError,ValueError,IndexError,AttributeError,RecursionError,zipfile.BadZipFile) as error:
        cert.update(status='INVALID',error=type(error).__name__+': '+str(error))
    return cert


def main():
    if len(sys.argv)!=4:
        print('usage: initial_graph_checker.py ARM_DIRECTORY FIXTURE_ID v_restricted_strict|normalized_kind',file=sys.stderr)
        return 2
    out=check_arm(*sys.argv[1:]); print(json.dumps(out,ensure_ascii=False,indent=2,sort_keys=True))
    return 0 if out['status'] in ('VALID_EXPORT_CERTIFICATE','VALID_SEMANTIC_REFUSAL','VALID_VACUOUS_INITIALIZER') else 2


if __name__=='__main__': raise SystemExit(main())


