"""Hand-derived contracts for exact pinned source listings, independent of profiles.

No source formula is evaluated at import. Boolean source fields use false/true,
response-pattern monitors use S0/S1. The declaration pins include the omitted
pattern added by the already-declared reconstruction, not a new repair.
"""
from dataclasses import dataclass

BOOL = ('false', 'true')
MONITOR = ('S0', 'S1')
HELPER = '~envHelp'


def truth(state, name):
    return state[name] == 'true'


def implies(a, b):
    return not a or b


def response_update(state, successor, monitor, request, response):
    # Exact four disjuncts of the source pRespondsToS declaration simplify to:
    pending = (state[monitor] == 'S1' or request) and not response
    return (successor[monitor] == 'S1') == pending


@dataclass(frozen=True)
class SourceContract:
    candidate: str
    source_bytes: int
    source_sha256: str
    env: tuple
    system: tuple
    aux: tuple
    theta_e: object
    theta_s: object
    rho_e: object
    rho_s: object
    justice: object
    timing_note: str

    @property
    def names(self):
        return self.env + self.system + tuple(name for name, _ in self.aux)

    @property
    def values(self):
        return {**{name: BOOL for name in self.env + self.system},
                **{name: values for name, values in self.aux}}

    @property
    def fields(self):
        return ([{'name': name, 'domain': list(BOOL), 'owner': 'ENV', 'role': 'ENV'} for name in self.env]
                + [{'name': name, 'domain': list(BOOL), 'owner': 'SYS', 'role': 'SYS'} for name in self.system]
                + [{'name': name, 'domain': list(values), 'owner': 'SYS', 'role': 'AUX'} for name, values in self.aux])


def monitors(owner, count, start=0):
    return tuple((f'{owner}_CONSTRAINT.{i}.pRespondsToS.state', MONITOR) for i in range(start, start + count))


ARB_MON = monitors('SYS', 2)


def arb_initial(s):
    return (not truth(s, 'g1') or not truth(s, 'g2')) and all(s[name] == 'S0' for name, _ in ARB_MON)


def arb_system(s, t):
    return ((not truth(t, 'g1') or not truth(t, 'g2'))
            and all(response_update(s, t, monitor, truth(s, request), truth(s, grant))
                    for (monitor, _), request, grant in zip(ARB_MON, ('r1', 'r2'), ('g1', 'g2'))))


def arb_preferred_invariant(s):
    return (not truth(s, 'g1') or not truth(s, 'g2')) and (truth(s, 'a') or (not truth(s, 'g1') and not truth(s, 'g2')))


def arb_preferred_system(s, t):
    return arb_preferred_invariant(t) and all(
        response_update(s, t, monitor, truth(s, request), truth(s, grant))
        for (monitor, _), request, grant in zip(ARB_MON, ('r1', 'r2'), ('g1', 'g2')))


LIFT_MON = monitors('SYS', 3)


def lift_initial_env(s, preferred):
    off = not any(truth(s, x) for x in ('b1', 'b2', 'b3'))
    # The extra c-only ENV state invariant is also part of thetaE.
    return off and (not preferred or implies(truth(s, 'c'), not all(truth(s, x) for x in ('b1', 'b2', 'b3'))))


def lift_initial_sys(s):
    return (truth(s, 'f1') and not truth(s, 'f2') and not truth(s, 'f3')
            and all(s[name] == 'S0' for name, _ in LIFT_MON))


def lift_environment(s, t, preferred):
    # ENV invariants mentioning SYS stay current-only; they do not constrain thetaE.
    if sum(truth(s, name) for name in ('f1', 'f2', 'f3')) != 1:
        return False
    for b, f in zip(('b1', 'b2', 'b3'), ('f1', 'f2', 'f3')):
        if truth(s, b) and truth(s, f) and truth(t, b):
            return False
        if truth(s, b) and not truth(s, f) and not truth(s, 'c') and not truth(t, b):
            return False
    if preferred:
        # The ENV-only c/button invariant shifts to the successor; the f1 rule does not.
        if truth(t, 'c') and all(truth(t, x) for x in ('b1', 'b2', 'b3')):
            return False
        if not truth(s, 'f1') and all(truth(s, x) for x in ('b1', 'b2', 'b3')):
            return False
    return True


def lift_system(s, t):
    b1, b2, b3, c = (truth(s, name) for name in ('b1', 'b2', 'b3', 'c'))
    n1, n2, n3 = (truth(t, name) for name in ('f1', 'f2', 'f3'))
    moves = ((n1 and not b2 and not b3) or (n2 and (b2 or b3)) or (n1 and c),
             (n1 and b1) or (n2 and not b1 and not b3) or (n3 and b3) or (n2 and c),
             (n3 and not b1 and not b2) or (n2 and (b1 or b2)) or (n3 and c))
    return (all(implies(truth(s, floor), allowed) for floor, allowed in zip(('f1', 'f2', 'f3'), moves))
            and all(response_update(s, t, monitor, truth(s, button), truth(s, floor) or c)
                    for (monitor, _), button, floor in zip(LIFT_MON, ('b1', 'b2', 'b3'), ('f1', 'f2', 'f3'))))


MINE_MON = monitors('SYS', 1)


def mine_initial_env(s):
    return not truth(s, 'highwater') and not truth(s, 'methane')


def mine_initial_sys(s, preferred):
    prev = 'PREV_aux_1' if preferred else 'PREV_aux_0'
    return (not truth(s, 'pump') and not truth(s, prev)
            and (not preferred or s[MINE_MON[0][0]] == 'S0'))


def mine_environment(s, t, preferred):
    prev = 'PREV_aux_1' if preferred else 'PREV_aux_0'
    return (implies(truth(s, prev) and truth(s, 'pump'), not truth(t, 'highwater'))
            and (not preferred or implies(truth(s, 'pump'), not truth(s, 'highwater') or not truth(s, 'methane'))))


def mine_system(s, t, variant):
    preferred = variant == 'preferred'
    prev = 'PREV_aux_1' if preferred else 'PREV_aux_0'
    if truth(t, prev) != truth(s, 'pump'):
        return False
    if variant in ('preferred', 'trivial_1') and not implies(truth(s, 'highwater'), truth(t, 'pump')):
        return False
    if variant == 'trivial_2' and not implies(truth(s, 'methane'), not truth(t, 'pump')):
        return False
    if preferred:
        if not implies(truth(s, 'methane'), not truth(t, 'pump') or (truth(t, 'methane') and truth(t, 'highwater'))):
            return False
        # p is next(!pump), so the monitor response reads the next pump.
        if not response_update(s, t, MINE_MON[0][0], truth(s, 'methane'), not truth(t, 'pump')):
            return False
    return True


SINGLE_MON = monitors('SYS', 1)
TRAFFIC_MON = monitors('SYS', 2)
TRAFFIC_ENV_MON = monitors('ENV', 2, 2)


def traffic_invariant(s):
    return ((not truth(s, 'greenA') or not truth(s, 'greenB'))
            and implies(truth(s, 'emergency'), not truth(s, 'greenA') and not truth(s, 'greenB')))


def traffic_initial(s, preferred):
    aux = TRAFFIC_MON + (TRAFFIC_ENV_MON if preferred else ())
    return traffic_invariant(s) and all(s[name] == 'S0' for name, _ in aux)


def traffic_environment(s, t, preferred):
    a, b, ga, gb = (truth(s, name) for name in ('carA', 'carB', 'greenA', 'greenB'))
    na, nb, ne = (truth(t, name) for name in ('carA', 'carB', 'emergency'))
    clauses = [implies(a and ga, not na), implies(b and gb, not nb)]
    if preferred:
        clauses += [implies(a and not ga and not b, na), implies(b and not gb and not a, nb),
                    implies(b and not gb, nb or not na), implies(a and not ga, na or not gb),
                    implies(a and not ga, na or not ne), implies(b and not gb, nb or not ga),
                    implies(a and not ga, na or not nb),
                    implies(a and not ga and not truth(s, 'emergency'), na)]
    return all(clauses)


def traffic_system(s, t, preferred):
    if not traffic_invariant(t):
        return False
    for (monitor, _), request, response in zip(TRAFFIC_MON, ('carA', 'carB'), ('greenA', 'greenB')):
        if not response_update(s, t, monitor, truth(s, request), truth(s, response)):
            return False
    if preferred:
        # ENV response patterns are represented by SYS-owned logical monitors.
        for (monitor, _), car, green in zip(TRAFFIC_ENV_MON, ('carB', 'carA'), ('greenB', 'greenA')):
            if not response_update(s, t, monitor, truth(s, car) and not truth(s, green), truth(t, car)):
                return False
    return True


def justice_monitors(s, env, system):
    return ([s[name] == 'S0' for name, _ in env], [s[name] == 'S0' for name, _ in system])


CONTRACTS = {
    # Declared regression baseline only; not a tenth member of the remaining-nine cohort.
    'arbiter__preferred': SourceContract(
        'arbiter__preferred', 886, 'e412763fa69183ebadc1977768de0ea797c342f49f8717c2a5af0162046b4116',
        ('a', 'r1', 'r2'), ('g1', 'g2'), ARB_MON, lambda s: True,
        lambda s: arb_preferred_invariant(s) and all(s[name] == 'S0' for name, _ in ARB_MON),
        lambda s, t: truth(s, 'a') or all(not truth(s, name) for name in ('g1', 'g2', 'r1', 'r2')),
        arb_preferred_system,
        lambda s: ([truth(s, 'a')], [s[name] == 'S0' for name, _ in ARB_MON]),
        'Regression baseline: SYS invariant current initially/next on edges; ENV mixed invariant current-only.'),
    'arbiter__trivial_1': SourceContract(
        'arbiter__trivial_1', 725, 'e6440379d9bf184f03942ce56abf462c525a5a821696fde1f9098c75d7195aac',
        ('a', 'r1', 'r2'), ('g1', 'g2'), ARB_MON, lambda s: True, arb_initial,
        lambda s, t: True, arb_system, lambda s: justice_monitors(s, (), ARB_MON),
        'SYS invariant current initially/next on edges; request/grant current -> next response monitor.'),
    'traffic_single__trivial_1': SourceContract(
        'traffic_single__trivial_1', 726, '2afcb72d696cb88215df9bf5a0776200757f0794491a2435dccd91cbeda067b8',
        ('car', 'emergency', 'police'), ('green',), SINGLE_MON, lambda s: True,
        lambda s: s[SINGLE_MON[0][0]] == 'S0',
        lambda s, t: implies(truth(s, 'car') and not truth(s, 'green'), truth(t, 'car')),
        lambda s, t: response_update(s, t, SINGLE_MON[0][0], truth(s, 'car'), truth(s, 'green')),
        lambda s: ([not truth(s, 'police')], [s[SINGLE_MON[0][0]] == 'S0']),
        'ENV current car/green -> next car; SYS response monitor uses current car/green.'),
}

for variant, length, digest in [
        ('preferred', 2391, 'ff72b88abec4316e9f78f807344748687bcdeb68606817ba34fa975f34482202'),
        ('trivial_1', 2218, '6a8f8220385130b2eb219ecfa33186b179d610ffcf805a30f9cab47ab204dae7')]:
    preferred = variant == 'preferred'
    name = 'lift__' + variant
    CONTRACTS[name] = SourceContract(name, length, digest, ('b1', 'b2', 'b3', 'c'), ('f1', 'f2', 'f3'), LIFT_MON,
        lambda s, p=preferred: lift_initial_env(s, p), lift_initial_sys,
        lambda s, t, p=preferred: lift_environment(s, t, p), lift_system,
        lambda s: justice_monitors(s, (), LIFT_MON),
        'Mixed ENV invariants current-only; ENV-only invariant next; SYS move reads next floor; response monitors current.')

for variant, length, digest in [
        ('preferred', 1050, 'af387f61bd2b45cf0f8003b2eb8065e8e4f5be04d83d5ff1f7454bed3e6137ed'),
        ('trivial_1', 351, 'afbb72b7107f9de803db3a3be2fb20a1ea52d3d9999f3e41be3f108d3ddabecf'),
        ('trivial_2', 350, '45f467a8b04e0ce1ab46dd56ea698e38d5c7656fa56f71775bd93b7a8adf3944')]:
    preferred = variant == 'preferred'
    aux = (MINE_MON if preferred else ()) + ((('PREV_aux_1' if preferred else 'PREV_aux_0'), BOOL),)
    name = 'minepump__' + variant
    CONTRACTS[name] = SourceContract(name, length, digest, ('highwater', 'methane'), ('pump',), aux,
        mine_initial_env, lambda s, p=preferred: mine_initial_sys(s, p),
        lambda s, t, p=preferred: mine_environment(s, t, p), lambda s, t, v=variant: mine_system(s, t, v),
        lambda s, p=preferred: justice_monitors(s, (), MINE_MON if p else ()),
        'PREV pump starts false and copies current pump; preferred response reads next pump; SYS reads next ENV values.')

for variant, length, digest in [
        ('preferred', 2242, '4a1088626051ae50aa4e9686d03f8e8fdcb119671b9ca7b438b2764c611801ad'),
        ('trivial_1', 1125, '783fb80c0f2a9fd446fbb169bc46900c30d1e3eca015362e2375f36a44e8d579')]:
    preferred = variant == 'preferred'
    aux = TRAFFIC_MON + (TRAFFIC_ENV_MON if preferred else ())
    name = 'traffic_updated__' + variant
    CONTRACTS[name] = SourceContract(name, length, digest, ('carA', 'carB', 'emergency'), ('greenA', 'greenB'), aux,
        lambda s: True, lambda s, p=preferred: traffic_initial(s, p),
        lambda s, t, p=preferred: traffic_environment(s, t, p), lambda s, t, p=preferred: traffic_system(s, t, p),
        lambda s, p=preferred: ([not truth(s, 'emergency')] + [s[n] == 'S0' for n, _ in (TRAFFIC_ENV_MON if p else ())],
                               [s[n] == 'S0' for n, _ in TRAFFIC_MON]),
        'SYS invariant initial-current/next-edge; ENV pattern AUX SYS-owned, update includes next car, justice remains ENV.')
