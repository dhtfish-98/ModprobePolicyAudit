"""Inspect selected modprobe configuration, never insert/remove kernel modules."""
import posixpath
import re
import shlex
from .common import InputError, Report, filemap, logical_lines, mapping, sequence, string

DIRECTORIES=('/etc/modprobe.d','/run/modprobe.d','/usr/local/lib/modprobe.d','/usr/lib/modprobe.d','/lib/modprobe.d')
LIMITS=['Configuration-only modprobe policy; blacklist suppresses internal aliases, not direct insertion. Blocking install stubs do not prevent insmod, init_module, initramfs or privileged direct loading.',
 'Custom MODPROBE_OPTIONS, built-in modules, module-provided aliases, runtime dependencies, options validity and kernel metadata are OPEN.',
 'All configured install/remove commands are examined as strings and never executed. Policy goals are caller-supplied disabled module names.']

def module(value):
    value=string(value,'module')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value):raise InputError('invalid module name')
    return value.replace('-','_')

def analyze(snapshot):
    mapping(snapshot,'snapshot');data=filemap(snapshot.get('files'));desired=sequence(snapshot.get('disabled_modules'),'disabled_modules')
    desired={module(x) for x in desired};report=Report('ModprobePolicyAudit','Complete supplied selected modprobe.d commands plus declared module-disablement goals')
    chosen={};blacklist=set();installs={};softdeps={};aliases={};options={};graph={}
    for path in data:
        directory=posixpath.dirname(path);name=posixpath.basename(path)
        if directory not in DIRECTORIES or not name.endswith('.conf'):report.add('file_scope','OPEN',path,'Outside default configuration directory scope');continue
        if name not in chosen or DIRECTORIES.index(directory)<DIRECTORIES.index(posixpath.dirname(chosen[name])):chosen[name]=path
    for name,path in sorted(chosen.items()):
        for number,raw in logical_lines(data[path]):
            try:tokens=shlex.split(raw,comments=True)
            except ValueError as exc:raise InputError(str(exc)) from exc
            if not tokens:continue
            where=path+':'+str(number);kind=tokens[0]
            if kind not in ('blacklist','install','remove','alias','options','softdep','weakdep'):
                report.add('directive','OPEN',where,'Unknown configuration command');continue
            if len(tokens)<2:raise InputError('missing module operand')
            if kind=='alias':
                if len(tokens)!=3:raise InputError('alias requires pattern and real module')
                pattern=tokens[1].replace('-','_');target=module(tokens[2]);aliases[pattern]=(target,where)
                if set(pattern).issubset({'*','?'}) and '*' in pattern and pattern.count('?')<=1:
                    report.add('alias_scope','FAIL',where,'Global alias redirects all nonempty module requests')
                elif not pattern or pattern[0] in '*?[' or '[' in pattern or '\\' in pattern:
                    report.add('alias_scope','OPEN',where,'Alias pattern scope outside the definite literal-prefix profile')
                else:report.add('alias_scope','PASS',where,'Literal-prefix alias declaration; actual matching/resolution is not simulated')
                continue
            mod=module(tokens[1]);rest=tokens[2:]
            if kind=='blacklist':
                if rest:raise InputError('unexpected blacklist operands')
                blacklist.add(mod)
            elif kind in ('install','remove'):
                if not rest:raise InputError('empty module shell command')
                # Shell syntax is retained verbatim; a quoted compound command cannot become a safe stub.
                command=raw.strip().split(None,2)[2].strip()
                safe=command in ('/bin/false','/usr/bin/false','/bin/true','/usr/bin/true')
                if kind=='install':installs[mod]=(safe,command,where)
                report.add('shell_override','PASS' if safe else 'OPEN',where,'Exact blocking/no-op stub' if safe else 'Arbitrary shell override requires manual review')
            elif kind=='options':
                if not rest:raise InputError('empty module options')
                options.setdefault(mod,{})
                for token in rest:
                    if '=' not in token:report.add('options','OPEN',where,'Flag option not interpreted');continue
                    key,value=token.split('=',1)
                    if key in options[mod] and options[mod][key]!=value:report.add('option_conflict','FAIL',where,'Repeated contradictory option '+key)
                    options[mod][key]=value
                report.add('options','OPEN',where,'Module-specific option meanings need kernel/module metadata')
            else:
                dependencies=[]
                if kind=='softdep':
                    marker=False
                    for token in rest:
                        if token in ('pre:','post:'):marker=True;continue
                        if not marker:raise InputError('softdep requires pre:/post: marker')
                        dependencies.append(module(token))
                    softdeps[mod]=(dependencies,where)
                else:dependencies=[module(x) for x in rest]
                if not dependencies:report.add('dependency','OPEN',where,'Empty dependency declaration')
                graph.setdefault(mod,set()).update(dependencies)
                report.add('dependency','OPEN',where,'Optional/kernel-request dependency loading not simulated')
    # Alias-to-alias is not supported by kmod; expose it rather than recursively pretending equivalence.
    for pattern,(target,where) in aliases.items():
        if target in aliases:report.add('alias_chain','OPEN',where,'Alias targets another configured alias')
        if target in desired:report.add('disabled_alias','OPEN',where,'Explicit alias targets disabled policy module')
    visited=set();active=set();budget=0
    def walk(name):
        nonlocal budget
        budget+=1
        if budget>10000:raise InputError('dependency graph budget exceeded')
        if len(active)>=32:raise InputError('dependency graph depth exceeded')
        if name in active:report.add('dependency_cycle','FAIL',name,'Dependency cycle');return
        if name in visited:return
        active.add(name)
        for child in graph.get(name,()):walk(child)
        active.remove(name);visited.add(name)
    for name in graph:walk(name)
    loaded=snapshot.get('loaded_modules')
    if loaded is not None:loaded={module(x) for x in sequence(loaded,'loaded_modules')}
    for mod in sorted(desired):
        report.check('alias_blacklist',mod in blacklist,mod,'Blacklist protects automatic internal-alias requests only')
        stub=installs.get(mod)
        report.check('install_block',bool(stub and stub[0]),mod,'Exact install blocking/no-op stub required by declared policy')
        if mod in softdeps:report.add('softdep_precedence','FAIL',mod,'Configured softdep takes precedence over install override')
        if loaded is None:report.add('loaded_state','OPEN',mod,'No loaded module snapshot')
        else:report.check('loaded_state',mod not in loaded,mod,'Disabled policy module appears loaded' if mod in loaded else 'Not in supplied loaded-module list')
    if not desired:report.add('policy_scope','OPEN','disabled_modules','No disablement goals')
    if not chosen:report.add('configuration','OPEN','files','No selected configuration files')
    return report.finish(LIMITS)
