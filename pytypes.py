"""Lightweight Python type checker: infers the type of simple expressions (literals, int()/input()/str() results,
variables assigned from them) and reports operations that WILL raise at runtime. Unknown types never produce a claim."""
import ast
from collections import Counter

BUILTIN = {"int": int, "float": float, "str": str, "bool": bool, "list": list, "dict": dict, "tuple": tuple, "set": set, "bytes": bytes, "None": type(None)}
NUM = {"int", "float", "bool"}
SEQ = {"str", "list", "tuple", "bytes"}
CALL_T = {"int": "int", "float": "float", "str": "str", "input": "str", "len": "int", "bool": "bool", "list": "list", "dict": "dict",
          "set": "set", "tuple": "tuple", "repr": "str", "chr": "str", "ord": "int"}
STR_STR = {"upper", "lower", "strip", "lstrip", "rstrip", "title", "capitalize", "replace", "join", "format", "center", "ljust", "rjust", "zfill", "swapcase", "casefold"}
STR_INT = {"count", "find", "rfind", "index", "rindex"}
SYM = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/", ast.FloorDiv: "//", ast.Mod: "%", ast.Pow: "**"}
ORD = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}
ANN = {"int": "int", "float": "float", "str": "str", "bool": "bool", "list": "list", "dict": "dict", "set": "set", "tuple": "tuple"}

def arith(op, a, b):
    """Result type, or 'ERR' when Python would raise TypeError."""
    if a in NUM and b in NUM: return "float" if op == "/" else None if op == "**" else "float" if "float" in (a, b) else "int"
    if op == "+": return a if a == b and a in SEQ else "ERR"
    if op == "*": return a if a in SEQ and b in ("int", "bool") else b if b in SEQ and a in ("int", "bool") else "ERR"
    if op == "%": return a if a in ("str", "bytes") else "ERR"
    if op == "-" and a == b == "set": return "set"
    return "ERR"

def names_assigned(stmts):
    return {n.id for s in stmts for n in ast.walk(s) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}

class Checker:
    def __init__(self, tree, lines, F):
        self.out, self.lines, self.F, self.guard = [], lines, F, 0
        bound = Counter()
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)): bound[n.id] += 1
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): bound[n.name] += 1
            elif isinstance(n, ast.arg): bound[n.arg] += 1
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names: bound[(a.asname or a.name).split(".")[0]] += 1
            elif isinstance(n, ast.ExceptHandler) and n.name: bound[n.name] += 1
        self.shadow = set(bound)
        self.volatile = {x for n in ast.walk(tree) if isinstance(n, (ast.Global, ast.Nonlocal)) for x in n.names}
        self.funcs = {s.name: s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and bound[s.name] == 1 and not s.decorator_list}

    def err(self, n, sev, title, why, impact, rec, fix="", conf=0.95, status="Confirmed"):
        ln = getattr(n, "lineno", 1)
        self.out.append(self.F(ln, self.lines[ln - 1] if 0 < ln <= len(self.lines) else "", "Bug", sev, title, why, impact, rec, fix, conf, status))

    def setv(self, env, name, t):
        if t is None or name in self.volatile: env.pop(name, None)
        else: env[name] = t

    # ---- expressions (each one is visited exactly once; checks happen on the way)
    def ty(self, n, env):
        if isinstance(n, ast.Constant): return {bool: "bool", int: "int", float: "float", str: "str", bytes: "bytes", type(None): "None"}.get(type(n.value))
        if isinstance(n, ast.Name): return env.get(n.id)
        if isinstance(n, ast.JoinedStr):
            for v in n.values:
                if isinstance(v, ast.FormattedValue): self.ty(v.value, env)
            return "str"
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            for e in n.elts: self.ty(e, env)
            return type(n).__name__.lower()
        if isinstance(n, ast.Dict):
            for e in [*n.keys, *n.values]:
                if e is not None: self.ty(e, env)
            return "dict"
        if isinstance(n, ast.BinOp): return self.binop(n, env)
        if isinstance(n, ast.UnaryOp):
            t = self.ty(n.operand, env); return "bool" if isinstance(n.op, ast.Not) else t if t in NUM else None
        if isinstance(n, ast.Compare): return self.compare(n, env)
        if isinstance(n, ast.BoolOp):
            ts = [self.ty(v, env) for v in n.values]; return ts[0] if all(t == ts[0] for t in ts) else None
        if isinstance(n, ast.IfExp):
            self.ty(n.test, env); a, b = self.ty(n.body, env), self.ty(n.orelse, env); return a if a == b else None
        if isinstance(n, ast.Call): return self.call(n, env)
        if isinstance(n, ast.Attribute): self.attr(n, self.ty(n.value, env)); return None
        if isinstance(n, ast.Subscript):
            t = self.ty(n.value, env); self.ty(n.slice, env); return "str" if t == "str" else None
        if isinstance(n, ast.NamedExpr):
            t = self.ty(n.value, env); self.setv(env, n.target.id, t); return t
        if isinstance(n, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda)): return {"ListComp": "list", "SetComp": "set", "DictComp": "dict"}.get(type(n).__name__)
        for c in ast.iter_child_nodes(n):
            if isinstance(c, ast.expr): self.ty(c, env)
        return None

    def binop(self, n, env):
        a, b, op = self.ty(n.left, env), self.ty(n.right, env), type(n.op)
        if op in (ast.Div, ast.FloorDiv, ast.Mod) and isinstance(n.right, ast.Constant) and type(n.right.value) in (int, float) and n.right.value == 0 and not (op is ast.Mod and a == "str"):
            self.err(n, "HIGH", "Division by zero", "The right-hand side is always 0.", "ZeroDivisionError at runtime.", "Check the divisor before dividing.")
        if a is None or b is None or op not in SYM: return None
        r = arith(SYM[op], a, b)
        if r != "ERR": return r
        l, rt = ast.unparse(n.left), ast.unparse(n.right)
        fix = ""
        if SYM[op] == "+" and (a in NUM) != (b in NUM) and "str" in (a, b):
            fix = f"{l} + int({rt})   # to add numbers\nstr({l}) + {rt}   # to join text" if a in NUM else f"int({l}) + {rt}   # to add numbers\n{l} + str({rt})   # to join text"
        self.err(n, "HIGH", "Type error: unsupported operand types", f"`{l} {SYM[op]} {rt}` mixes {a} and {b}, which Python cannot combine.", "TypeError at runtime: the program crashes on this line.",
                 "Convert one side so both have the same type (str(...) to join text, int(...) to calculate).", fix)
        return None

    def compare(self, n, env):
        left = self.ty(n.left, env)
        for op, c in zip(n.ops, n.comparators):
            right = self.ty(c, env)
            if type(op) in ORD and left and right and left != right and not (left in NUM and right in NUM):
                self.err(n, "HIGH", "Type error: cannot compare", f"`{ast.unparse(n.left)} {ORD[type(op)]} {ast.unparse(c)}` compares {left} with {right}.", "TypeError at runtime.",
                         "Convert the text with int(...) / float(...) before comparing.")
            left = right
        return "bool"

    def attr(self, n, t):
        if t in BUILTIN and not hasattr(BUILTIN[t], n.attr):
            self.err(n, "HIGH", "Attribute error", f"A {t} value has no attribute '{n.attr}'.", "AttributeError at runtime.", "Check the type of the value or the attribute name.")

    def call(self, n, env):
        fn, ats = n.func, [self.ty(a.value if isinstance(a, ast.Starred) else a, env) for a in n.args]
        for k in n.keywords: self.ty(k.value, env)
        if isinstance(fn, ast.Attribute):
            rt = self.ty(fn.value, env); self.attr(fn, rt)
            if rt == "str" and hasattr(str, fn.attr):
                return "str" if fn.attr in STR_STR else "list" if fn.attr == "split" else "int" if fn.attr in STR_INT else "bool" if fn.attr.startswith(("is", "starts", "ends")) else None
            return None
        if not isinstance(fn, ast.Name): self.ty(fn, env); return None
        name = fn.id
        if name in CALL_T and name not in self.shadow:
            a0 = n.args[0] if n.args else None
            if name in ("int", "float") and a0 is not None:
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    try: (int if name == "int" else float)(a0.value)
                    except ValueError: self.err(n, "HIGH", f"{name}() of a non-number", f"{name}({a0.value!r}) can never be converted.", "ValueError at runtime.", "Pass a numeric string.")
                elif ats[0] in ("list", "dict", "set", "tuple", "None"): self.err(n, "HIGH", f"Type error: {name}() argument", f"{name}() cannot convert a {ats[0]}.", "TypeError at runtime.", "Pass a string or a number.")
                elif isinstance(a0, ast.Call) and isinstance(a0.func, ast.Name) and a0.func.id == "input" and "input" not in self.shadow and self.guard == 0:
                    self.err(n, "LOW", f"{name}() on user input can raise ValueError", "If the user types something that is not a number, the program crashes.", "Unhandled ValueError on bad input.",
                             "Wrap it in try/except ValueError and ask again.", f"try:\n    value = {name}(input(...))\nexcept ValueError:\n    print('Please enter a number')", 0.8, "Suggestion")
            if name == "len" and ats and ats[0] in ("int", "float", "bool", "None"):
                self.err(n, "HIGH", "Type error: len() of a non-sequence", f"A {ats[0]} has no length.", "TypeError at runtime.", "Call len() on a string, list, tuple or dict.")
            return CALL_T[name]
        f = self.funcs.get(name)
        if f is not None and not any(isinstance(a, ast.Starred) for a in n.args) and not any(k.arg is None for k in n.keywords): self.arity(n, f)
        return None

    def arity(self, n, f):
        a = f.args; pos = [p.arg for p in a.posonlyargs + a.args]; kw = [k.arg for k in n.keywords]
        need = pos[:len(pos) - len(a.defaults)]; names = set(pos[len(a.posonlyargs):]) | {k.arg for k in a.kwonlyargs}
        if len(n.args) > len(pos) and not a.vararg:
            return self.err(n, "HIGH", "Wrong number of arguments", f"{f.name}() takes {len(pos)} argument(s) but {len(n.args)} were given.", "TypeError at runtime.", f"Pass at most {len(pos)} argument(s).")
        bad = [k for k in kw if k not in names]
        if bad and not a.kwarg: return self.err(n, "HIGH", "Unexpected keyword argument", f"{f.name}() has no parameter named '{bad[0]}'.", "TypeError at runtime.", "Use one of: " + ", ".join(sorted(names)))
        miss = [p for p in need[len(n.args):] if p not in kw] + [k.arg for k, d in zip(a.kwonlyargs, a.kw_defaults) if d is None and k.arg not in kw]
        if miss: self.err(n, "HIGH", "Missing function argument", f"{f.name}() needs {', '.join(repr(m) for m in miss)} but the call does not pass it.", "TypeError at runtime.", "Pass every required argument.")

    # ---- statements (sequential; types are forgotten wherever control flow could change them)
    def assign(self, tgt, t, env):
        if isinstance(tgt, ast.Name): self.setv(env, tgt.id, t)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for e in tgt.elts: self.assign(e, None, env)
        elif isinstance(tgt, ast.Starred): self.assign(tgt.value, None, env)
        elif isinstance(tgt, ast.Attribute): self.attr(tgt, self.ty(tgt.value, env))
        elif isinstance(tgt, ast.Subscript): self.ty(tgt.value, env); self.ty(tgt.slice, env)

    def block(self, stmts, env):
        for s in stmts: self.stmt(s, env)

    def forget(self, env, stmts):
        for nm in names_assigned(stmts): env.pop(nm, None)

    def stmt(self, s, env):
        T = type(s)
        if T is ast.Assign:
            t = self.ty(s.value, env)
            for tgt in s.targets: self.assign(tgt, t, env)
        elif T is ast.AnnAssign:
            t = self.ty(s.value, env) if s.value else None
            ann = ANN.get(s.annotation.id) if isinstance(s.annotation, ast.Name) else None
            if isinstance(s.target, ast.Name): self.setv(env, s.target.id, ann or t)
        elif T is ast.AugAssign:
            if isinstance(s.target, ast.Name):
                bo = ast.copy_location(ast.BinOp(left=ast.Name(id=s.target.id, ctx=ast.Load()), op=s.op, right=s.value), s)
                self.setv(env, s.target.id, self.binop(bo, env))
            else: self.ty(s.value, env)
        elif T in (ast.Expr, ast.Return, ast.Raise, ast.Assert):
            for c in ast.iter_child_nodes(s):
                if isinstance(c, ast.expr): self.ty(c, env)
        elif T is ast.If:
            self.ty(s.test, env); e1, e2 = dict(env), dict(env); self.block(s.body, e1); self.block(s.orelse, e2)
            env.clear(); env.update({k: v for k, v in e1.items() if e2.get(k) == v})
        elif T in (ast.For, ast.AsyncFor, ast.While):
            it = self.ty(s.iter, env) if T is not ast.While else self.ty(s.test, env)
            if T is not ast.While and it in ("int", "float", "bool", "None"):
                self.err(s, "HIGH", "Type error: not iterable", f"A {it} cannot be looped over.", "TypeError at runtime.", "Loop over range(...), a list, a string or another iterable.")
            self.forget(env, [s]); e = dict(env); self.block(s.body, e); self.block(s.orelse, dict(env))
        elif T in (ast.Try, getattr(ast, "TryStar", ast.Try)):
            self.forget(env, [s]); catches = any(h.type is None or (isinstance(h.type, ast.Name) and h.type.id in ("ValueError", "Exception", "BaseException")) for h in s.handlers)
            self.guard += catches; self.block(s.body, dict(env)); self.guard -= catches
            for h in s.handlers: self.block(h.body, dict(env))
            self.block(s.orelse, dict(env)); self.block(s.finalbody, dict(env))
        elif T in (ast.With, ast.AsyncWith):
            for i in s.items:
                self.ty(i.context_expr, env)
                if i.optional_vars is not None: self.assign(i.optional_vars, None, env)
            self.block(s.body, env)
        elif T in (ast.FunctionDef, ast.AsyncFunctionDef):
            for d in s.decorator_list + s.args.defaults: self.ty(d, env)
            fenv = {a.arg: ANN[a.annotation.id] for a in s.args.posonlyargs + s.args.args + s.args.kwonlyargs if isinstance(a.annotation, ast.Name) and a.annotation.id in ANN and a.annotation.id not in self.shadow}
            saved, self.guard = self.guard, 0; self.block(s.body, fenv); self.guard = saved; env.pop(s.name, None)
        elif T is ast.ClassDef:
            self.block(s.body, {}); env.pop(s.name, None)
        elif T in (ast.Import, ast.ImportFrom):
            for a in s.names: env.pop((a.asname or a.name).split(".")[0], None)
        else: self.forget(env, [s])

def check(tree, lines):
    from analyzers import F
    c = Checker(tree, lines, F); c.block(tree.body, {}); return c.out
