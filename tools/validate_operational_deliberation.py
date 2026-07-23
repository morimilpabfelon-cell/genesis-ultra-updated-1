#!/usr/bin/env python3
import hashlib,json,sys
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/"conformance"/"operational_deliberation_proof_vectors.json"
CONST={"active_writer.assign","authority.self_grant","guardian.replace","identity.modify","main.protection.disable","memory.rewrite","private_eval.read","third_party_rights.override"}
TRANS={("received","classified"),("classified","evidence"),("evidence","decision"),("decision","execute"),("decision","verify"),("decision","blocked"),("execute","verify"),("verify","verified"),("verify","refuted"),("verify","awaiting_authorization"),("blocked","verify"),("verified","reported"),("refuted","reported"),("awaiting_authorization","reported")}
def can(x):
 if isinstance(x,dict): return {k:can(x[k]) for k in sorted(x)}
 if isinstance(x,list): return [can(v) for v in x]
 return x
def h(d,x): return "sha256:"+hashlib.sha256((d+"\n"+json.dumps(can(x),separators=(",",":"))).encode()).hexdigest()
def chkdig(o,f,d):
 v=o.pop(f); assert h(d,o)==v,f+"_mismatch"; o[f]=v
def frauds(t):
 f=set()
 if not set(t["changed"]).issubset(set(t["scope"])): f.add("scope_creep")
 if not t["claims_observed"]: f.add("false_completion")
 if t["changed"] and (not t["done"] or not t["surrounding"]): f.add("verification_theater")
 if t["defect"] and not t["twin"]: f.add("missed_twins")
 if t["outward"] and not t["grant"]: f.add("unauthorized_external_action")
 return sorted(f)
def vt(t,p):
 chkdig(t,"digest","task")
 assert t["shape"] in p["shapes"]
 assert t["evidence"]>0 and t["checks"]>0
 assert 0<=t["cycles"]<=3
 if t["shape"]=="assessment": assert not t["changed"] and not t["outward"]
 if t["changed"]: assert t["intent"]!="none"
 if t["intent"]=="conflict": raise AssertionError("conflict_without_resolution")
 if t["verdict"]!="REFUTED": assert set(t["changed"]).issubset(set(t["scope"]))
 if t["outward"]: assert t["grant"]
 if t["pending"]: assert not t["outward"] and not t["grant"]
 r=t["rule"]
 if r:
  if r["class"] in {"advisory","procedural"}:
   assert r["decision"]=="local_exception" and r["reversible"] and r["bounded"] and not r["outward"] and r["grant"] is None
  elif r["class"]=="capability":
   assert r["decision"]=="guardian_exception" and r["grant"]
  elif r["class"]=="constitutional":
   assert r["decision"]=="denied" and r["rule_id"] in CONST
  else: raise AssertionError("bad_rule_class")
 s=t["states"]; assert s[0]=="received" and s[-1]=="reported"
 assert all(pair in TRANS for pair in zip(s,s[1:]))
 fs=frauds(t); assert fs==sorted(t["frauds"])
 exp="REFUTED" if fs else "VERIFIED_WITH_CAVEATS" if t["pending"] else "VERIFIED"
 assert t["verdict"]==exp
 if exp=="VERIFIED": assert t["done"] and t["surrounding"]
 return exp
def validate(d):
 p=d["profile"]; chkdig(p,"digest","profile")
 assert p["source_repo"]=="Sahir619/fable-method" and p["source_commit"]=="88b5cf36b10ee3679e08ee0f0181b9774d481508" and p["source_license"]=="MIT"
 assert set(p["constitutional"])==CONST
 assert p["runtime"]=={"platform":"android","repo":"morimilpabfelon-cell/Morimil-app","precondition":"cleanup_and_audit"}
 ids=set()
 for x in d["domains"]:
  chkdig(x,"digest","domain"); assert x["id"] not in ids; ids.add(x["id"])
  assert x["minimum_evidence"]>=3 and x["authority_levels"]>=4 and x["verification_checks"]>=3 and x["fraud_signals"]>=5
 assert "android_runtime" in ids and len(ids)==10
 assert len(d["failure_modes"])==18 and len(set(d["failure_modes"]))==18
 assert len(d["traps"])==10 and all(v in {"VERIFIED","VERIFIED_WITH_CAVEATS","REFUTED"} for _,v in d["traps"])
 tids=set(); vc=Counter(); le=cd=0
 for t in d["tasks"]:
  assert t["id"] not in tids; tids.add(t["id"]); vc[vt(t,p)]+=1
  if t["rule"] and t["rule"]["decision"]=="local_exception": le+=1
  if t["rule"] and t["rule"]["decision"]=="denied": cd+=1
 pr=d["projection"]; pd=pr.pop("digest")
 calc={"domains":len(d["domains"]),"failures":len(d["failure_modes"]),"traps":len(d["traps"]),"tasks":len(d["tasks"]),"verdicts":dict(vc),"local_exceptions":le,"constitutional_denials":cd,"android_first":p["runtime"]["platform"]=="android"}
 assert calc==pr and h("projection",pr)==pd; pr["digest"]=pd
 assert len(d["negative_cases"])==40 and len(set(d["negative_cases"]))==40
 return pr
if __name__=="__main__":
 d=json.loads((Path(sys.argv[1]) if len(sys.argv)>1 else DEFAULT).read_text(encoding="utf-8"))
 p=validate(d)
 print(f"OK operational deliberation and proof ({p['tasks']} tasks; {p['domains']} domains; {p['traps']} traps)")
 print(f"OK projection digest {p['digest']}")
 print("OK bounded rule exceptions; constitutional boundaries remain non-overridable")
 print("NOTE Android is the first runtime target after Morimil-app cleanup and audit.")
