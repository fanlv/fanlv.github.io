#!/usr/bin/env python3
"""Build, verify and sign Veil's six data-only packs. Private key is supplied as a local file.

python3 publish.py --output /path/to/site/veil/rules/v1 --key /secure/key [--from-bundle /path/to/filterPacks]
"""
import argparse,base64,datetime,hashlib,json,pathlib,shutil,subprocess,tempfile,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
PIN='1cfdcaf042880a5e0027a8fc6f7ebf9ee667acc9'
PUBLIC_KEY='atjb78QoQHR92czcRONU5e3u02C9GeTYHhJ8+jig4EA='
SOURCES={
 'ads':('EasyList','https://easylist.to/easylist/easylist.txt','The EasyList authors','CC-BY-SA-3.0'),
 'privacy':('EasyPrivacy','https://easylist.to/easylist/easyprivacy.txt','The EasyList authors','CC-BY-SA-3.0'),
 'annoyances':("Fanboy's Annoyance List",'https://easylist-downloads.adblockplus.org/fanboy-annoyance.txt','Fanboy and the EasyList authors','CC-BY-3.0'),
 'regional-china':('EasyList China','https://easylist-downloads.adblockplus.org/easylistchina.txt','John and Li (EasyList China)','CC-BY-SA-3.0'),
 'regional-france':('Liste FR','https://easylist-downloads.adblockplus.org/liste_fr.txt','Lian, Crits and smed79 (Liste FR)','CC-BY-SA-3.0'),
 'regional-korea':('KoreanList','https://easylist-downloads.adblockplus.org/koreanlist.txt','Mark Choi (KoreanList)','CC-BY-SA-3.0')}
def encode(v):return (json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def run(a,**kwargs):return subprocess.run(a,check=True,**kwargs)
def old_manifest(output):
 p=output/'manifest.json'
 if not p.exists():return None
 return json.loads(base64.b64decode(json.loads(p.read_text())['payload']))

def refresh(work,previous):
 converter=work/'converter'
 run(['git','clone','--quiet','https://github.com/AdguardTeam/SafariConverterLib.git',str(converter)])
 run(['git','checkout','--quiet','--detach',PIN],cwd=converter)
 run(['swift','build','-c','release','--product','ConverterTool','--force-resolved-versions'],cwd=converter)
 local=json.loads((HERE/'local-rules.json').read_text())
 extras={'ads':[],'privacy':[],'annoyances':[]}
 terms=('analytics','googletagmanager','hotjar','mixpanel','segment','clarity','scorecard','facebook','fullstory','amplitude')
 for rule in local:
  kind='annoyances' if rule['action']['type']=='css-display-none' else ('privacy' if any(t in rule['trigger']['url-filter'].lower() for t in terms) else 'ads')
  extras[kind].append(rule)
 baseline={p['id']:p for p in (previous or {}).get('packs',[])}
 packs=[]
 for pack_id,(name,url,author,source_license) in SOURCES.items():
  rawfile=work/(pack_id+'.txt')
  run(['curl','--fail','--location','--retry','3','--connect-timeout','20','--max-time','90','--output',str(rawfile),url])
  raw=rawfile.read_bytes();text=raw.decode('utf-8-sig')
  expected=('creativecommons.org/licenses/by/3.0' if source_license=='CC-BY-3.0' else 'creativecommons.org/licenses/by-sa/3.0')
  if not text.startswith('[Adblock Plus') or not any(x in text[:6000] for x in (expected,'easylist.to/pages/licence.html')):raise ValueError('Review format or license change: '+pack_id)
  result=json.loads(subprocess.check_output([str(converter/'.build/release/ConverterTool'),'convert','--input-path',str(rawfile),'--safari-version','17','--advanced-blocking','true']))
  if result['discardedSafariRules']:raise ValueError('Native capacity exceeded: '+pack_id)
  if pack_id in baseline and result['errorsCount']>baseline[pack_id]['conversionErrors']:raise ValueError('New conversion errors require review: '+pack_id)
  rules=extras.get(pack_id,[])+json.loads(result['safariRulesJSON'])
  if not 0<len(rules)<149000:raise ValueError('Invalid count: '+pack_id)
  data=encode(rules);(work/(pack_id+'.json')).write_bytes(data)
  modified=next((s.split(': ',1)[1] for s in text.splitlines()[:25] if s.startswith('! Last modified: ')),'')
  packs.append({'id':pack_id,'name':name,'author':author,'sourceURL':url,'sourceSHA256':sha(raw),'modified':modified,
    'file':pack_id+'.json','sha256':sha(data),'bytes':len(data),'ruleCount':len(rules),'license':'CC-BY-SA-3.0',
    'sourceLicense':source_license,'advancedRulesExcluded':result['advancedRulesCount'],'conversionErrors':result['errorsCount']})
 version=sha(encode(packs))[:20]
 return {'formatVersion':1,'version':version,'generation':int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
  'converter':'SafariConverterLib 4.3.1 / Safari 17','license':'CC-BY-SA-3.0','packs':packs}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--key',type=pathlib.Path,required=True);p.add_argument('--from-bundle',type=pathlib.Path);a=p.parse_args()
 if not a.key.is_file():raise ValueError('Signing key is required; never generate a replacement implicitly')
 previous=old_manifest(a.output)
 with tempfile.TemporaryDirectory(prefix='veil-rule-publish-') as temp:
  work=pathlib.Path(temp)
  verifier=work/'verify';signer=work/'sign'
  run(['xcrun','swiftc','-parse-as-library',str(HERE/'VerifyRules.swift'),'-o',str(verifier)])
  run(['xcrun','swiftc','-parse-as-library',str(HERE/'SignRulePackage.swift'),'-o',str(signer)])
  if a.from_bundle:
   candidate=json.loads((a.from_bundle/'manifest.json').read_text())
   for pack in candidate['packs']:shutil.copyfile(a.from_bundle/pack['file'],work/pack['file'])
  else:candidate=refresh(work,previous)
  if previous and candidate['version']==previous['version']:
   print('No rule changes');return
  if previous and candidate['generation']<=previous['generation']:raise ValueError('Refusing manifest rollback')
  if set(p['id'] for p in candidate['packs'])!=set(SOURCES) or len(candidate['packs'])!=6:raise ValueError('Missing or duplicate packs')
  for pack in candidate['packs']:
   if pack['file']!=pack['id']+'.json':raise ValueError('Invalid path')
   data=(work/pack['file']).read_bytes()
   if len(data)!=pack['bytes'] or sha(data)!=pack['sha256'] or len(json.loads(data))!=pack['ruleCount']:raise ValueError('Bad pack data')
   run([str(verifier),str(work/pack['file'])])
  plain=work/'package-manifest.json';plain.write_bytes(encode(candidate))
  signed=work/'manifest.json'
  output=subprocess.check_output([str(signer),str(plain),str(a.key.resolve()),str(signed)],text=True)
  if 'Public key: '+PUBLIC_KEY not in output:raise ValueError('Signing key does not match the app trust anchor')
  version_path=a.output/candidate['version'];version_path.mkdir(parents=True,exist_ok=True)
  for pack in candidate['packs']:shutil.copyfile(work/pack['file'],version_path/pack['file'])
  shutil.copyfile(plain,version_path/'package-manifest.json')
  temporary=a.output/'manifest.json.tmp';shutil.copyfile(signed,temporary);temporary.replace(a.output/'manifest.json')
  print('Published verified candidate locally:',candidate['version'])
if __name__=='__main__':main()
