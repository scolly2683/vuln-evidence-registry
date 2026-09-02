import json, re
d = json.load(open('kev.json'))['vulnerabilities']
d.sort(key=lambda x: x['dateAdded'], reverse=True)

def pick(stratum, rules, n):
    out, seen = [], set()
    for rule in rules:
        label, vend, prod = rule[:3]; pin = rule[3] if len(rule) > 3 else None
        for x in d:
            if pin and x['cveID'] != pin: continue
            if prod.endswith('Windows$') and int(x['cveID'][4:8]) < 2020: continue
            if re.search(vend, x['vendorProject'], re.I) and re.search(prod, x['product'], re.I) and x['cveID'] not in seen:
                x = dict(x, stratum=stratum, slot=label); out.append(x); seen.add(x['cveID']); break
        if len(out) >= n: break
    return out[:n]

edge = pick('edge', [
 ('fortios','Fortinet','FortiOS$'), ('fortios-2','Fortinet','FortiOS$'),
 ('panos','Palo Alto','PAN-OS'), ('panos-2','Palo Alto','PAN-OS'),
 ('ivanti-ics','Ivanti','Connect Secure'), ('ivanti-epmm','Ivanti','EPMM'),
 ('citrix','Citrix','NetScaler'), ('citrix-2','Citrix','NetScaler'),
 ('cisco-asa','Cisco','ASA'), ('cisco-iosxe','Cisco','IOS and IOS XE'),
 ('juniper','Juniper','Junos'), ('sonicwall','SonicWall','.'),
 ('f5','F5','BIG-IP'), ('exchange','Microsoft','Exchange Server'),
 ('zimbra','Synacor','Zimbra'), ('manageengine','Zoho','ManageEngine'),
 ('sap','SAP','NetWeaver'), ('coldfusion','Adobe','ColdFusion'),
 ('weblogic','Oracle','WebLogic'), ('vcenter','VMware','vCenter'),
 ('moveit','Progress','MOVEit'), ('confluence','Atlassian','Confluence'),
], 20)

ms = pick('microsoft', [
 ('win-smb','Microsoft','^Windows$'), ('office','Microsoft','^Office$'),
 ('sharepoint','Microsoft','SharePoint'), ('win32k','Microsoft','Win32k'),
 ('defender','Microsoft','Defender'), ('outlook','Microsoft','Outlook'),
 ('hyperv','Microsoft','Hyper-V'), ('spooler','Microsoft','Print Spooler|Windows Print'),
 ('mshtml','Microsoft','MSHTML|Internet Explorer'), ('word','Microsoft','Word'),
 ('excel','Microsoft','Excel'), ('sql','Microsoft','SQL Server'),
 ('ntlm','Microsoft','Windows$'), ('kerberos','Microsoft','Windows$'), ('edge','Microsoft','Edge'),
 ('access','Microsoft','Access'),
], 15)
# the three '^Windows$' slots will collide on dedupe; backfill with next-most-recent Windows entries
have = {x['cveID'] for x in ms}
for x in d:
    if len(ms) >= 15: break
    if x['vendorProject']=='Microsoft' and x['product']=='Windows' and int(x['cveID'][4:8])>=2020 and x['cveID'] not in have:
        ms.append(dict(x, stratum='microsoft', slot='win-fill')); have.add(x['cveID'])

oss = pick('oss', [
 ('log4j','Apache','Log4j2','CVE-2021-44228'), ('kernel','Linux','Kernel'), ('kernel-2','Linux','Kernel'),
 ('tomcat','Apache','Tomcat'), ('struts','Apache','Struts','CVE-2017-5638'), ('httpd','Apache','HTTP Server'),
 ('activemq','Apache','ActiveMQ'), ('ofbiz','Apache','OFBiz'), ('spring','VMware|Spring','Spring'),
 ('jenkins','Jenkins','.'), ('langflow','Langflow','.'), ('php','PHP','.'),
 ('gitlab','GitLab','.'), ('openssh','OpenBSD|OpenSSH','OpenSSH'), ('roundcube','Roundcube','.'),
 ('nextjs','Vercel','Next'), ('django','Django','.'), ('grafana','Grafana','.'), ('git','Git','^Git$'),
], 15)

all50 = edge + ms + oss
# Log4Shell is the calibration example in the prompt — keep it in explicitly as a control record
for s,xs in (('edge',edge),('microsoft',ms),('oss',oss)):
    print(f'== {s} ({len(xs)})')
    for x in xs: print(f"  {x['cveID']:<16} {x['dateAdded']}  {x['vendorProject']} / {x['product']}  [{x['slot']}]")
print('TOTAL', len(all50), 'unique', len({x['cveID'] for x in all50}))
json.dump(all50, open('kev_sample.json','w'), indent=1)
