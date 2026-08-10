--------------------------------------------------------------------------------
-- Fix-channel routing for Oracle — paste-and-run.
--
-- Gives your Power BI report the columns it is missing today:
--     ROUTING_STATUS  ROUTED | UNROUTED | SUPPRESSED   ("is it real / do we act")
--     CHANNEL_ID / CHANNEL_NAME / OWNER_GROUP          ("who fixes this")
--     SLA_DAYS / DUE_DATE / OVERDUE_FLAG               ("by when / is it late")
--
-- Point Power BI at VM_FINDING_ROUTED and you are done. Analysts never touch
-- this file: they add technology rules through the HTML triage tool, which
-- emits INSERT statements you paste into section 3.
--------------------------------------------------------------------------------

--==============================================================================
-- 0. PLACEHOLDERS — change these to your real objects, then run top to bottom.
--==============================================================================
--   VM_FINDINGS        your scanner findings table (Qualys + Wiz + GitHub)
--   FINDING_ID         unique row id
--   CVE_ID             'CVE-2021-44228'
--   ASSET_ID           host / image / repo identifier
--   VENDOR             'Microsoft'            (NULL is fine)
--   PRODUCT            'Windows Server 2019'  (NULL is fine)
--   DESCRIPTION        detection title/summary (NULL is fine)
--   PURL               'pkg:maven/...'        (NULL is fine — GitHub/SCA only)
--   DETECTION_ID       Qualys QID as text     (NULL is fine)
--   FIRST_SEEN         DATE the finding first appeared
--   SEVERITY           your severity column
--   SOURCE             'QUALYS' | 'WIZ' | 'GITHUB'
--   ZONE               'DMZ' when internet-facing (drives the 7-day SLA)
--
-- If a column does not exist, replace it below with NULL — e.g. use
-- CAST(NULL AS VARCHAR2(200)) AS PURL. Nothing breaks.
--==============================================================================


--==============================================================================
-- 1. TABLES
--==============================================================================

CREATE TABLE VM_CHANNEL (
  CHANNEL_ID     VARCHAR2(40)  NOT NULL PRIMARY KEY,
  CHANNEL_NAME   VARCHAR2(100) NOT NULL,
  OWNER_GROUP    VARCHAR2(100),
  CADENCE        VARCHAR2(200),
  SLA_DAYS       NUMBER(4)     DEFAULT 30 NOT NULL,
  DMZ_SLA_DAYS   NUMBER(4)     DEFAULT 7  NOT NULL
);

CREATE TABLE VM_ROUTING_RULE (
  RULE_ID      VARCHAR2(60)  NOT NULL PRIMARY KEY,
  PRIORITY     NUMBER(4)     DEFAULT 100 NOT NULL,  -- lower wins
  MATCH_TYPE   VARCHAR2(12)  NOT NULL,              -- VENDOR|KEYWORD|PURL_PREFIX|CVE|QID
  MATCH_VALUE  VARCHAR2(200) NOT NULL,
  CHANNEL_ID   VARCHAR2(40)  NOT NULL REFERENCES VM_CHANNEL(CHANNEL_ID),
  NOTE         VARCHAR2(500),
  ACTIVE_FLAG  CHAR(1)       DEFAULT 'Y' NOT NULL,
  CREATED_BY   VARCHAR2(60),
  CREATED_ON   DATE          DEFAULT SYSDATE
);
CREATE INDEX IX_VM_RULE_ACTIVE ON VM_ROUTING_RULE (ACTIVE_FLAG, PRIORITY, RULE_ID);

-- A suppression is a LEASE: it must carry evidence and an expiry. When
-- REVIEW_BY passes the finding stops being suppressed and comes back.
CREATE TABLE VM_SUPPRESSION (
  SUPPRESSION_ID VARCHAR2(60)   NOT NULL PRIMARY KEY,
  MATCH_TYPE     VARCHAR2(12)   NOT NULL,          -- CVE | QID
  MATCH_VALUE    VARCHAR2(200)  NOT NULL,
  VERDICT        VARCHAR2(24)   NOT NULL,          -- FALSE_POSITIVE|NOT_APPLICABLE|RISK_ACCEPTED
  EVIDENCE       VARCHAR2(1000) NOT NULL,
  REVIEW_BY      DATE           NOT NULL,
  CREATED_BY     VARCHAR2(60),
  CREATED_ON     DATE           DEFAULT SYSDATE
);


--==============================================================================
-- 2. CHANNELS — the new set. Edit OWNER_GROUP / SLA to match your org.
--==============================================================================
INSERT ALL
  INTO VM_CHANNEL VALUES ('windows-endpoint','Windows endpoints (EUC)','EUC team','Patch Tuesday + 5 days',5,5)
  INTO VM_CHANNEL VALUES ('windows-server-onprem','On-prem Windows servers','Windows server team','Patch Tuesday + 30 days',30,7)
  INTO VM_CHANNEL VALUES ('euc-central-bundle','EUC central bundle','EUC team','Monthly central push',30,7)
  INTO VM_CHANNEL VALUES ('euc-user-installed','EUC user-installed (not bundled)','Per-exception owner','Ad hoc',30,7)
  INTO VM_CHANNEL VALUES ('mac-endpoint','Mac endpoints','Jamf team','Apple releases + MDM window',14,7)
  INTO VM_CHANNEL VALUES ('mobile-ios','iOS / iPadOS fleet','Mobile platform ops','Apple releases',14,7)
  INTO VM_CHANNEL VALUES ('linux-onprem','On-prem Linux','Linux team','Continuous vendor errata',30,7)
  INTO VM_CHANNEL VALUES ('k8s-image','Container base images','Cloud image team','Base-image rebuild cycle',30,7)
  INTO VM_CHANNEL VALUES ('ami-rehydrate','EC2 AMI rebuilds','Cloud team','AMI rebuild cycle',30,7)
  INTO VM_CHANNEL VALUES ('build-dependency','App dependencies (CI)','Repo owner (per app)','Continuous dependency PRs',30,7)
  INTO VM_CHANNEL VALUES ('internal-app','Internally-operated apps','App team (per app)','Ad hoc',30,7)
  INTO VM_CHANNEL VALUES ('middleware','Middleware (host-installed)','App / hosting team','Ad hoc',30,7)
  INTO VM_CHANNEL VALUES ('database','Database servers','DBA team','Ad hoc',30,7)
  INTO VM_CHANNEL VALUES ('network','Network appliances','Network engineering','Vendor advisories',30,7)
  INTO VM_CHANNEL VALUES ('virtualisation','Virtualisation platforms','Platform / infra','Vendor advisories',30,7)
  INTO VM_CHANNEL VALUES ('oracle-cpu','Oracle Critical Patch Update','Oracle platform team','Quarterly CPU',90,7)
  INTO VM_CHANNEL VALUES ('vendor-product','Enterprise vendor products','Vendor product owner','Vendor patch programme',30,7)
  INTO VM_CHANNEL VALUES ('cloud-managed','Cloud-managed services','Cloud team','Provider-patched',30,7)
SELECT * FROM DUAL;


--==============================================================================
-- 3. TECHNOLOGY RULES — first match wins (lowest PRIORITY first).
--    This is the section that grows: analysts send you INSERTs from the tool.
--==============================================================================
INSERT ALL
  -- 10: vendor claims everything it publishes
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-oracle',10,'VENDOR','oracle','oracle-cpu','WebLogic/MySQL/Java ride the quarterly CPU')
  -- 20-25: operating systems and product carve-outs
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-exchange',20,'KEYWORD','exchange server','windows-server-onprem','Server product, not the EUC bundle')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-sharepoint',20,'KEYWORD','sharepoint','windows-server-onprem','Bundle does not package SharePoint')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-iis',20,'KEYWORD','internet information services','windows-server-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-win-server',25,'KEYWORD','windows server','windows-server-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-windows',30,'KEYWORD','windows','windows-endpoint','Endpoint default; server rules above win')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-ios',25,'KEYWORD','ios','mobile-ios','Mobile platform ops, not Jamf')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-ipados',25,'KEYWORD','ipados','mobile-ios',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-macos',30,'KEYWORD','macos','mac-endpoint',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-apple',35,'VENDOR','apple','mac-endpoint',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-kernel',20,'KEYWORD','linux kernel','linux-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-rhel',25,'VENDOR','red hat','linux-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-ubuntu',25,'VENDOR','canonical','linux-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-suse',25,'VENDOR','suse','linux-onprem',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-debian',25,'VENDOR','debian','linux-onprem',NULL)
  -- 30: end-user computing
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-office',30,'KEYWORD','office','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-outlook',30,'KEYWORD','outlook','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-teams',30,'KEYWORD','teams','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-edge',30,'KEYWORD','edge','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-chrome',30,'KEYWORD','chrome','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-firefox',30,'KEYWORD','firefox','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-acrobat',30,'KEYWORD','acrobat','euc-central-bundle',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-vstudio',28,'KEYWORD','visual studio','euc-user-installed','Not in the central bundle')
  -- 40-45: build / dependency
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-purl-npm',40,'PURL_PREFIX','pkg:npm/','build-dependency',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-purl-maven',40,'PURL_PREFIX','pkg:maven/','build-dependency',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-purl-pypi',40,'PURL_PREFIX','pkg:pypi/','build-dependency',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-purl-nuget',40,'PURL_PREFIX','pkg:nuget/','build-dependency',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-purl-golang',40,'PURL_PREFIX','pkg:golang/','build-dependency',NULL)
  -- 50: infrastructure classes
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-netscaler',45,'KEYWORD','netscaler','network','Citrix ADC is a network appliance')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-tomcat',50,'KEYWORD','tomcat','middleware',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-nginx',50,'KEYWORD','nginx','middleware',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-apache-httpd',50,'KEYWORD','httpd','middleware',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-jboss',50,'KEYWORD','jboss','middleware',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-sqlserver',50,'KEYWORD','sql server','database',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-postgres',50,'KEYWORD','postgresql','database',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-mongodb',50,'KEYWORD','mongodb','database',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-cisco',50,'VENDOR','cisco','network',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-fortinet',50,'VENDOR','fortinet','network',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-paloalto',50,'VENDOR','palo alto','network',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-vmware',50,'VENDOR','vmware','virtualisation',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-citrix',52,'VENDOR','citrix','virtualisation','NetScaler rule above wins')
  -- 65-70: internal apps and named vendors
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-jenkins',65,'KEYWORD','jenkins','internal-app','Run by an internal app team')
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-sap',70,'VENDOR','sap','vendor-product',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-atlassian',70,'VENDOR','atlassian','vendor-product',NULL)
  INTO VM_ROUTING_RULE (RULE_ID,PRIORITY,MATCH_TYPE,MATCH_VALUE,CHANNEL_ID,NOTE) VALUES ('r-ibm',70,'VENDOR','ibm','vendor-product',NULL)
SELECT * FROM DUAL;

COMMIT;


--==============================================================================
-- 4. THE VIEW — point Power BI here.
--==============================================================================
CREATE OR REPLACE VIEW VM_FINDING_ROUTED AS
WITH f AS (
  SELECT
      FINDING_ID, CVE_ID, ASSET_ID, VENDOR, PRODUCT, SEVERITY, SOURCE, ZONE,
      FIRST_SEEN,
      UPPER(NVL(VENDOR,'~'))                                     AS V_UP,
      UPPER(NVL(PRODUCT,' ') || ' ' || NVL(DESCRIPTION,' '))     AS TXT_UP,
      UPPER(NVL(CVE_ID,'~'))                                     AS CVE_UP,
      NVL(TO_CHAR(DETECTION_ID),'~')                             AS QID_TXT,
      UPPER(NVL(PURL,'~'))                                       AS PURL_UP
  FROM VM_FINDINGS                                    -- <<< PLACEHOLDER
),
sup AS (   -- active suppressions only: an expired lease stops silencing
  SELECT DISTINCT f.FINDING_ID, s.SUPPRESSION_ID, s.VERDICT
  FROM f
  JOIN VM_SUPPRESSION s
    ON (   (s.MATCH_TYPE = 'CVE' AND UPPER(s.MATCH_VALUE) = f.CVE_UP)
        OR (s.MATCH_TYPE = 'QID' AND s.MATCH_VALUE       = f.QID_TXT) )
   AND s.REVIEW_BY >= TRUNC(SYSDATE)
),
m AS (     -- every rule that matches, ranked; first match wins
  SELECT f.FINDING_ID, r.RULE_ID, r.CHANNEL_ID,
         ROW_NUMBER() OVER (PARTITION BY f.FINDING_ID
                            ORDER BY r.PRIORITY, r.RULE_ID) AS RN
  FROM f
  JOIN VM_ROUTING_RULE r
    ON r.ACTIVE_FLAG = 'Y'
   AND (   (r.MATCH_TYPE = 'VENDOR'      AND INSTR(f.V_UP,   UPPER(r.MATCH_VALUE)) > 0)
        OR (r.MATCH_TYPE = 'KEYWORD'     AND INSTR(f.TXT_UP, UPPER(r.MATCH_VALUE)) > 0)
        OR (r.MATCH_TYPE = 'PURL_PREFIX' AND f.PURL_UP LIKE UPPER(r.MATCH_VALUE) || '%')
        OR (r.MATCH_TYPE = 'CVE'         AND f.CVE_UP  = UPPER(r.MATCH_VALUE))
        OR (r.MATCH_TYPE = 'QID'         AND f.QID_TXT = r.MATCH_VALUE) )
),
base AS (
  SELECT f.FINDING_ID, f.CVE_ID, f.ASSET_ID, f.VENDOR, f.PRODUCT,
         f.SEVERITY, f.SOURCE, f.ZONE, f.FIRST_SEEN,
         m.RULE_ID, m.CHANNEL_ID, c.CHANNEL_NAME, c.OWNER_GROUP, c.CADENCE,
         sup.SUPPRESSION_ID, sup.VERDICT,
         CASE WHEN UPPER(NVL(f.ZONE,'X')) = 'DMZ'
              THEN c.DMZ_SLA_DAYS ELSE c.SLA_DAYS END AS SLA_DAYS
  FROM f
  LEFT JOIN m   ON m.FINDING_ID = f.FINDING_ID AND m.RN = 1
  LEFT JOIN VM_CHANNEL c ON c.CHANNEL_ID = m.CHANNEL_ID
  LEFT JOIN sup ON sup.FINDING_ID = f.FINDING_ID
)
SELECT
    FINDING_ID, CVE_ID, ASSET_ID, VENDOR, PRODUCT, SEVERITY, SOURCE, ZONE,
    FIRST_SEEN,
    CASE WHEN SUPPRESSION_ID IS NOT NULL THEN 'SUPPRESSED'
         WHEN CHANNEL_ID     IS NULL     THEN 'UNROUTED'
         ELSE 'ROUTED' END                       AS ROUTING_STATUS,
    CHANNEL_ID, CHANNEL_NAME, OWNER_GROUP, CADENCE,
    RULE_ID                                      AS DECIDED_BY_RULE,
    VERDICT                                      AS SUPPRESSION_VERDICT,
    SLA_DAYS,
    FIRST_SEEN + SLA_DAYS                        AS DUE_DATE,
    TRUNC(SYSDATE) - TRUNC(FIRST_SEEN)           AS AGE_DAYS,
    CASE WHEN SUPPRESSION_ID IS NULL
          AND CHANNEL_ID IS NOT NULL
          AND TRUNC(SYSDATE) > FIRST_SEEN + SLA_DAYS
         THEN 'Y' ELSE 'N' END                   AS OVERDUE_FLAG
FROM base;


--==============================================================================
-- 5. USEFUL QUERIES
--==============================================================================
-- The analyst queue: what no rule knows yet, biggest groups first.
--   SELECT VENDOR, PRODUCT, COUNT(*) CNT, COUNT(DISTINCT CVE_ID) CVES
--   FROM VM_FINDING_ROUTED WHERE ROUTING_STATUS='UNROUTED'
--   GROUP BY VENDOR, PRODUCT ORDER BY CNT DESC;
--
-- Health metric to chart over time: % unrouted.
--   SELECT ROUND(100*SUM(CASE WHEN ROUTING_STATUS='UNROUTED' THEN 1 ELSE 0 END)/COUNT(*),1)
--   FROM VM_FINDING_ROUTED;
--
-- Suppressions due for re-verification (the monthly hygiene sweep).
--   SELECT * FROM VM_SUPPRESSION WHERE REVIEW_BY <= TRUNC(SYSDATE)+30 ORDER BY REVIEW_BY;
