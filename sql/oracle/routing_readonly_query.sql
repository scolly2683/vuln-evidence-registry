--------------------------------------------------------------------------------
-- READ-ONLY routing query — no CREATE, no INSERT, no privileges needed.
--
-- The channel and rule tables are inlined as CTEs, so this is just a SELECT.
-- Paste the whole thing into Power BI:
--     Get Data > Oracle database > server/service > Advanced options
--     > SQL statement  (paste)  > Import
--
-- It returns your findings with the columns the report is missing:
--     ROUTING_STATUS   ROUTED | UNROUTED      ("do we act, and is it known")
--     CHANNEL_NAME / OWNER_GROUP              ("who fixes this")
--     SLA_DAYS / DUE_DATE / OVERDUE_FLAG      ("by when / is it late")
--     DECIDED_BY_RULE                         ("why it went there")
--
-- To add a technology rule: paste one more UNION ALL line into the RL block.
-- The analyst workbench (tools/analyst-triage-tool.html) generates those
-- lines for you — "Copy query rows".
--------------------------------------------------------------------------------
-- PLACEHOLDERS — change to your objects, then run.
--   VM_FINDINGS  FINDING_ID CVE_ID ASSET_ID VENDOR PRODUCT DESCRIPTION
--                PURL DETECTION_ID FIRST_SEEN SEVERITY SOURCE ZONE
--   Missing a column? Replace it with NULL in the F block. Nothing breaks.
--------------------------------------------------------------------------------

WITH ch AS (   -- fix channels: owner + SLA. Edit owners to match your org.
            SELECT 'windows-endpoint'      AS channel_id,'Windows endpoints (EUC)'         AS channel_name,'EUC team'              AS owner_group, 5 AS sla_days, 5 AS dmz_days FROM DUAL
  UNION ALL SELECT 'windows-server-onprem','On-prem Windows servers'         ,'Windows server team'   ,30, 7 FROM DUAL
  UNION ALL SELECT 'euc-central-bundle'   ,'EUC central bundle'              ,'EUC team'              ,30, 7 FROM DUAL
  UNION ALL SELECT 'euc-user-installed'   ,'EUC user-installed (not bundled)','Per-exception owner'   ,30, 7 FROM DUAL
  UNION ALL SELECT 'mac-endpoint'         ,'Mac endpoints'                   ,'Jamf team'             ,14, 7 FROM DUAL
  UNION ALL SELECT 'mobile-ios'           ,'iOS / iPadOS fleet'              ,'Mobile platform ops'   ,14, 7 FROM DUAL
  UNION ALL SELECT 'linux-onprem'         ,'On-prem Linux'                   ,'Linux team'            ,30, 7 FROM DUAL
  UNION ALL SELECT 'k8s-image'            ,'Container base images'           ,'Cloud image team'      ,30, 7 FROM DUAL
  UNION ALL SELECT 'ami-rehydrate'        ,'EC2 AMI rebuilds'                ,'Cloud team'            ,30, 7 FROM DUAL
  UNION ALL SELECT 'build-dependency'     ,'App dependencies (CI)'           ,'Repo owner (per app)'  ,30, 7 FROM DUAL
  UNION ALL SELECT 'internal-app'         ,'Internally-operated apps'        ,'App team (per app)'    ,30, 7 FROM DUAL
  UNION ALL SELECT 'middleware'           ,'Middleware (host-installed)'     ,'App / hosting team'    ,30, 7 FROM DUAL
  UNION ALL SELECT 'database'             ,'Database servers'                ,'DBA team'              ,30, 7 FROM DUAL
  UNION ALL SELECT 'network'              ,'Network appliances'              ,'Network engineering'   ,30, 7 FROM DUAL
  UNION ALL SELECT 'virtualisation'       ,'Virtualisation platforms'        ,'Platform / infra'      ,30, 7 FROM DUAL
  UNION ALL SELECT 'oracle-cpu'           ,'Oracle Critical Patch Update'    ,'Oracle platform team'  ,90, 7 FROM DUAL
  UNION ALL SELECT 'vendor-product'       ,'Enterprise vendor products'      ,'Vendor product owner'  ,30, 7 FROM DUAL
  UNION ALL SELECT 'cloud-managed'        ,'Cloud-managed services'          ,'Cloud team'            ,30, 7 FROM DUAL
),
rl AS (  -- technology rules: lowest priority number wins. ADD LINES HERE.
            SELECT 'r-oracle'      AS rule_id, 10 AS priority,'VENDOR'      AS match_type,'oracle'                        AS match_value,'oracle-cpu'            AS channel_id FROM DUAL
  UNION ALL SELECT 'r-exchange'    ,20,'KEYWORD'    ,'exchange server'              ,'windows-server-onprem' FROM DUAL
  UNION ALL SELECT 'r-sharepoint'  ,20,'KEYWORD'    ,'sharepoint'                   ,'windows-server-onprem' FROM DUAL
  UNION ALL SELECT 'r-iis'         ,20,'KEYWORD'    ,'internet information services','windows-server-onprem' FROM DUAL
  UNION ALL SELECT 'r-win-server'  ,25,'KEYWORD'    ,'windows server'               ,'windows-server-onprem' FROM DUAL
  UNION ALL SELECT 'r-windows'     ,30,'KEYWORD'    ,'windows'                      ,'windows-endpoint'      FROM DUAL
  UNION ALL SELECT 'r-ios'         ,25,'KEYWORD'    ,'ios '                         ,'mobile-ios'            FROM DUAL
  UNION ALL SELECT 'r-ipados'      ,25,'KEYWORD'    ,'ipados'                       ,'mobile-ios'            FROM DUAL
  UNION ALL SELECT 'r-macos'       ,30,'KEYWORD'    ,'macos'                        ,'mac-endpoint'          FROM DUAL
  UNION ALL SELECT 'r-apple'       ,35,'VENDOR'     ,'apple'                        ,'mac-endpoint'          FROM DUAL
  UNION ALL SELECT 'r-kernel'      ,20,'KEYWORD'    ,'linux kernel'                 ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-rhel'        ,25,'VENDOR'     ,'red hat'                      ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-ubuntu'      ,25,'VENDOR'     ,'canonical'                    ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-ubuntu2'     ,25,'VENDOR'     ,'ubuntu'                       ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-suse'        ,25,'VENDOR'     ,'suse'                         ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-debian'      ,25,'VENDOR'     ,'debian'                       ,'linux-onprem'          FROM DUAL
  UNION ALL SELECT 'r-office'      ,30,'KEYWORD'    ,'office'                       ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-outlook'     ,30,'KEYWORD'    ,'outlook'                      ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-teams'       ,30,'KEYWORD'    ,'teams'                        ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-edge'        ,30,'KEYWORD'    ,'edge'                         ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-chrome'      ,30,'KEYWORD'    ,'chrome'                       ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-firefox'     ,30,'KEYWORD'    ,'firefox'                      ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-acrobat'     ,30,'KEYWORD'    ,'acrobat'                      ,'euc-central-bundle'    FROM DUAL
  UNION ALL SELECT 'r-vstudio'     ,28,'KEYWORD'    ,'visual studio'                ,'euc-user-installed'    FROM DUAL
  UNION ALL SELECT 'r-purl-npm'    ,40,'PURL_PREFIX','pkg:npm/'                     ,'build-dependency'      FROM DUAL
  UNION ALL SELECT 'r-purl-maven'  ,40,'PURL_PREFIX','pkg:maven/'                   ,'build-dependency'      FROM DUAL
  UNION ALL SELECT 'r-purl-pypi'   ,40,'PURL_PREFIX','pkg:pypi/'                    ,'build-dependency'      FROM DUAL
  UNION ALL SELECT 'r-purl-nuget'  ,40,'PURL_PREFIX','pkg:nuget/'                   ,'build-dependency'      FROM DUAL
  UNION ALL SELECT 'r-purl-golang' ,40,'PURL_PREFIX','pkg:golang/'                  ,'build-dependency'      FROM DUAL
  UNION ALL SELECT 'r-netscaler'   ,45,'KEYWORD'    ,'netscaler'                    ,'network'               FROM DUAL
  UNION ALL SELECT 'r-tomcat'      ,50,'KEYWORD'    ,'tomcat'                       ,'middleware'            FROM DUAL
  UNION ALL SELECT 'r-nginx'       ,50,'KEYWORD'    ,'nginx'                        ,'middleware'            FROM DUAL
  UNION ALL SELECT 'r-httpd'       ,50,'KEYWORD'    ,'httpd'                        ,'middleware'            FROM DUAL
  UNION ALL SELECT 'r-jboss'       ,50,'KEYWORD'    ,'jboss'                        ,'middleware'            FROM DUAL
  UNION ALL SELECT 'r-sqlserver'   ,50,'KEYWORD'    ,'sql server'                   ,'database'              FROM DUAL
  UNION ALL SELECT 'r-postgres'    ,50,'KEYWORD'    ,'postgresql'                   ,'database'              FROM DUAL
  UNION ALL SELECT 'r-mongodb'     ,50,'KEYWORD'    ,'mongodb'                      ,'database'              FROM DUAL
  UNION ALL SELECT 'r-cisco'       ,50,'VENDOR'     ,'cisco'                        ,'network'               FROM DUAL
  UNION ALL SELECT 'r-fortinet'    ,50,'VENDOR'     ,'fortinet'                     ,'network'               FROM DUAL
  UNION ALL SELECT 'r-paloalto'    ,50,'VENDOR'     ,'palo alto'                    ,'network'               FROM DUAL
  UNION ALL SELECT 'r-vmware'      ,50,'VENDOR'     ,'vmware'                       ,'virtualisation'        FROM DUAL
  UNION ALL SELECT 'r-citrix'      ,52,'VENDOR'     ,'citrix'                       ,'virtualisation'        FROM DUAL
  UNION ALL SELECT 'r-jenkins'     ,65,'KEYWORD'    ,'jenkins'                      ,'internal-app'          FROM DUAL
  UNION ALL SELECT 'r-sap'         ,70,'VENDOR'     ,'sap'                          ,'vendor-product'        FROM DUAL
  UNION ALL SELECT 'r-atlassian'   ,70,'VENDOR'     ,'atlassian'                    ,'vendor-product'        FROM DUAL
  UNION ALL SELECT 'r-ibm'         ,70,'VENDOR'     ,'ibm'                          ,'vendor-product'        FROM DUAL
  -- >>> ADD ANALYST RULES BELOW THIS LINE <<<
),
sup AS (  -- SUPPRESSIONS: verdicts analysts have recorded (false positive /
          -- not applicable / risk accepted). Every one carries an expiry —
          -- once REVIEW_BY passes, the finding automatically comes back.
          -- The seed row below contributes nothing (WHERE 1=0); it only fixes
          -- the column names and types so the block works when empty.
            SELECT 'CVE' AS match_type,'CVE-0000-00000' AS match_value,
                   'FALSE_POSITIVE' AS verdict, DATE '2099-01-01' AS review_by
              FROM DUAL WHERE 1=0
  -- >>> ADD ANALYST SUPPRESSIONS BELOW THIS LINE <<<
),
f AS (
  SELECT
      FINDING_ID, CVE_ID, ASSET_ID, VENDOR, PRODUCT, SEVERITY, SOURCE, ZONE, FIRST_SEEN,
      UPPER(NVL(VENDOR,'~'))                                 AS v_up,
      UPPER(NVL(PRODUCT,' ')||' '||NVL(DESCRIPTION,' '))     AS txt_up,
      UPPER(NVL(PURL,'~'))                                   AS purl_up,
      UPPER(NVL(CVE_ID,'~'))                                 AS cve_up,
      NVL(TO_CHAR(DETECTION_ID),'~')                         AS qid_txt
  FROM VM_FINDINGS                                  -- <<< PLACEHOLDER
  -- Keep the report fast: filter to what you actually report on, e.g.
  -- WHERE STATUS = 'OPEN' AND FIRST_SEEN >= ADD_MONTHS(TRUNC(SYSDATE),-12)
),
m AS (
  SELECT f.FINDING_ID, rl.rule_id, rl.channel_id,
         ROW_NUMBER() OVER (PARTITION BY f.FINDING_ID
                            ORDER BY rl.priority, rl.rule_id) AS rn
  FROM f
  JOIN rl ON (  (rl.match_type='VENDOR'      AND INSTR(f.v_up,   UPPER(rl.match_value))>0)
             OR (rl.match_type='KEYWORD'     AND INSTR(f.txt_up, UPPER(rl.match_value))>0)
             OR (rl.match_type='PURL_PREFIX' AND f.purl_up LIKE UPPER(rl.match_value)||'%') )
),
sm AS (   -- active suppressions only: an expired verdict stops suppressing
  SELECT DISTINCT f.FINDING_ID, sup.verdict
  FROM f
  JOIN sup ON (   (sup.match_type='CVE' AND f.cve_up  = UPPER(sup.match_value))
               OR (sup.match_type='QID' AND f.qid_txt = sup.match_value) )
   AND sup.review_by >= TRUNC(SYSDATE)
),
b AS (
  SELECT f.*, m.rule_id, m.channel_id, ch.channel_name, ch.owner_group, sm.verdict,
         CASE WHEN UPPER(NVL(f.ZONE,'X'))='DMZ' THEN ch.dmz_days ELSE ch.sla_days END AS sla_days
  FROM f
  LEFT JOIN m  ON m.FINDING_ID = f.FINDING_ID AND m.rn = 1
  LEFT JOIN ch ON ch.channel_id = m.channel_id
  LEFT JOIN sm ON sm.FINDING_ID = f.FINDING_ID
)
SELECT
    FINDING_ID, CVE_ID, ASSET_ID, VENDOR, PRODUCT, SEVERITY, SOURCE, ZONE, FIRST_SEEN,
    CASE WHEN verdict    IS NOT NULL THEN 'SUPPRESSED'
         WHEN channel_id IS NULL     THEN 'UNROUTED'
         ELSE 'ROUTED' END              AS ROUTING_STATUS,
    verdict                             AS SUPPRESSION_VERDICT,
    channel_id                          AS CHANNEL_ID,
    channel_name                        AS CHANNEL_NAME,
    owner_group                         AS OWNER_GROUP,
    rule_id                             AS DECIDED_BY_RULE,
    sla_days                            AS SLA_DAYS,
    FIRST_SEEN + sla_days               AS DUE_DATE,
    TRUNC(SYSDATE) - TRUNC(FIRST_SEEN)  AS AGE_DAYS,
    CASE WHEN verdict IS NULL
          AND channel_id IS NOT NULL
          AND TRUNC(SYSDATE) > FIRST_SEEN + sla_days
         THEN 'Y' ELSE 'N' END          AS OVERDUE_FLAG
FROM b
-- Tip: keep suppressed rows in the dataset and filter them out in Power BI,
-- so the suppression ledger and the "what did we silence and why" page work.
