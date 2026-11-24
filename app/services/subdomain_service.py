"""OWASP Sentinel - Subdomain Discovery & Reconnaissance Service

Provides non-destructive, unbounded subdomain enumeration via:
1. Multi-Engine Certificate Transparency (crt.sh, CertSpotter) & Passive DNS (HackerTarget, AlienVault, Anubis)
2. Authoritative DNS Protocol Mining (DoH TXT/SPF records, MX mail exchangers, NS nameservers, CNAME aliases)
3. Proactive Live Web & Header Harvesting (Content-Security-Policy, CORS, robots.txt, HTML hyperlinks)
4. Adaptive Target-Specific Vocabulary Mining (dynamically learning naming conventions from the target)
5. Unbounded Dynamic Mutation & Permutations (cross-product environment stems, numeric sequences, recursive child branches)
6. Zero-Packet-Loss Asynchronous DNS Resolution with Wildcard DNS Suppression
7. Real-Time Progressive Streaming & Live HTTP/HTTPS Service Verification
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import inspect
import json
import logging
import random
import re
import socket
import struct
import time
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.db.asset import AuthorizedAsset
from app.models.schemas.target import (
    DiscoveredSubdomain,
    SubdomainDiscoveryRequest,
    SubdomainDiscoveryResponse,
)

logger = logging.getLogger(__name__)

# Foundational enterprise dictionary covering cloud, dev/staging/qa, admin panels,
# auth/sso, apis, mail, cdn, smart city/iot, infrastructure, enterprise tools,
# and sectoral portals (provides the baseline foundation for dynamic unbounded probing)
BASE_ENTERPRISE_PREFIXES: tuple[str, ...] = (
    # 1. Standard Web & Portals
    "www", "www1", "www2", "www3", "www4", "www5", "web", "web1", "web2", "web3", "webmail", "site", "sites", "portal", "portals", "home",
    "index", "main", "online", "live", "pub", "public", "my", "app", "apps", "app1", "app2", "app3", "application",
    "platform", "hub", "space", "center", "central", "core", "core1", "base", "default", "start", "front", "frontend", "ui", "gui",
    "landing", "welcome", "entry", "gateway", "gw", "gw1", "gw2", "edge", "edge1", "edge2", "m", "mobile", "wap",

    # 2. Environments & Quality Assurance
    "dev", "dev1", "dev2", "dev3", "dev4", "dev5", "devel", "develop", "development", "developer", "developers", "dev-api", "dev-app", "dev-portal",
    "test", "test1", "test2", "test3", "test4", "testing", "tests", "test-api", "test-app", "qa", "qa1", "qa2", "qa3", "qa4", "qas", "qa-api", "qa-app",
    "uat", "uat1", "uat2", "uat3", "uat-api", "uat-app", "sit", "sit1", "sit2", "stage", "stage1", "stage2", "stage3", "staging", "staging1", "staging2", "staging3",
    "staging-api", "stg", "stg1", "stg2", "preprod", "pre-prod", "prod", "prod1", "prod2", "production", "live1", "live2",
    "sandbox", "sand", "lab", "labs", "preview", "preview1", "preview2", "demo", "demo1", "demo2", "demo3", "pilot", "poc", "trial",
    "beta", "beta1", "beta2", "alpha", "canary", "canary1", "dr", "failover", "backup", "backup1", "backup2", "backups", "bkup",
    "local", "local1", "env", "environment", "temp", "bak", "old", "new", "legacy", "v1", "v2", "v3", "v4",

    # 3. Admin, Management & Operations
    "admin", "admin1", "admin2", "admin3", "administrator", "admins", "adminportal", "adm", "root", "master",
    "manage", "management", "manager", "mgr", "console", "control", "controlpanel", "panel", "cp",
    "cpanel", "whm", "webmin", "directadmin", "plesk", "phpmyadmin", "pma", "pgadmin", "supervisor", "operator", "operations", "ops",
    "devops", "noc", "soc", "soc1", "soc2", "siem", "sysadmin", "system", "systems", "infrastructure", "infra", "gov", "governance",
    "cluster", "k8s", "kubernetes", "kube", "rancher", "portainer", "swarm", "docker", "registry", "harbor", "quay", "helm", "helm1",
    "argocd", "flux", "spinnaker", "citadel", "bastion", "jump", "jumphost",

    # 4. Auth, Identity, SSO & Security
    "auth", "auth1", "auth2", "authenticate", "authentication", "oauth", "oauth2", "sso", "sso2", "login", "login1", "login2",
    "signin", "sign-in", "logout", "register", "registration", "signup", "id", "id1", "id2", "idp", "identity", "iam",
    "accounts", "account", "profile", "user", "users", "member", "members", "client", "clients",
    "customer", "customers", "myaccount", "keycloak", "cas", "okta", "duo", "onelogin", "ping", "entra", "azuread",
    "saml", "openid", "token", "tokens", "session", "sessions", "verify", "verification", "2fa", "mfa",
    "pass", "password", "security", "sec", "sec-ops", "guard", "waf", "firewall", "fw", "vault", "secret", "secrets",
    "cert", "certs", "pki", "ssl", "tls", "vpn", "vpn1", "vpn2", "vpn3", "vpn-client", "openvpn", "openvpn1",
    "wireguard", "wireguard1", "wireguard2", "ipsec", "anyconnect", "pulse", "sslvpn", "remote", "access", "tunnel", "proxy", "proxy1", "proxy2", "proxy3", "reverse-proxy", "squid",
    "haproxy", "nginx", "apache", "ssh", "sftp", "ftp", "ftps", "ftp1", "ftp2", "vuln", "scanning", "pen", "pentest",
    "redteam", "blueteam", "compliance", "wazuh", "ossec", "crowdstrike", "sentinel", "defender",

    # 5. APIs, Microservices & Routing
    "api", "apis", "api1", "api2", "api3", "api4", "api-dev", "api-stage", "api-prod", "api-v1", "api-v2", "api-v3",
    "api-gateway", "apigateway", "apim", "apimanager", "apigee", "kong", "tyk", "envoy", "istio", "traefik",
    "graphql", "gql", "rest", "soap", "rpc", "grpc", "ws", "wss",
    "websocket", "websockets", "socket", "sockets", "webhook", "webhooks", "callback", "callbacks",
    "gateway-api", "router", "routes", "route", "edge-api", "backend", "back-end",
    "core-api", "service", "services", "microservice", "microservices", "microservices1", "svc", "connect", "sync",
    "stream", "streaming", "event", "events", "queue", "queues", "mq", "rabbit", "rabbitmq", "kafka", "kafka1",
    "pubsub", "broker", "dispatch", "pipeline", "flow",

    # 6. Mail, Communication & Collaboration
    "mail", "mail1", "mail2", "mail3", "mx", "mx0", "mx1", "mx2", "email", "e-mail", "smtp", "smtp1", "smtp2",
    "pop", "pop3", "imap", "imap4", "exchange", "exchange1", "owa", "autodiscover", "autoconfig", "zimbra", "postfix",
    "roundcube", "squirrelmail", "horde", "sendgrid", "mailgun", "bounce", "newsletter", "newsletters",
    "list", "lists", "bulk", "relay", "mail-relay", "mail-in", "mail-out", "chat", "chat1", "slack", "mattermost",
    "rocket", "meet", "meet1", "meet2", "meet3", "zoom", "zoom1", "video", "conference", "voice", "sip", "voip",
    "pbx", "asterisk", "jabber", "xmpp", "teams", "teams1", "comms", "talk", "call", "forum", "forums",
    "community", "discuss", "group", "groups", "office", "365", "sharepoint", "onedrive", "outlook", "lync",
    "skype", "webex", "chime",

    # 7. Development, Build & CI/CD
    "git", "gitlab", "gitlab1", "github", "github1", "gitea", "bitbucket", "gerrit", "svn", "cvs", "repo", "repos",
    "repository", "code", "source", "src", "build", "builds", "builder", "ci", "cd", "cicd",
    "jenkins", "jenkins1", "hudson", "teamcity", "bamboo", "travis", "circleci", "drone", "runner", "runners",
    "sonarqube", "sonar", "nexus", "artifactory", "package", "packages", "pkg", "npm", "pip", "pypi",
    "release", "releases", "dist", "deploy", "deployment", "ci-cd", "pipeline-ci",

    # 8. Content, Media, Assets & Storage
    "static", "static1", "static2", "assets", "asset", "assets1", "assets2", "media", "media1", "media2",
    "img", "img1", "img2", "images", "image", "pic", "pics", "photo", "photos", "video1", "video2",
    "audio", "cdn", "cdn1", "cdn2", "cdn3", "cdn4", "cache", "cache1", "cache2", "content", "download",
    "downloads", "dl", "upload", "uploads", "up", "files", "file", "files1", "doc", "docs",
    "documents", "drive", "box", "s3", "s3-bucket", "s3-internal", "bucket", "buckets", "storage", "storage1",
    "nas", "san", "nfs", "archive", "archives", "dump", "minio", "ceph", "gluster",

    # 9. Knowledge, Help & Support
    "help", "helpdesk", "support", "desk", "service-desk", "servicedesk", "zendesk", "freshdesk",
    "ticket", "tickets", "issue", "issues", "bug", "bugs", "bugzilla", "jira", "confluence", "wiki",
    "notion", "kb", "knowledge", "guide", "guides", "learn", "training", "academy", "edu", "tutorial",
    "manual", "info", "information", "status", "statuspage", "uptime", "health", "ping", "pingdom", "faq",
    "contact", "feedback", "survey", "review", "reviews",

    # 10. E-Commerce, Retail, Billing & Finance
    "shop", "shop1", "store", "store1", "market", "marketplace", "cart", "basket", "checkout", "checkout1",
    "pay", "pay1", "pay2", "payment", "payments", "payment1", "payments1", "paygate", "gateway-pay",
    "billing", "billing1", "bill", "invoice", "invoice1", "invoices", "wallet", "money", "bank",
    "banking", "finance", "accounting", "ledger", "pos", "merchant", "merchant1", "vendor", "vendors", "vendor1",
    "partner", "partners", "partners1", "affiliate", "affiliates", "affiliate1", "order", "orders", "track",
    "tracking", "ship", "shipping", "delivery", "cargo", "product", "products", "pricing", "b2b", "b2c",

    # 11. Analytics, Monitoring, Logs & BI
    "bi", "analytics", "stats", "statistics", "metrics", "telemetry", "trace", "tracing", "audit", "audit1",
    "log", "logs", "logging", "logstash", "fluentd", "datadog", "datadog1", "splunk", "sumologic", "elk",
    "elastic", "elastic1", "elasticsearch", "opensearch", "search", "solr", "find", "query", "grafana", "kibana",
    "zabbix", "nagios", "prtg", "prometheus", "sentry", "sentry1", "jaeger", "alerts", "alert", "beacon",
    "newrelic", "dynatrace", "appdynamics", "cloudwatch", "pagerduty", "opsgenie", "victorops",

    # 12. Databases & Data Engineering
    "db", "db1", "db2", "db3", "db-master", "db-slave", "db-replica", "database", "sql", "mysql", "mysql1",
    "mssql", "oracle", "oracle1", "postgres", "postgres1", "postgresql", "mongo", "mongo1", "mongodb",
    "redis", "redis1", "memcache", "memcache1", "memcached", "cassandra", "dynamo", "bigdata", "hadoop",
    "spark", "hive", "warehouse", "dwh", "lake", "datalake", "data", "etl", "zookeeper",

    # 13. Government Ministries, Departments, Public Sector & National Portals
    "nic", "uidai", "incometax", "incometaxindia", "cbse", "upsc", "epfo", "mohfw", "mha", "mea", "mof", "meity",
    "pmindia", "digitalindia", "parliament", "judiciary", "highcourt", "supremecourt", "rbi", "sebi", "isro", "drdo",
    "csir", "nta", "ugc", "aiims", "railways", "irctc", "irctcindia", "postoffice", "indiapost", "passport", "passportindia",
    "cybercrime", "ncb", "cbi", "nia", "ed", "gst", "gstn", "ewaybill", "digilocker", "umang", "bhim", "npci",
    "co-win", "cowin", "aarogyasetu", "poshan", "samarth", "diksha", "swayam", "mhrd", "dbt", "pfms", "gem", "cag",
    "eci", "election", "elections", "nvsp", "voter", "voters", "parivahan", "sarathi", "vahan", "echallan", "mparivahan",
    "census", "censusindia", "niti", "nitiaayog", "ayush", "ayushman", "abdm", "nha", "nhm", "pmjay", "services",
    "citizen", "grievance", "complaint", "tenders", "tender", "etenders", "eprocurement", "eproc", "procure",
    "registration", "certificates", "revenue", "treasury", "court", "disaster", "relief", "collector", "collectorate",
    "districts", "district", "tehsil", "panchayat", "egov", "police", "state", "national", "central-portal",
    "landrecords", "scholarship", "scholarships", "pension", "pensions", "epassport", "visa", "evisa", "immigration",
    "customs", "excise", "forest", "wildlife", "agriculture", "krishi", "farmer", "kisan", "cooperative", "fisheries",
    "animalhusbandry", "dairy", "civilsupplies", "ration", "pds", "textiles", "mines", "minerals", "steel", "petroleum",
    "heavyindustries", "fertilizers", "chemicals", "shipping", "ports", "waterways", "aviation", "civilaviation", "airports",
    "aai", "highways", "nhai", "roads", "bridges", "housing", "urbanplanning", "rural", "panchayatiraj", "drinkingwater",
    "swachhbharat", "jaljeevan", "energyefficiency", "renewable", "mnre", "atomic", "dae", "space", "isro-portal", "science",
    "dst", "biotech", "dbt-portal", "tourism", "incredibleindia", "culture", "youth", "sports", "sai", "olympics", "welfare",
    "socialjustice", "tribal", "minority", "women", "child", "wcd", "labour", "employment", "skills", "msde", "startup",
    "invest", "investindia", "dpiit", "commerce", "foreign-trade", "dgft", "statistics", "mospi", "law", "justice", "legal",
    "doj", "prosecution", "judges", "advocates", "notary",

    # 14. Indian States, UTs, Capitals & Metro Hubs
    "delhi", "mumbai", "bangalore", "bengaluru", "hyderabad", "chennai", "kolkata", "pune", "ahmedabad", "jaipur",
    "surat", "lucknow", "kanpur", "nagpur", "indore", "bhopal", "patna", "vadodara", "ghaziabad", "ludhiana",
    "agra", "nashik", "faridabad", "meerut", "rajkot", "varanasi", "srinagar", "aurangabad", "dhanbad", "amritsar",
    "navi-mumbai", "allahabad", "prayagraj", "ranchi", "howrah", "coimbatore", "jabalpur", "gwalior", "vijayawada",
    "jodhpur", "madurai", "raipur", "kota", "guwahati", "chandigarh", "solapur", "hubli", "bareilly", "moradabad",
    "mysore", "mysuru", "gurgaon", "gurugram", "aligarh", "jalandhar", "tiruchirappalli", "trichy", "bhubaneswar",
    "salem", "warangal", "mira-bhayandar", "thiruvananthapuram", "trivandrum", "bhiwandi", "saharanpur", "guntur",
    "amravati", "bikaner", "noida", "jamshedpur", "bhilai", "cuttack", "firozabad", "kochi", "cochin", "nellore",
    "bhavnagar", "dehradun", "durgapur", "asansol", "rourkela", "nanded", "kolhapur", "ajmer", "akola", "gulbarga",
    "jamnagar", "ujjain", "loni", "siliguri", "jhansi", "ulhasnagar", "jammu", "sangli", "mangalore", "erode",
    "belgaum", "kurnool", "ambattur", "nagapattinam", "tirunelveli", "malegaon", "gaya", "tirupati", "udaipur",
    "kakinada", "davanagere", "kozhikode", "calicut", "maharashtra", "gujarat", "rajasthan", "karnataka",
    "tamilnadu", "kerala", "andhra", "telangana", "punjab", "haryana", "bihar", "odisha", "assam", "jharkhand",
    "uttarakhand", "himachal", "goa", "tripura", "manipur", "meghalaya", "nagaland", "mizoram", "sikkim",
    "arunachal", "ladakh", "kashmir", "pondicherry", "puducherry", "daman", "diu", "dadra", "up", "mp", "ap", "tn", "ka", "mh", "gj", "rj", "wb",

    # 15. Academic, Education, Examination & University Hubs
    "jee", "jeemain", "jeeadv", "neet", "gate", "cat", "clat", "ugcnet", "csirnet", "results", "exam", "exams",
    "admission", "admissions", "counseling", "merit", "hallticket", "admitcard", "scorecard", "syllabus", "curriculum",
    "university", "college", "school", "board", "degrees", "convocation", "research-portal", "fellowship", "library",
    "faculty", "student", "students", "alumni",

    # 16. Smart City, Municipal, Regional & IoT
    "ems", "emsadmin", "cdm", "netmon", "swm", "smart", "city", "iot", "iot1", "iot2", "sensor", "sensors",
    "sensor1", "sensor2", "scada", "plc", "hmi", "gis", "gis1", "gis2", "map", "map1", "map2", "maps",
    "traffic", "traffic1", "traffic2", "light", "lighting", "led", "smartlight", "water", "water1", "waste", "waste1",
    "sewage", "solidwaste", "energy", "power", "power1", "solar", "grid", "grid1", "grid2", "utility", "utilities",
    "meter", "meters", "smartmeter", "ami", "amr", "supervisory", "telemetry1", "telemetry2", "fleet", "vehicle",
    "vehicles", "civic", "urban", "municipal", "corporation", "transit", "transit1", "transport", "bus", "bus1",
    "parking", "camera", "cameras", "cctv", "cctv1", "cctv2", "surveillance", "safety", "emergency", "alert-city",
    "weather", "pollution", "aqi", "sanitation", "health-city", "smarttrichy", "smartcity", "ticket1", "ticketing", "epay", "epayment",

    # 17. Infrastructure, DNS, Network & Cloud
    "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "dns", "dns1", "dns2", "dns3", "dns4", "dns5",
    "router1", "switch1", "host", "hosts", "server", "servers", "node", "nodes", "node1", "node2", "node3",
    "dc", "dc1", "dc2", "zone", "zone1", "zone2", "lb", "lb1", "lb2", "balancer", "net", "network",
    "int", "internal", "corp", "intranet", "intranet1", "extranet", "priv", "private", "dmz", "lan", "wan", "vpc",
    "route53", "cloudflare", "us", "eu", "ap", "asia", "in", "uk", "de", "fr", "ca", "au", "jp",
    "east", "west", "north", "south", "aws", "azure", "gcp", "cloud", "cloud1", "cloud2", "vm", "vms", "hypervisor",
    "consul", "vault-cluster", "nomad", "terraform", "terragrunt", "harbor-core", "registry-v2", "nexus-repo",
    "artifactory-edge", "sonarqube-dev", "openshift", "rancher-api", "k8s-ingress", "istio-gw", "traefik-ui",
    "envoy-edge", "thanos", "cortex", "loki", "tempo", "otel", "opentelemetry", "graylog", "wazuh-mgr",
    "sentinel-one", "cyberark", "hashi-vault", "ping-fed", "okta-sso", "keycloak-auth", "auth0-tenant",
    "rabbitmq-mgmt", "kafka-connect", "schema-reg", "redis-sentinel", "mongo-express", "pgadmin4",
    "clickhouse", "snowflake-proxy", "bigquery-gw", "airflow", "spark-master", "superset", "metabase",
    "redash", "tableau", "powerbi", "looker",

    # 18. Enterprise Business Apps & Teams
    "hr", "hcm", "work", "career", "careers", "jobs", "hiring", "people", "employee", "staff",
    "crm", "crm1", "erp", "erp1", "sap", "netsuite", "sales", "sales1", "marketing", "marketing1",
    "campaign", "campaign1", "lead", "leads", "leads1", "suppliers", "supplier",

    # 19. Modern Cloud, AI/ML, Container & Microservice Infrastructure
    "ai", "ml", "llm", "gpt", "model", "models", "chatgpt", "copilot", "inference", "vllm", "ollama",
    "triton", "langchain", "embeddings", "rag", "vector", "chroma", "pinecone", "weaviate", "qdrant",
    "fastapi", "supabase", "appwrite", "hasura", "convex", "prisma", "graphql-api", "rest-api",
    "cdn-origin", "edge-cache", "assets-cdn", "media-cdn", "static-cdn", "img-cdn", "s3-assets",
    "ingress", "ingress-controller", "istio", "istio-ingress", "envoy", "kong-api", "tyk-gateway",
    "keycloak", "auth0", "okta-auth", "idp-sso", "saml-idp", "oauth2-provider", "dex", "ory",
    "vault-sec", "consul-ui", "nomad-ui", "boundary", "teleport", "guacamole", "portainer-ce",
    "argocd-server", "flux-system", "crossplane", "tekton", "spinnaker-gate", "thanos-querier",
    "loki-gateway", "tempo-distributor", "jaeger-collector", "otel-collector", "opentelemetry-gw",
    "kafka-broker", "kafka-schema", "nats", "nats-server", "pulsar", "rabbitmq-cluster", "celery",
    "redis-cache", "redis-cluster", "memcached-node", "dragonfly", "clickhouse-http", "scylla",
    "cockroach", "cockroachdb", "tidb", "yugabyte", "questdb", "timescale", "neo4j",
    "pr-review", "review-apps", "preview-env", "branch-deploy", "dev-east", "dev-west", "staging-east",
    "prod-east", "prod-west", "us-east-1", "us-west-2", "eu-central-1", "ap-south-1",

    # 20. Mobile, Short & Peripheral
    "s1", "s2", "s3", "p1", "p2", "p3", "b1", "b2", "t1", "t2", "webdisk", "cpanel-webcall", "webmail-ssl"
)


def _generate_10k_prefix_wordlist(base_prefixes: tuple[str, ...]) -> tuple[str, ...]:
    """Dynamically generates 10,000+ unique high-probability enterprise prefixes.

    Combines:
    1. Curated baseline enterprise dictionary (~1,514 stems)
    2. Numeric permutations ({stem}{n}, {stem}0{n}, {stem}-{n}) on top 100+ stems (0..50)
    3. Multi-tier environment cross-products ({env}-{stem}) across environments & services
    4. Cloud/region cross-products ({region}-{service}, {service}-{cloud})
    5. Numeric subnets & node ranges
    """
    top_stems = [
        "api", "app", "web", "dev", "stage", "staging", "test", "qa", "prod", "production",
        "admin", "portal", "auth", "login", "sso", "mail", "email", "mx", "smtp", "pop",
        "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "elastic",
        "k8s", "kube", "cluster", "node", "srv", "server", "host", "worker", "agent",
        "vpn", "gw", "gateway", "proxy", "edge", "lb", "loadbalancer", "router",
        "cloud", "aws", "azure", "gcp", "corp", "internal", "private", "secure",
        "cdn", "static", "assets", "media", "img", "images", "files", "docs",
        "git", "gitlab", "github", "ci", "cd", "jenkins", "build", "deploy",
        "monitor", "grafana", "prometheus", "kibana", "zabbix", "status", "health",
        "pay", "payment", "billing", "shop", "store", "cart", "checkout",
        "chat", "msg", "slack", "connect", "meet", "zoom", "voice", "video",
        "ns", "dns", "ntp", "radius", "ldap", "ad", "domain", "dc",
        "ws", "websocket", "grpc", "rpc", "rest", "graphql", "hub", "space",
        "core", "base", "backend", "front", "frontend", "ui", "client", "mobile",
        "demo", "preview", "beta", "alpha", "rc", "uat", "sand", "sandbox",
        "v1", "v2", "v3", "legacy", "old", "new", "next", "temp", "bak", "backup"
    ]

    envs = ["dev", "stage", "staging", "qa", "test", "uat", "prod", "internal", "corp", "demo", "sandbox", "preview"]
    sub_services = ["api", "app", "web", "auth", "admin", "portal", "db", "gw", "mail", "vpn", "k8s", "lb", "pay", "media", "node", "sec", "log", "queue"]
    regions = ["us-east", "us-west", "eu-west", "eu-central", "ap-south", "ap-southeast", "east", "west", "central", "north", "south"]
    clouds = ["aws", "gcp", "azure", "k8s", "edge", "cdn"]

    prefixes = set(base_prefixes)

    for stem in top_stems:
        prefixes.add(stem)
        for i in range(51):
            prefixes.add(f"{stem}{i}")
            prefixes.add(f"{stem}-{i}")
        for i in range(1, 21):
            prefixes.add(f"{stem}{i:02d}")
            prefixes.add(f"{stem}-{i:02d}")

    for env in envs:
        for s in sub_services:
            prefixes.add(f"{env}-{s}")
            prefixes.add(f"{env}{s}")
            for i in range(1, 11):
                prefixes.add(f"{env}-{s}{i}")
                prefixes.add(f"{env}-{s}-{i}")
                prefixes.add(f"{env}{s}{i}")

    for reg in regions:
        for s in ("api", "app", "gw", "edge", "vpn", "db", "dc", "node", "srv"):
            prefixes.add(f"{reg}-{s}")
            prefixes.add(f"{s}-{reg}")
            for i in range(1, 10):
                prefixes.add(f"{reg}-{s}-{i}")
                prefixes.add(f"{s}-{reg}-{i}")

    for cloud in clouds:
        for s in ("api", "app", "gw", "prod", "stage", "dev", "vpn", "ingress"):
            prefixes.add(f"{cloud}-{s}")
            prefixes.add(f"{s}-{cloud}")

    return tuple(sorted(prefixes))


# Dynamically generated 10,000+ enterprise prefixes wordlist
EXPANDED_SUBDOMAIN_PREFIXES: tuple[str, ...] = _generate_10k_prefix_wordlist(BASE_ENTERPRISE_PREFIXES)

# Maintain backward compatibility for any external import references
COMMON_SUBDOMAIN_PREFIXES = EXPANDED_SUBDOMAIN_PREFIXES


def _build_dns_query(qname: str, qid: int) -> bytes:
    """Build standard DNS wire format query for an IPv4 A-record."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    parts = qname.strip(".").split(".")
    qbytes = b"".join(bytes([len(p)]) + p.encode("latin1") for p in parts) + b"\x00"
    tail = struct.pack("!HH", 1, 1)  # Type A (1), Class IN (1)
    return header + qbytes + tail


def _parse_dns_response(data: bytes) -> tuple[int, list[str]]:
    """Parse raw UDP DNS response packet, extracting transaction ID and resolved IPv4 addresses."""
    if len(data) < 12:
        return 0, []
    qid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if (flags & 0x8000) == 0:  # Not a response
        return qid, []
    if (flags & 0x000F) != 0:  # Error (e.g. NXDOMAIN)
        return qid, []
    offset = 12
    # Skip question section
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 5
                break
            elif (length & 0xC0) == 0xC0:
                offset += 6
                break
            else:
                offset += 1 + length
    ips: list[str] = []
    # Parse answers
    for _ in range(ancount):
        if offset >= len(data):
            break
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            ips.append(socket.inet_ntoa(data[offset : offset + 4]))
        offset += rdlength
    return qid, ips


class SubdomainDiscoveryService:
    """Unbounded non-destructive reconnaissance engine for comprehensive apex domain asset mapping."""

    @classmethod
    def normalize_apex_domain(cls, raw: str) -> str:
        """Extract clean apex domain from URL or raw hostname input."""
        cleaned = raw.strip().lower()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.hostname or cleaned
        if "/" in cleaned:
            cleaned = cleaned.split("/")[0]
        if ":" in cleaned:
            cleaned = cleaned.split(":")[0]
        parts = [p for p in cleaned.split(".") if p]
        if len(parts) > 2 and parts[0] == "www":
            cleaned = ".".join(parts[1:])
        return cleaned

    _dns_executor = ThreadPoolExecutor(max_workers=80)

    @classmethod
    async def _resolve_hosts(
        cls, hosts: list[str], timeout: float = 2.0, client: httpx.AsyncClient | None = None
    ) -> dict[str, list[str]]:
        """Asynchronously resolve a batch of hostnames with high-speed non-blocking resolution.

        Leverages multiplexed DoH (Cloudflare and Google DNS over HTTPS) for instant sub-second resolution
        with fallback to a dedicated 80-thread worker pool executing concurrent socket.getaddrinfo.
        """
        results: dict[str, list[str]] = {h: [] for h in hosts}
        if not hosts:
            return results

        # 1. High-speed DoH resolution for batches (multiplexed Cloudflare + Google DoH)
        if len(hosts) > 10:
            sem = asyncio.Semaphore(150)
            doh_endpoints = [
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/resolve",
            ]

            async def _doh_lookup(h: str, idx: int, cli: httpx.AsyncClient) -> tuple[str, list[str]]:
                async with sem:
                    endpoint = doh_endpoints[idx % 2]
                    try:
                        r = await cli.get(
                            f"{endpoint}?name={h}&type=A",
                            timeout=min(timeout, 2.0),
                        )
                        if r.status_code == 200:
                            data = r.json()
                            st = data.get("Status")
                            answers = data.get("Answer", [])
                            ips = [
                                ans["data"]
                                for ans in answers
                                if ans.get("type") == 1
                            ]
                            cnames = [
                                ans["data"].rstrip(".")
                                for ans in answers
                                if ans.get("type") == 5
                            ]
                            if ips:
                                return h, sorted(list(set(ips)))
                            elif cnames:
                                return h, [f"CNAME:{cnames[0]}"]
                            elif st == 0:
                                # Status 0 (NOERROR) confirms hostname exists in DNS zone
                                return h, ["DNS:ACTIVE"]
                    except Exception:
                        pass
                    return h, []

            try:
                if client is not None:
                    tasks = [_doh_lookup(h, idx, client) for idx, h in enumerate(hosts)]
                    doh_res = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in doh_res:
                        if isinstance(res, tuple) and res[1]:
                            results[res[0]] = res[1]
                else:
                    async with httpx.AsyncClient(
                        headers={"accept": "application/dns-json"},
                        verify=False,
                        limits=httpx.Limits(max_connections=200, max_keepalive_connections=150),
                    ) as new_client:
                        tasks = [_doh_lookup(h, idx, new_client) for idx, h in enumerate(hosts)]
                        doh_res = await asyncio.gather(*tasks, return_exceptions=True)
                        for res in doh_res:
                            if isinstance(res, tuple) and res[1]:
                                results[res[0]] = res[1]
            except Exception:
                pass

        # 2. For unresolved hosts or small batches (<= 10 hosts), fall back to ThreadPoolExecutor socket.getaddrinfo
        unresolved = [h for h in hosts if not results.get(h)]
        if unresolved and len(hosts) <= 10:
            loop = asyncio.get_running_loop()

            def _resolve_sync(h: str) -> tuple[str, list[str]]:
                try:
                    addr_info = socket.getaddrinfo(h, None, family=socket.AF_INET)
                    ips = sorted(list({str(info[4][0]) for info in addr_info}))
                    return h, ips
                except Exception:
                    return h, []

            tasks = [loop.run_in_executor(cls._dns_executor, _resolve_sync, h) for h in unresolved]
            resolved_tuples = await asyncio.gather(*tasks)
            for h, ips in resolved_tuples:
                if ips:
                    results[h] = ips

        return results

    @classmethod
    async def _resolve_host(cls, host: str) -> list[str]:
        """Resolve a single host IPv4 addresses."""
        res_map = await cls._resolve_hosts([host], timeout=1.5)
        return res_map.get(host, [])

    @classmethod
    async def _detect_wildcard_dns(cls, apex: str) -> set[str]:
        """Test non-existent canary subdomains to detect wildcard DNS resolution and prevent false positives."""
        canary_a = f"sentinel-rnd-canary-{random.randint(100000, 999999)}-a.{apex}"
        canary_b = f"sentinel-rnd-canary-{random.randint(100000, 999999)}-b.{apex}"
        resolved = await cls._resolve_hosts([canary_a, canary_b], timeout=1.8)

        ips_a = set(resolved.get(canary_a, []))
        ips_b = set(resolved.get(canary_b, []))

        # Wildcard DNS is active if both completely random canary names resolved to IPs
        if ips_a and ips_b and (ips_a == ips_b or bool(ips_a.intersection(ips_b))):
            wildcard_ips = ips_a.union(ips_b)
            logger.info(f"Wildcard DNS identified for '{apex}': {wildcard_ips}")
            return wildcard_ips

        return set()

    @classmethod
    async def _query_crt_sh(cls, apex: str) -> set[str]:
        """Query crt.sh Certificate Transparency logs with multi-URL fallback and retry."""
        found: set[str] = set()
        urls = [
            f"https://crt.sh/?q={apex}&output=json",
            f"https://crt.sh/?dNSName=%25.{apex}&output=json",
        ]
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
        }

        for ct_url in urls:
            for attempt in range(2):
                try:
                    async with httpx.AsyncClient(timeout=18.0, verify=False) as client:
                        resp = await client.get(ct_url, headers=headers)
                        if resp.status_code == 200:
                            entries = resp.json()
                            for entry in entries:
                                for key in ("name_value", "common_name"):
                                    val = entry.get(key, "")
                                    if not val:
                                        continue
                                    for n in str(val).split("\n"):
                                        sub = n.strip().lower()
                                        if sub.startswith("*."):
                                            sub = sub[2:]
                                        if sub and sub.endswith("." + apex) and sub != apex:
                                            if all(c.isalnum() or c in ".-_" for c in sub):
                                                found.add(sub)
                            if found:
                                logger.info(f"crt.sh returned {len(found)} subdomains for {apex}")
                                return found
                except Exception as e:
                    logger.debug(f"crt.sh attempt {attempt+1} on {ct_url} failed: {e}")
                    await asyncio.sleep(0.5)

        return found

    @classmethod
    async def _query_hackertarget(cls, apex: str) -> tuple[set[str], dict[str, list[str]]]:
        """Query HackerTarget Hostsearch API for active passive DNS mappings."""
        found: set[str] = set()
        ip_map: dict[str, list[str]] = {}
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={apex}"
        try:
            async with httpx.AsyncClient(timeout=7.0, verify=False) as client:
                resp = await client.get(
                    ht_url,
                    headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"},
                )
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if not line or "," not in line:
                            continue
                        parts = line.split(",", 1)
                        sub = parts[0].strip().lower()
                        ip = parts[1].strip() if len(parts) > 1 else ""
                        if sub.endswith("." + apex) and sub != apex:
                            found.add(sub)
                            if ip and ip != "None":
                                ip_map.setdefault(sub, []).append(ip)
                    logger.info(f"HackerTarget returned {len(found)} subdomains for {apex}")
        except Exception as e:
            logger.debug(f"HackerTarget passive lookup skipped: {e}")
        return found, ip_map

    @classmethod
    async def _query_certspotter(cls, apex: str) -> set[str]:
        """Query CertSpotter Certificate Transparency API."""
        found: set[str] = set()
        cs_url = f"https://api.certspotter.com/v1/issuances?domain={apex}&include_subdomains=true&expand=dns_names"
        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False) as client:
                resp = await client.get(cs_url, headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"})
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        dns_names = entry.get("dns_names", [])
                        for n in dns_names:
                            sub = n.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub.endswith("." + apex) and sub != apex:
                                found.add(sub)
        except Exception as e:
            logger.debug(f"CertSpotter CT lookup skipped or timed out for {apex}: {e}")
        return found

    @classmethod
    async def _query_alienvault(cls, apex: str) -> set[str]:
        """Query AlienVault OTX Passive DNS indicators."""
        found: set[str] = set()
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{apex}/passive_dns"
        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False) as client:
                resp = await client.get(otx_url, headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").strip().lower()
                        if hostname.endswith("." + apex) and hostname != apex:
                            found.add(hostname)
        except Exception as e:
            logger.debug(f"AlienVault passive DNS skipped for {apex}: {e}")
        return found

    @classmethod
    async def _query_anubis(cls, apex: str) -> set[str]:
        """Query Anubis subdomains aggregator."""
        found: set[str] = set()
        anubis_url = f"https://jldc.me/anubis/subdomains/{apex}"
        try:
            async with httpx.AsyncClient(timeout=6.0, verify=False) as client:
                resp = await client.get(anubis_url, headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for sub in data:
                            s = str(sub).strip().lower()
                            if s.endswith("." + apex) and s != apex:
                                found.add(s)
        except Exception as e:
            logger.debug(f"Anubis lookup skipped for {apex}: {e}")
        return found

    @classmethod
    async def _query_wayback_cdx(cls, apex: str) -> set[str]:
        """Query Internet Archive Wayback Machine CDX API for historical & live subdomains."""
        found: set[str] = set()
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{apex}/*&output=json&collapse=urlkey&fl=original&limit=10000"
        )
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OWASP-Sentinel-Recon/2.0"}
        try:
            async with httpx.AsyncClient(timeout=28.0, verify=False) as client:
                resp = await client.get(cdx_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    # First row is typically header e.g. ["original"]
                    rows = data[1:] if len(data) > 1 else data
                    for row in rows:
                        if isinstance(row, list) and row:
                            raw_val = str(row[0]).strip().lower()
                            if "://" in raw_val:
                                parsed = urlparse(raw_val)
                                host = parsed.hostname or ""
                            else:
                                host = raw_val.split("/")[0]
                            if host.endswith("." + apex) and host != apex:
                                if all(c.isalnum() or c in ".-_" for c in host):
                                    found.add(host)
                    if found:
                        logger.info(f"Wayback CDX returned {len(found)} subdomains for {apex}")
        except Exception as e:
            logger.debug(f"Wayback CDX lookup skipped or timed out for {apex}: {e}")
        return found

    @classmethod
    async def _query_subdomain_center(cls, apex: str) -> set[str]:
        """Query Subdomain Center API for comprehensive real-time passive asset listings."""
        found: set[str] = set()
        sc_url = f"https://api.subdomain.center/?domain={apex}"
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(sc_url, headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        for sub in data:
                            s = str(sub).strip().lower()
                            if s.endswith("." + apex) and s != apex:
                                if all(c.isalnum() or c in ".-_" for c in s):
                                    found.add(s)
                    if found:
                        logger.info(f"Subdomain Center returned {len(found)} subdomains for {apex}")
        except Exception as e:
            logger.debug(f"Subdomain Center lookup skipped for {apex}: {e}")
        return found

    @classmethod
    async def _query_urlscan(cls, apex: str) -> set[str]:
        """Query URLScan.io search API for publicly scanned hostnames under the target apex."""
        found: set[str] = set()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{apex}&size=1000"
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(url, headers={"User-Agent": "OWASP-Sentinel-Recon/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    for r in data.get("results", []):
                        for obj_k in ("task", "page"):
                            obj = r.get(obj_k, {})
                            dom = obj.get("domain", "").strip().lower()
                            if dom.endswith("." + apex) and dom != apex:
                                if all(c.isalnum() or c in ".-_" for c in dom):
                                    found.add(dom)
                    if found:
                        logger.info(f"URLScan.io returned {len(found)} subdomains for {apex}")
        except Exception as e:
            logger.debug(f"URLScan.io lookup skipped for {apex}: {e}")
        return found

    @classmethod
    def _generate_sector_intelligence(cls, apex: str) -> set[str]:
        """Generate high-yield sector and jurisdictional domain assets for public sector and enterprise targets."""
        found: set[str] = set()
        clean_apex = apex.lower().strip()

        # National, Regional & Municipal Public Sector Intelligence (gov.in, nic.in, state portals)
        if clean_apex in ("gov.in", "nic.in") or clean_apex.endswith(".gov.in") or clean_apex.endswith(".nic.in"):
            central_bodies = [
                "nic", "uidai", "incometax", "incometaxindia", "cbse", "upsc", "epfo", "mohfw", "mha", "mea",
                "mof", "meity", "pmindia", "digitalindia", "parliament", "judiciary", "highcourt", "supremecourt",
                "sci", "rbi", "sebi", "isro", "drdo", "csir", "nta", "ugc", "aiims", "railways", "irctc",
                "indiapost", "postoffice", "passport", "cybercrime", "ncb", "cbi", "nia", "ed", "gst", "gstn",
                "ewaybill", "digilocker", "umang", "bhim", "npci", "cowin", "aarogyasetu", "poshan", "samarth",
                "diksha", "swayam", "mhrd", "dbt", "pfms", "gem", "cag", "eci", "nvsp", "voter", "parivahan",
                "sarathi", "vahan", "echallan", "mparivahan", "census", "nitiaayog", "ayush", "abdm", "nha",
                "nhm", "pmjay", "services", "citizen", "grievance", "etenders", "eprocure", "pds", "mines",
                "steel", "petroleum", "aviation", "airports", "aai", "highways", "nhai", "roads", "swachhbharat",
                "jaljeevan", "renewable", "mnre", "dae", "dst", "biotech", "incredibleindia", "sai", "msde",
                "investindia", "dpiit", "dgft", "mospi", "doj", "prosecution", "customs", "centralexcise",
                "cbic", "cbdt", "fssai", "bis", "trai", "cci", "cerc", "pfrda", "irdai", "nabard", "sidbi",
                "exim", "nhb", "iit", "iim", "nit", "ignou", "icmr", "icar", "barc", "npcil", "bhel",
                "ongc", "ioc", "bpcl", "hpcl", "gail", "sail", "ntpc", "coalindia", "powergrid", "bel", "hal",
                "cris", "nhpc", "sjvn", "thdc", "posoco", "eesl", "ireda", "cpcl", "nrl", "mrpl", "iocl",
                "cil", "moef", "mowr", "mot", "mod", "mop", "moca", "moes", "mord", "mopr", "mowcd", "msje",
                "moma", "mofpi", "mohua", "mopng", "mos", "moci", "mca", "mib", "mspi", "sansad", "natgrid",
                "cert-in", "nciipc", "drdo-portal", "isro-portal", "mod-gov", "cisf", "crpf", "bsf", "itbp",
                "ssb", "nsg", "assamrifles", "ib", "raw", "spg", "police-portal", "bprd", "ncrb", "lokpal",
                "cvc", "cic", "nhrc", "ncw", "ncbc", "ncsc", "ncst", "ncpcr", "minorityaffairs", "tribalaffairs",
                "pwd-portal", "cpwd", "nbcc-india", "surveyofindia", "gsi", "fsi", "imd", "incois", "ncsm"
            ]

            states = [
                "andhra", "arunachal", "assam", "bihar", "chhattisgarh", "goa", "gujarat", "haryana",
                "himachal", "jharkhand", "karnataka", "kerala", "mp", "maharashtra", "manipur", "meghalaya",
                "mizoram", "nagaland", "odisha", "punjab", "rajasthan", "sikkim", "tn", "tamilnadu",
                "telangana", "tripura", "up", "uttarakhand", "wb", "westbengal", "delhi", "jammu",
                "kashmir", "ladakh", "chandigarh", "puducherry", "andaman", "daman", "diu", "dadra",
                "ap", "mh", "gj", "ka", "kl", "rj", "pb", "hr", "jh", "or", "ch", "cg"
            ]

            state_depts = [
                "police", "transport", "revenue", "treasury", "highcourt", "court", "education", "health",
                "finance", "forest", "agriculture", "pwd", "rto", "eservices", "collector", "panchayat",
                "water", "energy", "excise", "commercialtax", "landrecords", "recruitment", "disaster",
                "welfare", "tourism", "sports", "industry", "labor", "employment", "housing", "urban",
                "rural", "food", "civilsupplies", "irrigation", "cooperation", "fisheries", "animalhusbandry",
                "mining", "power", "environment", "socialjustice", "tribal", "women", "child", "election",
                "tender", "eproc", "sec", "psc", "jail", "fire", "coastal", "vigilance", "anti-corruption"
            ]

            districts = [
                "ahmedabad", "surat", "vadodara", "rajkot", "bhavnagar", "jamnagar", "junagadh", "gandhinagar",
                "anand", "bharuch", "mehsana", "morbi", "navsari", "valsad", "porbandar", "amreli",
                "pune", "nagpur", "nashik", "thane", "aurangabad", "solapur", "amravati", "kolhapur",
                "nanded", "sangli", "jalgaon", "akola", "latur", "dhule", "ahmednagar", "chandrapur",
                "lucknow", "kanpur", "ghaziabad", "agra", "meerut", "varanasi", "prayagraj", "bareilly",
                "aligarh", "moradabad", "saharanpur", "gorakhpur", "noida", "firozabad", "jhansi", "mathura",
                "patna", "gaya", "bhagalpur", "muzaffarpur", "purnia", "darbhanga", "biharsharif", "arrah",
                "bhopal", "indore", "jabalpur", "gwalior", "ujjain", "sagar", "dewas", "satna", "ratlam",
                "jaipur", "jodhpur", "kota", "bikaner", "ajmer", "udaipur", "bhilwara", "alwar", "bharatpur",
                "ludhiana", "amritsar", "jalandhar", "patiala", "bathinda", "mohali", "hoshiarpur", "pathankot",
                "gurugram", "faridabad", "panipat", "ambala", "yamunanagar", "rohtak", "hisar", "karnal",
                "ranchi", "jamshedpur", "dhanbad", "bokaro", "deoghar", "hazaribagh", "giridih", "ramgarh",
                "bhubaneswar", "cuttack", "rourkela", "berhampur", "sambalpur", "puri", "balasore", "bhadrak",
                "kolkata", "howrah", "durgapur", "asansol", "siliguri", "bardhaman", "malda", "kharagpur",
                "guwahati", "silchar", "dibrugarh", "jorhat", "nagaon", "tinsukia", "tezpur", "bongaigaon",
                "chennai", "coimbatore", "madurai", "tiruchirappalli", "salem", "tirunelveli", "tiruppur",
                "ranipet", "nagercoil", "thanjavur", "vellore", "kanchipuram", "erode", "thoothukudi", "dindigul",
                "bengaluru", "mysuru", "hubli", "mangalore", "belgaum", "davangere", "bellary", "vijayapura",
                "shimoga", "tumkur", "raichur", "bidar", "hospet", "gadag", "hassan", "chitradurga", "udupi",
                "thiruvananthapuram", "kochi", "kozhikode", "kollam", "thrissur", "alappuzha", "palakkad",
                "kannur", "kottayam", "manjeri", "malappuram", "kasaragod", "idukki", "pathanamthitta",
                "hyderabad", "warangal", "nizamabad", "karimnagar", "ramagundam", "khammam", "mahbubnagar",
                "visakhapatnam", "vijayawada", "guntur", "nellore", "kurnool", "rajahmundry", "kadapa",
                "kakinada", "tirupati", "anantapur", "vizianagaram", "eluru", "nandyal", "ongole"
            ]

            if clean_apex in ("gov.in", "nic.in"):
                # 1. Central ministries & statutory bodies
                for b in central_bodies:
                    found.add(f"{b}.{clean_apex}")
                    found.add(f"www.{b}.{clean_apex}")
                    found.add(f"api.{b}.{clean_apex}")
                    found.add(f"portal.{b}.{clean_apex}")
                    found.add(f"admin.{b}.{clean_apex}")
                    found.add(f"services.{b}.{clean_apex}")

                # 2. States, state departments & e-governance systems
                for s in states:
                    found.add(f"{s}.{clean_apex}")
                    found.add(f"www.{s}.{clean_apex}")
                    found.add(f"portal.{s}.{clean_apex}")
                    found.add(f"services.{s}.{clean_apex}")
                    for d in state_depts:
                        found.add(f"{d}.{s}.{clean_apex}")
                        found.add(f"{s}{d}.{clean_apex}")
                        found.add(f"{s}-{d}.{clean_apex}")

                # 3. Districts, collectorates and municipal portals
                for dist in districts:
                    found.add(f"{dist}.{clean_apex}")
                    found.add(f"www.{dist}.{clean_apex}")
                    found.add(f"portal.{dist}.{clean_apex}")
                    found.add(f"collectorate.{dist}.{clean_apex}")
            elif clean_apex.endswith(".gov.in") or clean_apex.endswith(".nic.in"):
                # Sub-entity such as gujarat.gov.in or incometax.gov.in
                for d in state_depts:
                    found.add(f"{d}.{clean_apex}")
                    found.add(f"www.{d}.{clean_apex}")
                    found.add(f"portal.{d}.{clean_apex}")
                    found.add(f"api.{d}.{clean_apex}")
                for dist in districts:
                    found.add(f"{dist}.{clean_apex}")
                    found.add(f"collectorate.{dist}.{clean_apex}")
                for p in ("www", "portal", "api", "admin", "mail", "services", "login", "app", "dev", "staging", "auth", "secure"):
                    found.add(f"{p}.{clean_apex}")

        return found

    @classmethod
    def _mine_target_vocabulary(cls, discovered_hosts: list[str], apex: str) -> set[str]:
        """Mine unique vocabulary tokens, stems, and naming patterns directly from discovered target assets.

        Eliminates reliance on fixed static wordlists by learning the target's own naming conventions.
        """
        tokens: set[str] = set()
        apex_suffix = "." + apex
        stop_words = {"com", "net", "org", "gov", "in", "edu", "mil", "co", "io", "app", "dev", "www"}
        for h in discovered_hosts:
            if h.endswith(apex_suffix):
                sub = h[: -len(apex_suffix)]
                for part in re.split(r"[\.\-_0-9]+", sub):
                    part = part.lower().strip()
                    if len(part) >= 2 and part.isalpha() and part not in stop_words:
                        tokens.add(part)
        return tokens

    @classmethod
    async def _mine_dns_authoritative_records(cls, apex: str) -> set[str]:
        """Query DNS-over-HTTPS (DoH) for authoritative TXT/SPF, MX, NS, and CNAME records,
        discovering internal hostnames disclosed directly in public DNS zone configuration.
        """
        found: set[str] = set()
        headers = {"Accept": "application/dns-json", "User-Agent": "OWASP-Sentinel-Recon/2.0"}
        rtypes = ["TXT", "MX", "NS", "CNAME"]
        async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
            for rtype in rtypes:
                for doh_url in (
                    f"https://dns.google/resolve?name={apex}&type={rtype}",
                    f"https://cloudflare-dns.com/dns-query?name={apex}&type={rtype}",
                ):
                    try:
                        resp = await client.get(doh_url, headers=headers)
                        if resp.status_code == 200:
                            data = resp.json()
                            for ans in data.get("Answer", []):
                                val = str(ans.get("data", ""))
                                for match in re.findall(r"([a-zA-Z0-9_\-\.]+\." + re.escape(apex) + r")", val):
                                    m = match.strip(".").lower()
                                    if m != apex and all(c.isalnum() or c in ".-_" for c in m):
                                        found.add(m)
                            break
                    except Exception:
                        pass
        return found

    @classmethod
    async def _mine_live_web_assets(cls, sample_hosts: list[str], apex: str) -> set[str]:
        """Proactively harvest subdomains from Content-Security-Policy (CSP), CORS, robots.txt,
        and HTML hyperlinks on live web targets concurrently.
        """
        found: set[str] = set()
        targets = [apex] + [h for h in sample_hosts if h != apex][:5]
        headers = {"User-Agent": "OWASP-Sentinel-Discovery/2.0 (Asset Mining)"}
        urls = [
            f"{scheme}://{t}{path}"
            for t in targets
            for scheme in ("https", "http")
            for path in ("/", "/robots.txt")
        ]

        async def _fetch_url(url: str, client: httpx.AsyncClient) -> set[str]:
            sub_found: set[str] = set()
            try:
                resp = await client.get(url, headers=headers)
                csp = resp.headers.get("content-security-policy", "")
                if csp:
                    for match in re.findall(r"([a-zA-Z0-9_\-\.]+\." + re.escape(apex) + r")", csp):
                        m = match.strip(".").lower()
                        if m != apex and all(c.isalnum() or c in ".-_" for c in m):
                            sub_found.add(m)
                if resp.status_code == 200 and resp.text:
                    for match in re.findall(r"https?://([a-zA-Z0-9_\-\.]+\." + re.escape(apex) + r")", resp.text):
                        m = match.strip(".").lower()
                        if m != apex and all(c.isalnum() or c in ".-_" for c in m):
                            sub_found.add(m)
            except Exception:
                pass
            return sub_found

        try:
            async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=True) as client:
                tasks = [_fetch_url(u, client) for u in urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, set):
                        found.update(r)
        except Exception:
            pass

        return found

    @classmethod
    def _generate_unbounded_candidates(
        cls, apex: str, discovered_hosts: list[str], max_candidates: int | None = None
    ) -> list[str]:
        """Dynamically generate candidate subdomains without artificial fixed-wordlist limits.

        Synthesizes:
        1. Mined target vocabulary tokens (learned directly from target assets, prioritized by frequency).
        2. Environment cross-products (dev-{t}, api-{t}, admin-{t}, portal-{t}, etc.).
        3. Dynamic numeric variations (web1..web10, api1..api10, app01..app05).
        4. Recursive multi-level permutations on discovered sub-branches (api.{host}, portal.{host}, admin.{host}).
        5. Core enterprise baseline prefixes.
        """
        candidates: set[str] = set()

        # 1. Mine target vocabulary tokens
        mined_tokens = cls._mine_target_vocabulary(discovered_hosts, apex)

        # 2. Count frequency across discovered hosts to prioritize high-value tokens
        token_freq: dict[str, int] = {}
        apex_suffix = "." + apex
        for h in discovered_hosts:
            if h.endswith(apex_suffix):
                sub = h[: -len(apex_suffix)]
                for part in re.split(r"[\.\-_0-9]+", sub):
                    p = part.lower().strip()
                    if len(p) >= 2 and p.isalpha():
                        token_freq[p] = token_freq.get(p, 0) + 1

        sorted_tokens = sorted(mined_tokens, key=lambda t: token_freq.get(t, 0), reverse=True)

        # 3. Add base tokens directly on apex
        for token in sorted_tokens:
            candidates.add(f"{token}.{apex}")

        # 4. Environment cross-products on top prioritized tokens
        env_stems = ("api", "admin", "dev", "portal", "test", "stage", "staging", "uat", "qa", "auth", "vpn", "mail", "app", "internal", "corp", "secure", "gw")
        top_tokens = sorted_tokens[:150] if len(sorted_tokens) > 150 else sorted_tokens
        for token in top_tokens:
            for env in env_stems:
                candidates.add(f"{env}-{token}.{apex}")
                candidates.add(f"{token}-{env}.{apex}")
                candidates.add(f"{env}.{token}.{apex}")

        # 5. Numeric range mutations on high-probability prefixes
        numeric_bases = ("web", "app", "api", "node", "server", "portal", "mail", "db", "ns", "cluster", "vpn", "gw", "dc", "edge")
        for base in numeric_bases:
            for num in range(1, 11):
                candidates.add(f"{base}{num}.{apex}")
            for num in (1, 2, 3):
                candidates.add(f"{base}0{num}.{apex}")

        # 6. Multi-level recursive child hosts on discovered assets
        recursive_hosts = [h for h in discovered_hosts if h != apex and h.count(".") >= 2]
        for host in recursive_hosts[:50]:
            for env in ("api", "admin", "dev", "portal", "mail", "auth", "services", "app", "gateway", "test"):
                candidate = f"{env}.{host}"
                if len(candidate) <= 255:
                    candidates.add(candidate)

        # 7. Core enterprise baseline
        for p in EXPANDED_SUBDOMAIN_PREFIXES:
            candidates.add(f"{p}.{apex}")

        candidate_list = list(candidates)
        if max_candidates and len(candidate_list) > max_candidates:
            candidate_list = candidate_list[:max_candidates]

        return candidate_list

    @classmethod
    def _generate_permutations(cls, discovered_hosts: list[str], apex: str, max_candidates: int = 150) -> list[str]:
        """Generate dynamic recursive permutations on discovered assets, maintaining backward compatibility."""
        return cls._generate_unbounded_candidates(apex, discovered_hosts, max_candidates=max_candidates)

    @classmethod
    async def _verify_live_service(
        cls, subdomain: str
    ) -> tuple[bool, str, int, int | None, float | None, str | None, str | None]:
        """Probe HTTPS and HTTP to determine whether the subdomain responds to live web traffic,
        extracting HTTP status code, round-trip latency, server banner, and page title."""
        start = time.perf_counter()
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=2.5) as client:
            # 1. Try HTTPS first
            try:
                r = await client.get(
                    f"https://{subdomain}",
                    headers={"User-Agent": "OWASP-Sentinel-Discovery/2.0 (Live Reconnaissance)"},
                    timeout=2.0,
                )
                duration_ms = round((time.perf_counter() - start) * 1000, 1)
                server = r.headers.get("server") or r.headers.get("x-powered-by")
                title = None
                if r.text:
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = " ".join(m.group(1).split()).strip()[:120] or None
                return True, "https", 443, r.status_code, duration_ms, server, title
            except Exception:
                pass

            # 2. Fallback to HTTP
            try:
                r = await client.get(
                    f"http://{subdomain}",
                    headers={"User-Agent": "OWASP-Sentinel-Discovery/2.0 (Live Reconnaissance)"},
                    timeout=1.5,
                )
                duration_ms = round((time.perf_counter() - start) * 1000, 1)
                server = r.headers.get("server") or r.headers.get("x-powered-by")
                title = None
                if r.text:
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = " ".join(m.group(1).split()).strip()[:120] or None
                return True, "http", 80, r.status_code, duration_ms, server, title
            except Exception:
                pass

        return False, "https", 443, None, None, None, None

    @classmethod
    async def _live_scrape_target_network(
        cls,
        apex: str,
        seed_hosts: list[str],
        max_hosts: int = 50,
        max_depth: int = 2,
        progress_callback: Any = None,
    ) -> dict[str, dict[str, Any]]:
        """Active real-time web crawler & JavaScript asset spider for finding live subdomains.

        Performs:
        1. Deep HTML, sitemap.xml, robots.txt, and /.well-known/security.txt crawling on live endpoints.
        2. JavaScript bundle parsing: extracts referenced frontend script bundles, modulepreloads,
           embedded API gateways, WebSocket URLs, and internal subdomains in client code and JSON configs.
        3. Real-time HTTP response header harvesting: CSP, CORS, Link headers.
        4. Immediate live active DNS & HTTP/HTTPS probe validation of all candidate subdomains.
        5. Recursive spidering across newly confirmed live subdomains up to max_depth.
        """
        discovered_live_assets: dict[str, dict[str, Any]] = {}
        all_candidate_hosts: set[str] = set()
        visited_hosts: set[str] = set()

        async def _emit_progress(pct: int, msg: str, items: list[dict[str, Any]] | None = None):
            if progress_callback:
                try:
                    res = progress_callback(pct, msg, items or [])
                    if inspect.isawaitable(res):
                        await res
                except Exception:
                    pass

        initial_queue: list[str] = []
        for h in [apex, f"www.{apex}"] + seed_hosts:
            clean_h = h.strip().lower()
            if clean_h and clean_h not in initial_queue:
                initial_queue.append(clean_h)

        queue = initial_queue[:max_hosts]
        current_depth = 1

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        apex_escaped = re.escape(apex)
        subdomain_pat = re.compile(
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+" + apex_escaped,
            re.IGNORECASE,
        )
        url_pat = re.compile(
            r"""(?:https?|wss?)://([a-zA-Z0-9_\-\.]+\.""" + apex_escaped + r""")""",
            re.IGNORECASE,
        )

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=2.5,
            limits=httpx.Limits(max_connections=80, max_keepalive_connections=50),
        ) as client:
            while queue and current_depth <= max_depth:
                current_batch = [h for h in queue if h not in visited_hosts][:20]
                queue = [h for h in queue if h not in current_batch and h not in visited_hosts]
                for h in current_batch:
                    visited_hosts.add(h)

                if not current_batch:
                    break

                batch_pct = 45 + min(6, int((len(visited_hosts) / max(1, len(initial_queue))) * 6))
                await _emit_progress(
                    batch_pct,
                    f"Scraping live HTML, JS & endpoints ({len(visited_hosts)}/{min(max_hosts, len(visited_hosts) + len(queue))} hosts)...",
                )

                sem = asyncio.Semaphore(20)

                async def _scrape_host(target_host: str) -> set[str]:
                    host_candidates: set[str] = set()
                    async with sem:
                        base_url = None
                        root_resp = None
                        for scheme in ("https", "http"):
                            try:
                                r = await client.get(f"{scheme}://{target_host}/", headers=headers, timeout=2.0)
                                if r.status_code < 500:
                                    base_url = f"{scheme}://{target_host}"
                                    root_resp = r
                                    break
                            except Exception:
                                pass

                        if not base_url or not root_resp:
                            return host_candidates

                        # 1. Harvest headers: Content-Security-Policy, CORS, Link, Location
                        for h_key in ("content-security-policy", "access-control-allow-origin", "link", "location"):
                            h_val = root_resp.headers.get(h_key, "")
                            if h_val:
                                for m in subdomain_pat.findall(h_val):
                                    m_clean = m.strip(".").lower()
                                    if m_clean.endswith("." + apex) and m_clean != apex:
                                        host_candidates.add(m_clean)

                        # 2. Harvest HTML body: URLs, inline scripts, anchor links, unescaping JSON slashes
                        raw_html = root_resp.text or ""
                        html_text = raw_html.replace(r"\/", "/")
                        if html_text:
                            for m in url_pat.findall(html_text):
                                m_clean = m.strip(".").lower()
                                if m_clean.endswith("." + apex) and m_clean != apex:
                                    host_candidates.add(m_clean)
                            for m in subdomain_pat.findall(html_text):
                                m_clean = m.strip(".").lower()
                                if m_clean.endswith("." + apex) and m_clean != apex:
                                    host_candidates.add(m_clean)

                            # 3. Harvest referenced frontend JavaScript bundles & modulepreloads
                            script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html_text, re.IGNORECASE)
                            preload_srcs = re.findall(r"""<link[^>]+(?:href=["']([^"']+)["'][^>]+rel=["'](?:modulepreload|preload|prefetch)["']|rel=["'](?:modulepreload|preload|prefetch)["'][^>]+href=["']([^"']+)["'])""", html_text, re.IGNORECASE)
                            all_links = list(script_srcs)
                            for p1, p2 in preload_srcs:
                                lnk = p1 or p2
                                if lnk:
                                    all_links.append(lnk)

                            js_urls = []
                            for src in all_links:
                                src_clean = src.strip()
                                if not src_clean or src_clean.startswith("data:"):
                                    continue
                                if src_clean.startswith("//"):
                                    js_urls.append("https:" + src_clean)
                                elif src_clean.startswith("http://") or src_clean.startswith("https://"):
                                    if apex in src_clean:
                                        js_urls.append(src_clean)
                                elif src_clean.startswith("/"):
                                    js_urls.append(base_url + src_clean)

                            for js_url in js_urls[:10]:  # Up to 10 JS bundles per host
                                try:
                                    js_resp = await client.get(js_url, headers=headers, timeout=2.0)
                                    if js_resp.status_code == 200 and js_resp.text:
                                        js_text = js_resp.text.replace(r"\/", "/")
                                        for m in url_pat.findall(js_text):
                                            m_clean = m.strip(".").lower()
                                            if m_clean.endswith("." + apex) and m_clean != apex:
                                                host_candidates.add(m_clean)
                                        for m in subdomain_pat.findall(js_text):
                                            m_clean = m.strip(".").lower()
                                            if m_clean.endswith("." + apex) and m_clean != apex:
                                                host_candidates.add(m_clean)
                                except Exception:
                                    pass

                        # 4. Crawl /robots.txt
                        try:
                            robots_resp = await client.get(f"{base_url}/robots.txt", headers=headers, timeout=1.8)
                            if robots_resp.status_code == 200 and robots_resp.text:
                                for m in subdomain_pat.findall(robots_resp.text):
                                    m_clean = m.strip(".").lower()
                                    if m_clean.endswith("." + apex) and m_clean != apex:
                                        host_candidates.add(m_clean)
                        except Exception:
                            pass

                        # 5. Crawl /sitemap.xml
                        try:
                            sitemap_resp = await client.get(f"{base_url}/sitemap.xml", headers=headers, timeout=1.8)
                            if sitemap_resp.status_code == 200 and sitemap_resp.text:
                                for m in url_pat.findall(sitemap_resp.text):
                                    m_clean = m.strip(".").lower()
                                    if m_clean.endswith("." + apex) and m_clean != apex:
                                        host_candidates.add(m_clean)
                        except Exception:
                            pass

                        # 6. Crawl /.well-known/security.txt
                        try:
                            sec_resp = await client.get(f"{base_url}/.well-known/security.txt", headers=headers, timeout=1.5)
                            if sec_resp.status_code == 200 and sec_resp.text:
                                for m in subdomain_pat.findall(sec_resp.text):
                                    m_clean = m.strip(".").lower()
                                    if m_clean.endswith("." + apex) and m_clean != apex:
                                        host_candidates.add(m_clean)
                        except Exception:
                            pass

                        # 7. Crawl common app endpoints: /login, /portal, /api, /docs
                        for app_path in ("/login", "/portal", "/api", "/docs"):
                            try:
                                ep_resp = await client.get(f"{base_url}{app_path}", headers=headers, timeout=1.8)
                                if ep_resp.status_code < 500 and ep_resp.text:
                                    ep_text = ep_resp.text.replace(r"\/", "/")
                                    for m in url_pat.findall(ep_text):
                                        m_clean = m.strip(".").lower()
                                        if m_clean.endswith("." + apex) and m_clean != apex:
                                            host_candidates.add(m_clean)
                                    for m in subdomain_pat.findall(ep_text):
                                        m_clean = m.strip(".").lower()
                                        if m_clean.endswith("." + apex) and m_clean != apex:
                                            host_candidates.add(m_clean)
                            except Exception:
                                pass

                        return host_candidates

                tasks = [_scrape_host(h) for h in current_batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, set):
                        all_candidate_hosts.update(r)

                # Filter and normalize candidate subdomains
                new_clean_candidates = [
                    c for c in all_candidate_hosts
                    if c.endswith("." + apex)
                    and c != apex
                    and all(ch.isalnum() or ch in ".-_" for ch in c)
                    and c not in discovered_live_assets
                ]

                # Immediate active verification of candidate subdomains (uncapped)
                if new_clean_candidates:
                    resolved_cand_map = await cls._resolve_hosts(new_clean_candidates, timeout=1.5)
                    active_cand = [c for c, ips in resolved_cand_map.items() if ips]

                    async def _verify_cand(sub: str):
                        res = await cls._verify_live_service(sub)
                        return sub, res

                    probe_tasks = [_verify_cand(c) for c in active_cand]
                    probed = await asyncio.gather(*probe_tasks, return_exceptions=True)

                    new_live_subs: list[str] = []
                    for item in probed:
                        if isinstance(item, tuple):
                            sub, res = item
                            is_live = res[0]
                            scheme = res[1]
                            port = res[2]
                            status_code = res[3]
                            duration_ms = res[4]
                            server = res[5] if len(res) > 5 else None
                            title = res[6] if len(res) > 6 else None
                            ips = resolved_cand_map.get(sub, [])

                            discovered_live_assets[sub] = {
                                "is_live": is_live,
                                "scheme": scheme,
                                "port": port,
                                "status_code": status_code,
                                "response_time_ms": duration_ms,
                                "server_banner": server,
                                "page_title": title,
                                "ip_addresses": ips,
                                "sources": ["Live Web Scraper (HTML/JS/CSP/Sitemap)"],
                                "live_scraped": True,
                            }
                            if is_live and sub not in visited_hosts:
                                new_live_subs.append(sub)

                    for c in new_clean_candidates:
                        if c not in discovered_live_assets:
                            ips = resolved_cand_map.get(c, [])
                            discovered_live_assets[c] = {
                                "is_live": False,
                                "scheme": "https",
                                "port": 443,
                                "status_code": None,
                                "response_time_ms": None,
                                "server_banner": None,
                                "page_title": None,
                                "ip_addresses": ips,
                                "sources": ["Live Web Scraper (HTML/JS/CSP/Sitemap)"],
                                "live_scraped": True,
                            }

                    if current_depth < max_depth and new_live_subs:
                        queue.extend(new_live_subs[:20])

                    batch_items = [
                        {
                            "subdomain": sub,
                            "canonical_url": f"{data.get('scheme', 'https')}://{sub}/",
                            "ip_addresses": data.get("ip_addresses", []),
                            "is_live": data.get("is_live", False),
                            "scheme": data.get("scheme", "https"),
                            "port": data.get("port", 443),
                            "status_code": data.get("status_code"),
                            "response_time_ms": data.get("response_time_ms"),
                            "server_banner": data.get("server_banner"),
                            "page_title": data.get("page_title"),
                            "live_scraped": True,
                            "sources": ["Live Web Scraper (HTML/JS/CSP/Sitemap)"],
                            "is_already_in_inventory": False,
                        }
                        for sub, data in discovered_live_assets.items()
                        if sub in new_clean_candidates
                    ]
                    probe_pct = min(56, batch_pct + 4)
                    await _emit_progress(
                        probe_pct,
                        f"Live scraper confirmed {len(new_live_subs)} active web endpoints (depth {current_depth})...",
                        batch_items,
                    )

                current_depth += 1

        return discovered_live_assets

    @classmethod
    async def discover(cls, request: SubdomainDiscoveryRequest, db: Session) -> SubdomainDiscoveryResponse:
        """Run complete unbounded subdomain discovery workflow across CT logs, passive DNS,
        authoritative DNS mining, adaptive target vocabulary, live web scraping, and live probing."""
        apex = cls.normalize_apex_domain(request.domain)
        candidate_sources: dict[str, list[str]] = {}
        known_ips: dict[str, list[str]] = {}
        ct_subdomains: set[str] = set()

        # Step 1: Wildcard DNS Canary Detection
        wildcard_task = cls._detect_wildcard_dns(apex)

        # Step 2: Multi-Engine Passive OSINT & Certificate Intelligence
        if request.include_cert_transparency:
            crt_task = cls._query_crt_sh(apex)
            ht_task = cls._query_hackertarget(apex)
            urlscan_task = cls._query_urlscan(apex)
            cs_task = cls._query_certspotter(apex)
            otx_task = cls._query_alienvault(apex)
            anubis_task = cls._query_anubis(apex)
            wayback_task = cls._query_wayback_cdx(apex)
            sc_task = cls._query_subdomain_center(apex)

            results = await asyncio.gather(
                wildcard_task, crt_task, ht_task, urlscan_task, cs_task, otx_task, anubis_task, wayback_task, sc_task, return_exceptions=True
            )
            wildcard_ips = results[0] if isinstance(results[0], set) else set()
            crt_hosts = results[1] if isinstance(results[1], set) else set()
            ht_data = results[2] if isinstance(results[2], tuple) else (set(), {})
            urlscan_hosts = results[3] if isinstance(results[3], set) else set()
            cs_hosts = results[4] if isinstance(results[4], set) else set()
            otx_hosts = results[5] if isinstance(results[5], set) else set()
            anubis_hosts = results[6] if isinstance(results[6], set) else set()
            wayback_hosts = results[7] if isinstance(results[7], set) else set()
            sc_hosts = results[8] if isinstance(results[8], set) else set()

            ht_hosts, ht_ips = ht_data
            for h, ips in ht_ips.items():
                known_ips[h] = ips

            for h in crt_hosts:
                candidate_sources.setdefault(h, []).append("Certificate Transparency (crt.sh)")
                ct_subdomains.add(h)
            for h in ht_hosts:
                candidate_sources.setdefault(h, []).append("Passive DNS (HackerTarget)")
                ct_subdomains.add(h)
            for h in urlscan_hosts:
                candidate_sources.setdefault(h, []).append("Passive Intelligence (URLScan.io)")
                ct_subdomains.add(h)
            for h in cs_hosts:
                candidate_sources.setdefault(h, []).append("Certificate Transparency (CertSpotter)")
                ct_subdomains.add(h)
            for h in otx_hosts:
                candidate_sources.setdefault(h, []).append("Passive DNS (AlienVault)")
                ct_subdomains.add(h)
            for h in anubis_hosts:
                candidate_sources.setdefault(h, []).append("Passive Intelligence (Anubis)")
                ct_subdomains.add(h)
            for h in wayback_hosts:
                candidate_sources.setdefault(h, []).append("Passive Intelligence (Wayback Machine)")
                ct_subdomains.add(h)
            for h in sc_hosts:
                candidate_sources.setdefault(h, []).append("Passive Intelligence (Subdomain Center)")
                ct_subdomains.add(h)
        else:
            wildcard_ips = await wildcard_task

        # Integrate Sector Intelligence for jurisdictional & public apex domains
        sector_hosts = cls._generate_sector_intelligence(apex)
        for h in sector_hosts:
            candidate_sources.setdefault(h, []).append("Sector Intelligence & Registry")
            ct_subdomains.add(h)

        # Step 3: Authoritative DNS Mining (TXT/SPF, MX, NS) & Real-Time Live Web/JS Scraping
        dns_mined_task = cls._mine_dns_authoritative_records(apex)
        web_mined_task = cls._mine_live_web_assets(list(candidate_sources.keys()), apex)
        dns_mined, web_mined = await asyncio.gather(dns_mined_task, web_mined_task)

        for h in dns_mined:
            candidate_sources.setdefault(h, []).append("DNS Protocol Mining (DoH)")
        for h in web_mined:
            candidate_sources.setdefault(h, []).append("Live Web & CSP Mining")

        live_scraped_map: dict[str, dict[str, Any]] = {}
        if getattr(request, "enable_live_scraping", True):
            seed_hosts = [apex, f"www.{apex}"] + [h for h in candidate_sources.keys() if known_ips.get(h)][:30]
            live_scraped_map = await cls._live_scrape_target_network(
                apex, seed_hosts, max_hosts=50, max_depth=getattr(request, "scrape_depth", 2)
            )
            for h, data in live_scraped_map.items():
                candidate_sources.setdefault(h, []).append("Live Web Scraper (HTML/JS/CSP/Sitemap)")
                ips = data.get("ip_addresses", [])
                if ips:
                    known_ips[h] = ips

        # Step 4: Adaptive Target Vocabulary Mining & Unbounded Dynamic Candidate Generation
        if request.include_dns_probe:
            unbounded_candidates = cls._generate_unbounded_candidates(
                apex, list(candidate_sources.keys()), max_candidates=None
            )
            # Resolve all synthesized dynamic candidates asynchronously with zero packet loss
            resolved_map = await cls._resolve_hosts(unbounded_candidates, timeout=1.8)

            for h, ips in resolved_map.items():
                if ips:
                    if wildcard_ips and h not in ct_subdomains:
                        if set(ips).issubset(wildcard_ips):
                            continue
                    candidate_sources.setdefault(h, []).append("Adaptive Target Vocabulary & Heuristics")
                    known_ips[h] = ips

        # Step 5: High-Speed DNS Resolution for unresolved discovered hosts
        unresolved_hosts = [h for h in candidate_sources.keys() if not known_ips.get(h)]
        if unresolved_hosts:
            dns_resolutions = await cls._resolve_hosts(unresolved_hosts, timeout=1.6)
            for h, ips in dns_resolutions.items():
                if ips:
                    known_ips[h] = ips

        # All discovered hosts are preserved as valid reconnaissance assets
        all_hosts = [h for h in candidate_sources.keys() if h != apex]

        # Step 6: Database Scope & Inventory Cross-Reference
        existing_assets = []
        if all_hosts:
            stmt = select(AuthorizedAsset).where(AuthorizedAsset.host.in_(all_hosts))
            existing_assets = list(db.scalars(stmt).all())
        existing_asset_map: dict[str, AuthorizedAsset] = {a.host: a for a in existing_assets}

        # Step 7: Live Service Verification (HTTP/HTTPS) - Uncapped
        items: list[DiscoveredSubdomain] = []
        dns_active_count = sum(1 for h in all_hosts if known_ips.get(h))

        if request.verify_live and all_hosts:
            verification_pool = [h for h in all_hosts if known_ips.get(h)]
            if not verification_pool:
                verification_pool = list(all_hosts)

            sem = asyncio.Semaphore(50)

            async def _probe(sub: str):
                async with sem:
                    return sub, await cls._verify_live_service(sub)

            probe_tasks = [_probe(h) for h in verification_pool]
            probe_results = await asyncio.gather(*probe_tasks)
            live_map: dict[str, tuple] = {h: res for h, res in probe_results}

            for sub in all_hosts:
                existing = existing_asset_map.get(sub)
                probe_res = live_map.get(sub)
                scraped_res = live_scraped_map.get(sub)

                if probe_res:
                    is_live = probe_res[0]
                    scheme = probe_res[1]
                    port = probe_res[2]
                    status_code = probe_res[3]
                    resp_time = probe_res[4]
                    server_banner = probe_res[5] if len(probe_res) > 5 else None
                    page_title = probe_res[6] if len(probe_res) > 6 else None
                elif scraped_res:
                    is_live = scraped_res.get("is_live", False)
                    scheme = scraped_res.get("scheme", "https")
                    port = scraped_res.get("port", 443)
                    status_code = scraped_res.get("status_code")
                    resp_time = scraped_res.get("response_time_ms")
                    server_banner = scraped_res.get("server_banner")
                    page_title = scraped_res.get("page_title")
                else:
                    is_live, scheme, port, status_code, resp_time, server_banner, page_title = False, "https", 443, None, None, None, None

                is_live_scraped = (scraped_res is not None and scraped_res.get("live_scraped", False)) or any(
                    "Live Web Scraper" in s for s in candidate_sources.get(sub, [])
                )

                items.append(
                    DiscoveredSubdomain(
                        subdomain=sub,
                        canonical_url=f"{scheme}://{sub}{'' if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80) else f':{port}'}/",
                        ip_addresses=known_ips.get(sub, []),
                        is_live=is_live,
                        scheme=scheme,
                        port=port,
                        status_code=status_code,
                        response_time_ms=resp_time,
                        server_banner=server_banner,
                        page_title=page_title,
                        live_scraped=is_live_scraped,
                        sources=candidate_sources.get(sub, ["Reconnaissance Engine"]),
                        is_already_in_inventory=existing is not None,
                        existing_asset_id=existing.id if existing else None,
                    )
                )
        else:
            for sub in all_hosts:
                existing = existing_asset_map.get(sub)
                scraped_res = live_scraped_map.get(sub)
                is_live_scraped = (scraped_res is not None and scraped_res.get("live_scraped", False)) or any(
                    "Live Web Scraper" in s for s in candidate_sources.get(sub, [])
                )
                items.append(
                    DiscoveredSubdomain(
                        subdomain=sub,
                        canonical_url=f"https://{sub}/",
                        ip_addresses=known_ips.get(sub, []),
                        is_live=False,
                        scheme="https",
                        port=443,
                        status_code=None,
                        response_time_ms=None,
                        server_banner=None,
                        page_title=scraped_res.get("page_title") if scraped_res else None,
                        live_scraped=is_live_scraped,
                        sources=candidate_sources.get(sub, ["Reconnaissance Engine"]),
                        is_already_in_inventory=existing is not None,
                        existing_asset_id=existing.id if existing else None,
                    )
                )

        # Sort: Live subdomains first, then DNS active (has IPs), then alphabetically
        items.sort(key=lambda x: (not x.is_live, len(x.ip_addresses) == 0, x.subdomain))
        live_count = sum(1 for item in items if item.is_live)
        live_scraped_count = sum(1 for item in items if item.live_scraped)

        # Sources Breakdown Summary
        sources_summary: dict[str, int] = {}
        for item in items:
            for src in item.sources:
                sources_summary[src] = sources_summary.get(src, 0) + 1

        return SubdomainDiscoveryResponse(
            target_domain=apex,
            total_discovered=len(items),
            live_count=live_count,
            dns_active_count=dns_active_count,
            live_scraped_count=live_scraped_count,
            sources_summary=sources_summary,
            subdomains=items,
            discovered_at=datetime.now(timezone.utc),
        )

    @classmethod
    async def discover_stream(
        cls, request: SubdomainDiscoveryRequest, db: Session
    ) -> AsyncGenerator[dict, None]:
        """Continuous live reconnaissance generator streaming progressive discovery batches by phase."""
        apex = cls.normalize_apex_domain(request.domain)
        candidate_sources: dict[str, list[str]] = {}
        known_ips: dict[str, list[str]] = {}
        ct_subdomains: set[str] = set()

        # Phase 1: Passive Intelligence Gathering - Progressive Non-Blocking Stream
        yield {
            "type": "phase",
            "phase": "Multi-Engine Passive Intelligence",
            "stage": 1,
            "total_stages": 7,
            "progress": 6,
            "message": f"Harvesting Certificate Transparency, Passive DNS & Wayback CDX for '{apex}'...",
        }

        wildcard_ips = set()
        if request.include_cert_transparency:
            passive_sources = [
                ("Passive Intelligence (URLScan.io)", cls._query_urlscan(apex)),
                ("Passive DNS (Subdomain Center)", cls._query_subdomain_center(apex)),
                ("Passive DNS (HackerTarget)", cls._query_hackertarget(apex)),
                ("Certificate Transparency (CertSpotter)", cls._query_certspotter(apex)),
                ("Passive DNS (AlienVault)", cls._query_alienvault(apex)),
                ("Passive Intelligence (Anubis)", cls._query_anubis(apex)),
                ("Certificate Transparency (crt.sh)", cls._query_crt_sh(apex)),
                ("Passive Intelligence (Wayback Machine)", cls._query_wayback_cdx(apex)),
            ]

            async def _run_source(src_name: str, coro):
                try:
                    res = await coro
                    return src_name, res
                except Exception as exc:
                    return src_name, exc

            tasks = [asyncio.create_task(_run_source(name, coro)) for name, coro in passive_sources]
            completed_sources = 0

            for fut in asyncio.as_completed(tasks):
                name, res = await fut
                completed_sources += 1
                new_items = []

                if isinstance(res, tuple):  # HackerTarget returns (hosts, ip_map)
                    ht_hosts, ht_ips = res
                    for h, ips in ht_ips.items():
                        known_ips[h] = ips
                    for h in ht_hosts:
                        if h != apex and all(c.isalnum() or c in ".-_" for c in h):
                            is_new = h not in candidate_sources
                            candidate_sources.setdefault(h, []).append(name)
                            ct_subdomains.add(h)
                            if is_new:
                                new_items.append(
                                    {
                                        "subdomain": h,
                                        "canonical_url": f"https://{h}/",
                                        "ip_addresses": known_ips.get(h, []),
                                        "is_live": False,
                                        "scheme": "https",
                                        "port": 443,
                                        "status_code": None,
                                        "response_time_ms": None,
                                        "sources": [name],
                                        "is_already_in_inventory": False,
                                    }
                                )
                elif isinstance(res, set):
                    for h in res:
                        if h != apex and all(c.isalnum() or c in ".-_" for c in h):
                            is_new = h not in candidate_sources
                            candidate_sources.setdefault(h, []).append(name)
                            ct_subdomains.add(h)
                            if is_new:
                                new_items.append(
                                    {
                                        "subdomain": h,
                                        "canonical_url": f"https://{h}/",
                                        "ip_addresses": known_ips.get(h, []),
                                        "is_live": False,
                                        "scheme": "https",
                                        "port": 443,
                                        "status_code": None,
                                        "response_time_ms": None,
                                        "sources": [name],
                                        "is_already_in_inventory": False,
                                    }
                                )

                pct = 6 + int((completed_sources / len(tasks)) * 18)  # 6% -> 24%
                if new_items:
                    chunk_size = 200
                    for i in range(0, len(new_items), chunk_size):
                        batch_slice = new_items[i : i + chunk_size]
                        yield {
                            "type": "batch",
                            "phase": "Passive Intelligence Gathering",
                            "count": len(batch_slice),
                            "total_discovered": len(candidate_sources),
                            "items": batch_slice,
                        }
                yield {
                    "type": "phase",
                    "phase": "Passive Intelligence Gathering",
                    "stage": 1,
                    "total_stages": 7,
                    "progress": pct,
                    "message": f"Harvested assets from {name} ({completed_sources}/{len(tasks)} sources complete, {len(candidate_sources)} subdomains)...",
                }
        else:
            yield {
                "type": "phase",
                "phase": "Passive Intelligence Gathering",
                "stage": 1,
                "total_stages": 7,
                "progress": 24,
                "message": "Passive intelligence phase complete.",
            }

        # Sector Intelligence & Registry Assets (e.g. gov.in, nic.in, public sector)
        sector_hosts = cls._generate_sector_intelligence(apex)
        if sector_hosts:
            sector_items = []
            for h in sector_hosts:
                if h != apex and all(c.isalnum() or c in ".-_" for c in h):
                    is_new = h not in candidate_sources
                    candidate_sources.setdefault(h, []).append("Sector Intelligence & Registry")
                    ct_subdomains.add(h)
                    if is_new:
                        sector_items.append(
                            {
                                "subdomain": h,
                                "canonical_url": f"https://{h}/",
                                "ip_addresses": known_ips.get(h, []),
                                "is_live": False,
                                "scheme": "https",
                                "port": 443,
                                "status_code": None,
                                "response_time_ms": None,
                                "sources": ["Sector Intelligence & Registry"],
                                "is_already_in_inventory": False,
                            }
                        )
            if sector_items:
                chunk_size = 200
                for i in range(0, len(sector_items), chunk_size):
                    batch_slice = sector_items[i : i + chunk_size]
                    yield {
                        "type": "batch",
                        "phase": "Sector Intelligence & Registry",
                        "count": len(batch_slice),
                        "total_discovered": len(candidate_sources),
                        "items": batch_slice,
                    }
            yield {
                "type": "phase",
                "phase": "Sector Intelligence & Registry",
                "stage": 1,
                "total_stages": 7,
                "progress": 26,
                "message": f"Integrated {len(sector_hosts)} sector-specific authoritative assets for '{apex}' (Total: {len(candidate_sources)})...",
            }

        # Phase 2: Authoritative DNS Mining & Web Asset Extraction
        yield {
            "type": "phase",
            "phase": "Authoritative DNS & Live Web Mining",
            "stage": 2,
            "total_stages": 7,
            "progress": 27,
            "message": "Mining DNS TXT/SPF/MX/NS records via DoH and inspecting live web CSP headers...",
        }
        dns_mined_task = asyncio.create_task(cls._mine_dns_authoritative_records(apex))
        web_mined_task = asyncio.create_task(cls._mine_live_web_assets(list(candidate_sources.keys()), apex))

        p2_tasks = [
            ("DNS Protocol Mining (DoH)", dns_mined_task),
            ("Live Web & CSP Mining", web_mined_task),
        ]
        completed_p2 = 0
        for fut in asyncio.as_completed([t[1] for t in p2_tasks]):
            res_hosts = await fut
            completed_p2 += 1
            new_p2_items = []
            for h in res_hosts:
                if h not in candidate_sources and h != apex:
                    candidate_sources.setdefault(h, []).append("Authoritative DNS / Web Mining")
                    new_p2_items.append(
                        {
                            "subdomain": h,
                            "canonical_url": f"https://{h}/",
                            "ip_addresses": [],
                            "is_live": False,
                            "scheme": "https",
                            "port": 443,
                            "sources": ["Authoritative DNS / Web Mining"],
                            "is_already_in_inventory": False,
                        }
                    )
            if new_p2_items:
                yield {
                    "type": "batch",
                    "phase": "Authoritative DNS & Web Mining",
                    "count": len(new_p2_items),
                    "total_discovered": len(candidate_sources),
                    "items": new_p2_items,
                }
            pct = 27 + int((completed_p2 / 2) * 6)  # 27% -> 33%
            yield {
                "type": "phase",
                "phase": "Authoritative DNS & Live Web Mining",
                "stage": 2,
                "total_stages": 7,
                "progress": pct,
                "message": f"Zone and web asset mining ({completed_p2}/2 complete, {len(candidate_sources)} assets)...",
            }

        # Phase 3: Wildcard DNS Canary & Core DNS Resolution
        yield {
            "type": "phase",
            "phase": "Wildcard Suppression & Host Resolution",
            "stage": 3,
            "total_stages": 7,
            "progress": 34,
            "message": "Detecting wildcard DNS canary records...",
        }
        wildcard_ips = await cls._detect_wildcard_dns(apex)
        yield {
            "type": "phase",
            "phase": "Wildcard Suppression & Host Resolution",
            "stage": 3,
            "total_stages": 7,
            "progress": 36,
            "message": f"Wildcard detection complete ({len(wildcard_ips)} wildcard IPs). Resolving passive hostnames...",
        }

        async def _safe_resolve(chunk: list[str], timeout: float, client: httpx.AsyncClient | None = None) -> dict[str, list[str]]:
            try:
                return await cls._resolve_hosts(chunk, timeout=timeout, client=client)
            except TypeError:
                return await cls._resolve_hosts(chunk, timeout=timeout)

        unresolved_passive = [h for h in candidate_sources.keys() if not known_ips.get(h)]
        if unresolved_passive:
            dns_chunk_size = 250
            total_unresolved = len(unresolved_passive)
            async with httpx.AsyncClient(
                headers={"accept": "application/dns-json"},
                verify=False,
                limits=httpx.Limits(max_connections=200, max_keepalive_connections=150),
            ) as doh_client:
                for i in range(0, total_unresolved, dns_chunk_size):
                    chunk = unresolved_passive[i : i + dns_chunk_size]
                    resolved_chunk = await _safe_resolve(chunk, timeout=1.4, client=doh_client)
                    active_updates = []
                    for h, ips in resolved_chunk.items():
                        if ips:
                            known_ips[h] = ips
                            active_updates.append(
                                {
                                    "subdomain": h,
                                    "canonical_url": f"https://{h}/",
                                    "ip_addresses": ips,
                                    "is_live": False,
                                    "scheme": "https",
                                    "port": 443,
                                    "sources": candidate_sources.get(h, ["Reconnaissance Engine"]),
                                    "is_already_in_inventory": False,
                                }
                            )
                    if active_updates:
                        yield {
                            "type": "batch",
                            "phase": "Host Resolution",
                            "count": len(active_updates),
                            "total_discovered": len(candidate_sources),
                            "items": active_updates,
                        }
                    pct = 36 + int(((i + len(chunk)) / total_unresolved) * 8)
                    dns_active = sum(1 for h in candidate_sources.keys() if known_ips.get(h))
                    yield {
                        "type": "phase",
                        "phase": "Wildcard Suppression & Host Resolution",
                        "stage": 3,
                        "total_stages": 7,
                        "progress": pct,
                        "message": f"Resolving asset DNS records ({min(i + len(chunk), total_unresolved)}/{total_unresolved})... Active DNS: {dns_active}",
                    }

        # Phase 4: Active Real-Time Live Web Scraping & JavaScript Spidering
        live_scraped_map: dict[str, dict[str, Any]] = {}
        if getattr(request, "enable_live_scraping", True):
            yield {
                "type": "phase",
                "phase": "Live Web Scraping & JavaScript Spidering",
                "stage": 4,
                "total_stages": 7,
                "progress": 45,
                "message": "Actively scraping live HTML, JS bundles, sitemaps, and CSP headers for live subdomains...",
            }
            seed_hosts = [apex, f"www.{apex}"] + [h for h in candidate_sources.keys() if known_ips.get(h)][:30]

            scrape_queue = asyncio.Queue()

            async def _on_scrape_progress(pct: int, msg: str, items: list[dict[str, Any]]):
                await scrape_queue.put((pct, msg, items))

            scrape_task = asyncio.create_task(
                cls._live_scrape_target_network(
                    apex,
                    seed_hosts,
                    max_hosts=50,
                    max_depth=getattr(request, "scrape_depth", 2),
                    progress_callback=_on_scrape_progress,
                )
            )

            while not scrape_task.done():
                try:
                    pct, msg, items = await asyncio.wait_for(scrape_queue.get(), timeout=0.3)
                    new_yield_items = []
                    for it in items:
                        sub = it["subdomain"]
                        if sub not in candidate_sources:
                            candidate_sources.setdefault(sub, []).append("Live Web Scraper (HTML/JS/CSP/Sitemap)")
                            ips = it.get("ip_addresses", [])
                            if ips:
                                known_ips[sub] = ips
                            new_yield_items.append(it)
                    if new_yield_items:
                        yield {
                            "type": "batch",
                            "phase": "Live Web Scraping & JavaScript Spidering",
                            "count": len(new_yield_items),
                            "total_discovered": len(candidate_sources),
                            "items": new_yield_items,
                        }
                    yield {
                        "type": "phase",
                        "phase": "Live Web Scraping & JavaScript Spidering",
                        "stage": 4,
                        "total_stages": 7,
                        "progress": pct,
                        "message": msg,
                    }
                except asyncio.TimeoutError:
                    pass

            live_scraped_map = await scrape_task

            # Drain any remaining updates from queue
            while not scrape_queue.empty():
                pct, msg, items = scrape_queue.get_nowait()
                new_yield_items = []
                for it in items:
                    sub = it["subdomain"]
                    if sub not in candidate_sources:
                        candidate_sources.setdefault(sub, []).append("Live Web Scraper (HTML/JS/CSP/Sitemap)")
                        ips = it.get("ip_addresses", [])
                        if ips:
                            known_ips[sub] = ips
                        new_yield_items.append(it)
                if new_yield_items:
                    yield {
                        "type": "batch",
                        "phase": "Live Web Scraping & JavaScript Spidering",
                        "count": len(new_yield_items),
                        "total_discovered": len(candidate_sources),
                        "items": new_yield_items,
                    }

            live_scraped_confirmed = sum(1 for d in live_scraped_map.values() if d.get("is_live"))
            yield {
                "type": "phase",
                "phase": "Live Web Scraping & JavaScript Spidering",
                "stage": 4,
                "total_stages": 7,
                "progress": 56,
                "message": f"Live scraper discovered {len(live_scraped_map)} assets ({live_scraped_confirmed} live active web endpoints).",
            }

        # Phase 5: Adaptive Target Vocabulary Mining & Unbounded Dynamic Candidate Generation
        if request.include_dns_probe:
            mined_tokens = cls._mine_target_vocabulary(list(candidate_sources.keys()), apex)
            yield {
                "type": "phase",
                "phase": "Adaptive Target Vocabulary & Dynamic Probing",
                "stage": 5,
                "total_stages": 7,
                "progress": 58,
                "message": f"Mined {len(mined_tokens)} target naming stems. Synthesizing unbounded candidates & permutations...",
            }
            unbounded_candidates = cls._generate_unbounded_candidates(
                apex, list(candidate_sources.keys()), max_candidates=None
            )
            # Only probe candidates not already discovered
            probe_candidates = [h for h in unbounded_candidates if h not in candidate_sources]
            total_probing = len(probe_candidates)

            if total_probing > 0:
                probe_chunk_size = 300
                async with httpx.AsyncClient(
                    headers={"accept": "application/dns-json"},
                    verify=False,
                    limits=httpx.Limits(max_connections=200, max_keepalive_connections=150),
                ) as doh_client:
                    for i in range(0, total_probing, probe_chunk_size):
                        chunk = probe_candidates[i : i + probe_chunk_size]
                        candidate_dns = await _safe_resolve(chunk, timeout=1.4, client=doh_client)

                        new_dict_items = []
                        for h, ips in candidate_dns.items():
                            if ips:
                                if wildcard_ips and h not in ct_subdomains:
                                    if set(ips).issubset(wildcard_ips):
                                        continue
                                candidate_sources.setdefault(h, []).append("Adaptive Target Vocabulary & Heuristics")
                                known_ips[h] = ips
                                new_dict_items.append(
                                    {
                                        "subdomain": h,
                                        "canonical_url": f"https://{h}/",
                                        "ip_addresses": ips,
                                        "is_live": False,
                                        "scheme": "https",
                                        "port": 443,
                                        "status_code": None,
                                        "response_time_ms": None,
                                        "sources": candidate_sources.get(h, ["Adaptive Target Vocabulary & Heuristics"]),
                                        "is_already_in_inventory": False,
                                    }
                                )

                        if new_dict_items:
                            yield {
                                "type": "batch",
                                "phase": "Adaptive Target Vocabulary Probing",
                                "count": len(new_dict_items),
                                "total_discovered": len(candidate_sources),
                                "items": new_dict_items,
                            }

                        pct = 58 + int(((i + len(chunk)) / total_probing) * 14)
                        yield {
                            "type": "phase",
                            "phase": "Adaptive Target Vocabulary & Dynamic Probing",
                            "stage": 5,
                            "total_stages": 7,
                            "progress": pct,
                            "message": f"Probing synthesized permutations ({min(i + len(chunk), total_probing)}/{total_probing})... Discovered: {len(candidate_sources)}",
                        }

        # Phase 6: Recursive Multi-Level Sub-Branch Permutations
        if request.include_permutations or request.continuous_scan:
            yield {
                "type": "phase",
                "phase": "Recursive Sub-Branch Discovery",
                "stage": 6,
                "total_stages": 7,
                "progress": 72,
                "message": "Generating recursive multi-level child subdomains across discovered services...",
            }
            top_roots = list(candidate_sources.keys())
            permutations = cls._generate_permutations(top_roots, apex, max_candidates=200)
            perm_candidates = [h for h in permutations if h not in candidate_sources]
            if perm_candidates:
                perm_chunk_size = 200
                total_perms = len(perm_candidates)
                async with httpx.AsyncClient(
                    headers={"accept": "application/dns-json"},
                    verify=False,
                    limits=httpx.Limits(max_connections=200, max_keepalive_connections=150),
                ) as doh_client:
                    for i in range(0, total_perms, perm_chunk_size):
                        chunk = perm_candidates[i : i + perm_chunk_size]
                        perm_dns = await _safe_resolve(chunk, timeout=1.4, client=doh_client)
                        perm_items = []
                        for h, ips in perm_dns.items():
                            if ips:
                                if wildcard_ips and h not in ct_subdomains:
                                    if set(ips).issubset(wildcard_ips):
                                        continue
                                candidate_sources.setdefault(h, []).append("Recursive Permutations")
                                known_ips[h] = ips
                                perm_items.append(
                                    {
                                        "subdomain": h,
                                        "canonical_url": f"https://{h}/",
                                        "ip_addresses": ips,
                                        "is_live": False,
                                        "scheme": "https",
                                        "port": 443,
                                        "status_code": None,
                                        "response_time_ms": None,
                                        "sources": candidate_sources.get(h, ["Recursive Permutations"]),
                                        "is_already_in_inventory": False,
                                    }
                                )
                        if perm_items:
                            yield {
                                "type": "batch",
                                "phase": "Recursive Sub-Branch Discovery",
                                "count": len(perm_items),
                                "total_discovered": len(candidate_sources),
                                "items": perm_items,
                            }
                        pct = 72 + int(((i + len(chunk)) / total_perms) * 10)
                        yield {
                            "type": "phase",
                            "phase": "Recursive Sub-Branch Discovery",
                            "stage": 6,
                            "total_stages": 7,
                            "progress": pct,
                            "message": f"Analyzing child sub-branches ({min(i + len(chunk), total_perms)}/{total_perms})... Discovered: {len(candidate_sources)}",
                        }

        # Phase 7: Live HTTP/HTTPS Verification
        all_hosts = [h for h in candidate_sources.keys() if h != apex]
        stmt = select(AuthorizedAsset).where(AuthorizedAsset.host.in_(all_hosts))
        existing_assets = list(db.scalars(stmt).all())
        existing_asset_map = {a.host: a for a in existing_assets}

        yield {
            "type": "phase",
            "phase": "Live Service Verification (HTTP/HTTPS)",
            "stage": 7,
            "total_stages": 7,
            "progress": 82,
            "message": "Probing live HTTP/HTTPS services, latency, page titles, and technology banners...",
        }

        live_map = {}
        if request.verify_live and all_hosts:
            probe_targets = [h for h in all_hosts if known_ips.get(h)]
            if not probe_targets:
                probe_targets = list(all_hosts)

            total_probes = len(probe_targets)
            if total_probes > 0:
                probe_chunk_size = 50
                sem = asyncio.Semaphore(50)

                async def _probe(sub: str):
                    async with sem:
                        return sub, await cls._verify_live_service(sub)

                live_count = 0
                for i in range(0, total_probes, probe_chunk_size):
                    chunk = probe_targets[i : i + probe_chunk_size]
                    probe_tasks = [_probe(h) for h in chunk]
                    probe_results = await asyncio.gather(*probe_tasks)
                    live_updates = []
                    for sub, res in probe_results:
                        live_map[sub] = res
                        if res and res[0]:
                            live_count += 1
                            server = res[5] if len(res) > 5 else None
                            title = res[6] if len(res) > 6 else None
                            scraped_info = live_scraped_map.get(sub)
                            is_scraped = (scraped_info is not None and scraped_info.get("live_scraped", False)) or any(
                                "Live Web Scraper" in s for s in candidate_sources.get(sub, [])
                            )
                            live_updates.append(
                                {
                                    "subdomain": sub,
                                    "canonical_url": f"{res[1]}://{sub}{'' if (res[1] == 'https' and res[2] == 443) or (res[1] == 'http' and res[2] == 80) else f':{res[2]}'}/",
                                    "ip_addresses": known_ips.get(sub, []),
                                    "is_live": True,
                                    "scheme": res[1],
                                    "port": res[2],
                                    "status_code": res[3],
                                    "response_time_ms": res[4],
                                    "server_banner": server,
                                    "page_title": title,
                                    "live_scraped": is_scraped,
                                    "sources": candidate_sources.get(sub, ["Live Verification"]),
                                    "is_already_in_inventory": existing_asset_map.get(sub) is not None,
                                }
                            )
                    if live_updates:
                        yield {
                            "type": "batch",
                            "phase": "Live Service Verification",
                            "count": len(live_updates),
                            "total_discovered": len(candidate_sources),
                            "items": live_updates,
                        }
                    pct = 82 + int(((i + len(chunk)) / total_probes) * 15)
                    yield {
                        "type": "phase",
                        "phase": "Live Service Verification (HTTP/HTTPS)",
                        "stage": 7,
                        "total_stages": 7,
                        "progress": pct,
                        "message": f"Verifying live HTTP/HTTPS services ({min(i + len(chunk), total_probes)}/{total_probes})... Live verified: {live_count}",
                    }

        final_items = []
        for sub in all_hosts:
            existing = existing_asset_map.get(sub)
            probe_res = live_map.get(sub)
            scraped_res = live_scraped_map.get(sub)
            if probe_res:
                is_live, scheme, port, status_code, resp_time = (
                    probe_res[0], probe_res[1], probe_res[2], probe_res[3], probe_res[4]
                )
                server_banner = probe_res[5] if len(probe_res) > 5 else None
                page_title = probe_res[6] if len(probe_res) > 6 else None
            elif scraped_res:
                is_live = scraped_res.get("is_live", False)
                scheme = scraped_res.get("scheme", "https")
                port = scraped_res.get("port", 443)
                status_code = scraped_res.get("status_code")
                resp_time = scraped_res.get("response_time_ms")
                server_banner = scraped_res.get("server_banner")
                page_title = scraped_res.get("page_title")
            else:
                is_live, scheme, port, status_code, resp_time, server_banner, page_title = False, "https", 443, None, None, None, None

            is_scraped = (scraped_res is not None and scraped_res.get("live_scraped", False)) or any(
                "Live Web Scraper" in s for s in candidate_sources.get(sub, [])
            )

            final_items.append(
                DiscoveredSubdomain(
                    subdomain=sub,
                    canonical_url=f"{scheme}://{sub}{'' if (scheme == 'https' and port == 443) or (scheme == 'http' and port == 80) else f':{port}'}/",
                    ip_addresses=known_ips.get(sub, []),
                    is_live=is_live,
                    scheme=scheme,
                    port=port,
                    status_code=status_code,
                    response_time_ms=resp_time,
                    server_banner=server_banner,
                    page_title=page_title,
                    live_scraped=is_scraped,
                    sources=candidate_sources.get(sub, ["Reconnaissance Engine"]),
                    is_already_in_inventory=existing is not None,
                    existing_asset_id=existing.id if existing else None,
                )
            )

        final_items.sort(key=lambda x: (not x.is_live, len(x.ip_addresses) == 0, x.subdomain))
        live_count = sum(1 for item in final_items if item.is_live)
        dns_active_count = sum(1 for h in all_hosts if known_ips.get(h))
        live_scraped_count = sum(1 for item in final_items if item.live_scraped)

        sources_summary: dict[str, int] = {}
        for item in final_items:
            for src in item.sources:
                sources_summary[src] = sources_summary.get(src, 0) + 1

        final_response = SubdomainDiscoveryResponse(
            target_domain=apex,
            total_discovered=len(final_items),
            live_count=live_count,
            dns_active_count=dns_active_count,
            live_scraped_count=live_scraped_count,
            sources_summary=sources_summary,
            subdomains=final_items,
            discovered_at=datetime.now(timezone.utc),
        )

        yield {
            "type": "complete",
            "phase": "Reconnaissance Complete",
            "progress": 100,
            "target_domain": apex,
            "total_discovered": len(final_items),
            "live_count": live_count,
            "dns_active_count": dns_active_count,
            "live_scraped_count": live_scraped_count,
            "sources_summary": sources_summary,
            "result": json.loads(final_response.model_dump_json()),
        }
