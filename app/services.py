from datetime import datetime, timedelta, timezone
from .elastic_client import es
# from .database import SessionLocal
# from .models import CountIP
# from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta   
from dateutil import parser
from zoneinfo import ZoneInfo
import os
import math
import re
import json
import copy

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"
INDEX_SEARCH = "logs-*"

class FilterItem(BaseModel):
    field: str
    operator: str
    value: Optional[str] = None

class SearchRequest(BaseModel):
    filters: List[FilterItem] = []
    timeframe: Optional[str] = None


def get_time_range_filter(timeframe: str):
    jakarta_tz = ZoneInfo("Asia/Jakarta")
    now = datetime.now(tz=jakarta_tz)

    if timeframe == "today":
        # mulai dari jam 00:00 UTC
        start = datetime(now.year, now.month, now.day)
    elif timeframe == "last1minutes" or timeframe == "1minutes":
        start = now - timedelta(seconds=5)
    elif timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe == "1hours" or timeframe == "last1hours":
        start = now - timedelta(hours=1)
    elif timeframe == "8hours" or timeframe == "last8hours":
        start = now - timedelta(hours=8)
    elif timeframe == "24hours" or timeframe == "last24hours":
        start = now - timedelta(hours=24)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    elif timeframe == "last30days":
        start = now - timedelta(days=30)
    elif timeframe == "last60days":
        start = now - timedelta(days=60)
    elif timeframe == "last90days":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=1)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}}

def get_time_range_for_stats(timeframe: str):
    jakarta_tz = ZoneInfo("Asia/Jakarta")
    now = datetime.now(tz=jakarta_tz)

    if timeframe == "today":
        start = datetime(now.year, now.month, now.day)
    elif timeframe == "last1seconds" or timeframe == "1seconds":
        start = now - timedelta(seconds=5)
    elif timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe == "1hours" or timeframe == "last1hours":
        start = now - timedelta(hours=1)
    elif timeframe in ["8hours", "last8hours"]:
        start = now - timedelta(hours=8)
    elif timeframe in ["24hours", "last24hours"]:
        start = now - timedelta(hours=24)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    elif timeframe == "last30days":
        start = now - timedelta(days=30)
    elif timeframe == "last60days":
        start = now - timedelta(days=60)
    elif timeframe == "last90days":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=1)

    return start, now

def get_combined_events(es, timeframe, filters=None, search_query=None, logic="AND"):
    index_pattern = "logs-*"

    # =============================
    # 1. TIME FILTER
    # =============================
    if timeframe == "today":
        gte, lte = "now/d", "now"
    elif timeframe == "yesterday":
        gte, lte = "now-1d/d", "now"
    elif timeframe == "last7days":
        gte, lte = "now-7d/d", "now"
    else:
        gte, lte = "now-30d/d", "now"

    base_filters = [
        {
            "range": {
                "@timestamp": {
                    "gte": gte,
                    "lte": lte,
                    "time_zone": "+07:00"
                }
            }
        },
        {
            "term": {
                "event.module": "suricata"
            }
        }
    ]

    dynamic_filters = []

    # =============================
    # 2. DYNAMIC FILTER
    # =============================
    if filters:
        for f in filters:
            field = f.field
            val = f.value
            op = getattr(f, "operator", "is")

            clause = None

            if field == "source_ip":
                clause = {"term": {"source.ip": val}}

            elif field == "destination_ip":
                clause = {"term": {"destination.ip": val}}

            elif field == "port":
                clause = {"term": {"destination.port": val}}

            elif field == "protocol":
                clause = {"term": {"network.transport": val.upper()}}

            elif field == "severity":
                clause = {"term": {"event.severity_label": val}}

            elif field == "description":
                clause = {
                    "wildcard": {
                        "rule.name": {
                            "value": f"*{val}*",
                            "case_insensitive": True
                        }
                    }
                }

            elif field == "category":
                clause = {"term": {"rule.category": val}}

            # operator tambahan
            if clause:
                if op == "is":
                    dynamic_filters.append(clause)

                elif op == "is_not":
                    dynamic_filters.append({
                        "bool": {
                            "must_not": [clause]
                        }
                    })

                elif op == "contains":
                    dynamic_filters.append({
                        "wildcard": {
                            list(clause["term"].keys())[0]: {
                                "value": f"*{val}*",
                                "case_insensitive": True
                            }
                        }
                    })

    # =============================
    # 3. LOGIC AND / OR
    # =============================
    logic_type = str(logic).strip().upper()

    if logic_type == "OR" and dynamic_filters:
        final_query = {
            "bool": {
                "filter": base_filters,
                "should": dynamic_filters,
                "minimum_should_match": 1
            }
        }
    else:
        final_query = {
            "bool": {
                "filter": base_filters + dynamic_filters
            }
        }

    # =============================
    # 4. SEARCH BAR
    # =============================
    if search_query:
        search_should = []

        # IP search
        if any(c.isdigit() for c in search_query):
            search_should.append({"match": {"source.ip": search_query}})
            search_should.append({"match": {"destination.ip": search_query}})

        # text search
        search_should.extend([
            {
                "wildcard": {
                    "message": {
                        "value": f"*{search_query}*",
                        "case_insensitive": True
                    }
                }
            },
            {"match": {"rule.name": search_query}},
            {"match": {"rule.category": search_query}},
            {"match": {"event.severity_label": search_query}},
            {"term": {"network.transport": search_query.upper()}}
        ])

        final_query["bool"].setdefault("must", [])
        final_query["bool"]["must"].append({
            "bool": {
                "should": search_should,
                "minimum_should_match": 1
            }
        })

    # =============================
    # 5. EXECUTE QUERY
    # =============================
    query = {
        "size": 200,
        "track_total_hits": True,
        "query": final_query,
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ]
    }

    res = es.search(index=index_pattern, body=query)
    hits = res.get("hits", {}).get("hits", [])

    # =============================
    # 6. MAPPING RESULT
    # =============================
    results = []

    for h in hits:
        src = h["_source"]

        results.append({
            "timestamp": src.get("@timestamp"),
            "event_type": src.get("event", {}).get("module"),
            "source_ip": src.get("source", {}).get("ip"),
            "destination_ip": src.get("destination", {}).get("ip"),
            "port": src.get("destination", {}).get("port"),
            "protocol": src.get("network", {}).get("transport"),
            "country": None,
            "destination_country": None,
            "severity": src.get("event", {}).get("severity_label"),
            "mitre_stages": None,
            "description": src.get("rule", {}).get("name"),
            "sub_type": None,
            "category": src.get("rule", {}).get("category"),
            "event_id": src.get("log", {}).get("id", {}).get("uid"),
            "source_longitude": None,
            "source_latitude": None,
            "destination_longitude": None,
            "destination_latitude": None,
            "application": "application",
            "rule_reference": src.get("rule", {}).get("reference"),
            "ruleset": src.get("rule", {}).get("ruleset"),
            "rule_action": src.get("rule", {}).get("action"),
            "rule_uuid": src.get("rule", {}).get("uuid"),
            "metadata_updated_at": src.get("rule", {}).get("metadata", {}).get("updated_at"),
            "metadata_created_at": src.get("rule", {}).get("metadata", {}).get("created_at"),
            "metadata_confidence": src.get("rule", {}).get("metadata", {}).get("confidence"),
            "metadata_severity": src.get("rule", {}).get("metadata", {}).get("signature_severity"),
            "packet_source": src.get("network", {}).get("packet_source")
        })

    return results

def get_suricata_events(es, INDEX, timeframe):
    # query = {
    #     "size": 0,
    #     "query": {
    #         "bool": {
    #             "filter": [
    #                 get_time_range_filter(timeframe),
    #                 {"term": {"event.module": "suricata"}}
    #             ]
    #         }
    #     },
    #     "aggs": {
    #         "by_rule": {
    #             "terms": {"field": "rule.name.keyword", "size": 500},
    #             "aggs": {
    #                 "sample_event": {
    #                     "top_hits": {
    #                         "size": 1,
    #                         "sort": [{"@timestamp": {"order": "desc"}}],
    #                         "_source": [
    #                             "source.ip",
    #                             "destination.ip",
    #                             "rule.category",
    #                             "rule.metadata.mitre_tactic_name",
    #                             "source.geo.country_name",
    #                             "destination.geo.country_name",
    #                             "event.severity_label",
    #                             "destination.port",
    #                             "mitre.stages",
    #                             "log.id.uid",
    #                             "network.transport",
    #                             "source.geo.location.lon",
    #                             "source.geo.location.lat",
    #                             "destination.geo.location.lon",
    #                             "destination.geo.location.lat",
    #                             "@timestamp"
    #                         ]
    #                     }
    #                 },
    #                 "first_event": {"min": {"field": "@timestamp"}},
    #                 "last_event": {"max": {"field": "@timestamp"}}
    #             }
    #         }
    #     }
    # }

    # res = es.search(index=INDEX, body=query)

    # results = []
    # for bucket in res["aggregations"]["by_rule"]["buckets"]:
    #     hit = bucket["sample_event"]["hits"]["hits"][0]["_source"] if bucket["sample_event"]["hits"]["hits"] else {}

    #     mitre_tactic_name = (
    #     hit.get("rule", {})
    #         .get("metadata", {})
    #         .get("mitre_tactic_name", [])
    #     )

    #     mitre_value = None
    #     if mitre_tactic_name:
    #         raw_mitre = mitre_tactic_name[0].strip().lower()

    #         if raw_mitre.startswith(("initial", "reconnaissance")):
    #             mitre_value = "Initial Attempts"
    #         elif raw_mitre.startswith(("execution", "persistence", "privilege", "escalation")):
    #             mitre_value = "Persistent Foothold"
    #         elif raw_mitre.startswith(("defense", "credential", "discovery", "command")):
    #             mitre_value = "Exploration"
    #         elif raw_mitre.startswith("lateral"):
    #             mitre_value = "Propagation"
    #         elif raw_mitre.startswith(("collection", "exfiltration", "impact")):
    #             mitre_value = "Exfiltration"
    #         else:
    #             mitre_value = mitre_tactic_name[0]

    #     raw_ts = hit.get("@timestamp")
    #     formatted_ts = None

    #     if raw_ts:
    #         dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    #         formatted_ts = dt.strftime("%Y-%m-%d %H:%M:%S")

    #     results.append({
    #         "destination_ip": hit.get("destination", {}).get("ip"),
    #         "source_ip": hit.get("source", {}).get("ip"),
    #         "country": hit.get("source", {}).get("geo", {}).get("country_name"),
    #         "event_type": "suricata",
    #         "sub_type": hit.get("rule", {}).get("category"),
    #         "severity": hit.get("event", {}).get("severity_label"),
    #         "timestamp": formatted_ts,
    #         "mitre_stages": mitre_value,
    #         "mitre_detail": mitre_tactic_name[0] if mitre_tactic_name else None,
    #         "event_id": hit.get("log", {}).get("id", {}).get("uid"),
    #         "application": "application",
    #         "description": bucket["key"],
    #         "protocol": hit.get("network", {}).get("transport"),
    #         "destination_country": hit.get("destination", {}).get("geo", {}).get("country_name"),
    #         "port": hit.get("destination", {}).get("port"),
    #         "count": bucket["doc_count"],
    #         "first_event": bucket["first_event"].get("value_as_string"),
    #         "last_event": bucket["last_event"].get("value_as_string"),
    #         "source_longitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
    #         "source_latitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
    #         "destination_longitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
    #         "destination_latitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
    #     })

    # return results

    query = {
    "size": 500,  
    "track_total_hits": True,  # Agar bisa menghitung total data lebih dari 10.000
    "query": {
        "bool": {
            "filter": [
                get_time_range_filter(timeframe),
                {"term": {"event.module": "suricata"}}
            ]
        }
    },
    "sort": [
        {"@timestamp": {"order": "desc"}} # Urutkan dari log terbaru
    ]
    }

    res = es.search(index=INDEX, body=query)
    total_data_found = res["hits"]["total"]["value"]

    results = []

    for hit_wrapper in res["hits"]["hits"]:
        hit = hit_wrapper.get("_source", {})

        mitre_tactic_name = (
        hit.get("rule", {})
           .get("metadata", {})
           .get("mitre_tactic_name", [])
        )
        
        mitre_value = None
        if mitre_tactic_name:
            raw_mitre = mitre_tactic_name[0].strip().lower()

            if raw_mitre.startswith(("initial", "reconnaissance")):
                mitre_value = "Initial Attempts"
            elif raw_mitre.startswith(("execution", "persistence", "privilege", "escalation")):
                mitre_value = "Persistent Foothold"
            elif raw_mitre.startswith(("defense", "credential", "discovery", "command")):
                mitre_value = "Exploration"
            elif raw_mitre.startswith("lateral"):
                mitre_value = "Propagation"
            elif raw_mitre.startswith(("collection", "exfiltration", "impact")):
                mitre_value = "Exfiltration"
            else:
                mitre_value = mitre_tactic_name[0]

        raw_ts = hit.get("@timestamp")
        formatted_ts = None
        if raw_ts:
            try:
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                formatted_ts = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_ts = raw_ts
    
        results.append({
            "timestamp": formatted_ts,
            "source_ip": hit.get("source", {}).get("ip"),
            "destination_ip": hit.get("destination", {}).get("ip"),
            "port": hit.get("destination", {}).get("port"),
            "protocol": hit.get("network", {}).get("transport"),
            "country": hit.get("source", {}).get("geo", {}).get("country_name"),
            "destination_country": hit.get("destination", {}).get("geo", {}).get("country_name"),
            "severity": hit.get("event", {}).get("severity_label"),
            "event_type": hit.get("event", {}).get("module"),
            "sub_type": hit.get("rule", {}).get("category"),
            "description": hit.get("rule", {}).get("name"), # Nama rule sebagai deskripsi event
            "mitre_stages": mitre_value,
            "mitre_detail": mitre_tactic_name[0] if mitre_tactic_name else None,
            "event_id": hit.get("log", {}).get("id", {}).get("uid"),
            "source_longitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lat"),
            "application": "application"
        })

    return results

def get_sophos_events(es, INDEX, timeframe):
    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "sophos"}},
                    {"terms": {"sophos.xg.log_type": ["IDP", "Content Filtering"]}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=INDEX, body=query)
    hits = res.get("hits", {}).get("hits", [])
    results = []

    for h in hits:
        src = h["_source"]
        sophos = src.get("sophos", {}).get("xg", {})

        rule_name = (
            sophos.get("message") or
            sophos.get("rule_name") or
            "unknown"
        )

        mitre_tactic_name = (
        src.get("mitre", {})
            .get("stages")
        )

        mitre_value = None
        if mitre_tactic_name:
            raw_mitre = mitre_tactic_name[0].strip().lower()

            if raw_mitre.startswith(("initial", "reconnaissance")):
                mitre_value = "Initial Attempts"
            elif raw_mitre.startswith(("execution", "persistence", "privilege", "escalation")):
                mitre_value = "Persistent Foothold"
            elif raw_mitre.startswith(("defense", "credential", "discovery")):
                mitre_value = "Exploration"
            elif raw_mitre.startswith("lateral"):
                mitre_value = "Propagation"
            elif raw_mitre.startswith(("collection", "exfiltration", "impact")):
                mitre_value = "Exfiltration"
            else:
                mitre_value = mitre_tactic_name

        raw_ts = src.get("@timestamp")
        formatted_ts = None

        if raw_ts:
            dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            formatted_ts = dt.strftime("%Y-%m-%d %H:%M:%S")

        results.append({
            "destination_ip": src.get("destination", {}).get("ip"),
            "source_ip": src.get("source", {}).get("ip"),
            "country": src.get("source", {}).get("geo", {}).get("country_name"),
            "event_type": "sophos",
            "sub_type": sophos.get("log_type"),
            "severity": src.get("event", {}).get("severity_label") or src.get("log", {}).get("level"),
            "timestamp": formatted_ts,
            "mitre_stages": mitre_value,
            "mitre_detail": src.get("mitre", {}).get("stages"),
            "event_id": src.get("log", {}).get("id", {}).get("uid"),
            "application": sophos.get("app_name"),
            "description": rule_name,
            "protocol": src.get("network", {}).get("transport"),
            "destination_country": src.get("destination", {}).get("geo", {}).get("country_name"),
            "port": src.get("destination", {}).get("port") or sophos.get("dst_port"),
            "count": 1,
            "first_event": src.get("@timestamp"),
            "last_event": src.get("@timestamp"),
            "source_longitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
        })

    return results

def get_panw_events(es, INDEX_PANW, timeframe):
    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "panw"}},
                    {"term": {"panw.panos.type": "THREAT"}},
                    {"terms": {"panw.panos.sub_type": ["file", "vulnerability"]}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=INDEX_PANW, body=query)
    hits = res.get("hits", {}).get("hits", [])

    results = []

    for h in hits:
        src = h["_source"]
        panw = src.get("panw", {}).get("panos", {})

        mitre_tactic_name = (
        src.get("mitre", {})
            .get("stages")
        )

        mitre_value = None
        if mitre_tactic_name:
            raw_mitre = mitre_tactic_name[0].strip().lower()

            if raw_mitre.startswith(("initial", "reconnaissance")):
                mitre_value = "Initial Attempts"
            elif raw_mitre.startswith(("execution", "persistence", "privilege", "escalation")):
                mitre_value = "Persistent Foothold"
            elif raw_mitre.startswith(("defense", "credential", "discovery")):
                mitre_value = "Exploration"
            elif raw_mitre.startswith("lateral"):
                mitre_value = "Propagation"
            elif raw_mitre.startswith(("collection", "exfiltration", "impact")):
                mitre_value = "Exfiltration"
            else:
                mitre_value = mitre_tactic_name

        raw_ts = src.get("@timestamp")
        formatted_ts = None

        if raw_ts:
            dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            formatted_ts = dt.strftime("%Y-%m-%d %H:%M:%S")

        results.append({
            "destination_ip": src.get("destination", {}).get("ip"),
            "source_ip": src.get("source", {}).get("ip"),
            "country": src.get("source", {}).get("geo", {}).get("country_name"),
            "event_type": "panw",
            "sub_type": panw.get("sub_type"),
            "severity": src.get("log", {}).get("syslog", {}).get("severity", {}).get("name"),
            "timestamp": formatted_ts,
            "mitre_stages": mitre_value,
            "mitre_detail": src.get("mitre", {}).get("stages"),
            "event_id": panw.get("seqno"),
            "application": panw.get("app"),
            "description": panw.get("threat", {}).get("name"),
            "protocol": src.get("network", {}).get("transport"),
            "destination_country": src.get("destination", {}).get("geo", {}).get("country_name"),
            "port": src.get("destination", {}).get("port") or panw.get("dest_port"),
            "count": 1,
            "first_event": src.get("@timestamp"),
            "last_event": src.get("@timestamp"),
            "source_longitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
        })

    return results

def compute_top5_risk(combined):

    # =============================
    # STEP 1: Build base table
    # =============================
    base = []
    for ev in combined:
        src = str(ev.get("source_ip", "")).split("/")[0]
        dst = str(ev.get("destination_ip", "")).split("/")[0]

        internal_ip = None
        if src.startswith("192.168."):
            internal_ip = src
        elif dst.startswith("192.168."):
            internal_ip = dst

        if not internal_ip:
            continue

        base.append({
            "created_date": datetime.utcnow(),
            "modul": ev.get("event_type", "").lower(),
            "severity": str(ev.get("event_severity_label", "")).lower(),
            "sub_type": str(ev.get("sub_type", "")).lower(),
            "rule_name": str(ev.get("description", "")),
            "internal_ip": internal_ip
        })

    if not base:
        return []

    # =============================
    # STEP 2: COUNT RULE PER IP
    # =============================
    rule_count = defaultdict(int)
    for b in base:
        key = (b["internal_ip"], b["rule_name"])
        rule_count[key] += 1

    # =============================
    # STEP 3: SCORE PER EVENT
    # =============================
    per_event_scores = []

    for b in base:
        ip = b["internal_ip"]
        rn = b["rule_name"]

        # modul weight
        m = b["modul"]
        if m == "suricata":
            w_modul = 1.0
        elif m == "panw":
            w_modul = 1.2
        elif m == "sophos":
            w_modul = 1.3
        else:
            w_modul = 1.0

        # severity weight
        sev = b["severity"]
        if sev in ("critical", "severe"):
            w_severity = 5.0
        elif sev == "high":
            w_severity = 3.5
        elif sev == "medium":
            w_severity = 2.0
        elif sev == "low":
            w_severity = 1.0
        else:
            w_severity = 0.5

        # subtype weight
        st = b["sub_type"]
        if st in ("malware", "c2", "command_and_control", "data_exfil", "exfiltration"):
            w_sub_type = 5.5
        elif st in ("exploit_attempt", "exploit", "intrusion", "lateral_movement"):
            w_sub_type = 4.5
        elif st in ("auth_bruteforce", "password_spray", "credential_access"):
            w_sub_type = 3.8
        elif st in ("policy_violation", "misconfiguration"):
            w_sub_type = 1.8
        else:
            w_sub_type = 1.0

        # rule weight
        rn_lower = rn.lower()
        if ("mimikatz" in rn_lower) or ("c2" in rn_lower) or ("ransomware" in rn_lower):
            w_rule = 1.4
        elif ("port scan" in rn_lower) or ("generic" in rn_lower):
            w_rule = 0.8
        else:
            w_rule = 1.0

        # decay
        time_decay = math.exp(-1)

        # duplicate dampening
        rc = rule_count[(ip, rn)]
        dup_damp = 1.0 / (1.0 + math.log(max(rc, 1)))

        # final event score
        event_score = (
            w_modul * w_severity * w_sub_type * w_rule *
            time_decay * dup_damp
        )

        per_event_scores.append({
            "internal_ip": ip,
            "modul": b["modul"],
            "sub_type": b["sub_type"],
            "event_score": event_score
        })

    # =============================
    # STEP 4: AGGREGATE per IP
    # =============================
    ip_data = defaultdict(lambda: {
        "event_count": 0,
        "modules": set(),
        "sub_types": set(),
        "raw_score": 0.0
    })

    for ev in per_event_scores:
        ip = ev["internal_ip"]
        ip_data[ip]["event_count"] += 1
        ip_data[ip]["modules"].add(ev["modul"])
        ip_data[ip]["sub_types"].add(ev["sub_type"])
        ip_data[ip]["raw_score"] += ev["event_score"]

    results = []

    # =============================
    # STEP 5: FINAL SCORE
    # =============================
    for ip, d in ip_data.items():
        modul_count = len(d["modules"])
        sub_type_count = len(d["sub_types"])

        score_raw = d["raw_score"]
        score_raw *= (1 + 0.2 * (modul_count - 1))
        score_raw *= (1 + 0.1 * min(sub_type_count - 1, 3))

        score_normalized = min(100, max(1, score_raw * 2))

        # severity level
        if score_normalized >= 80:
            sev_label = "Critical"
        elif score_normalized >= 60:
            sev_label = "High"
        elif score_normalized >= 30:
            sev_label = "Medium"
        else:
            sev_label = "Low"

        results.append({
            "ip": ip,
            "event_count": d["event_count"],
            "modul_count": modul_count,
            "sub_type_count": sub_type_count,
            "score": round(score_normalized, 2),
            "severity": sev_label
        })

    # urutkan DESC score
    results = sorted(results, key=lambda x: x["score"], reverse=True)

    return results[:5]

def calculate_risk_summary(timeframe):
# 1. Tentukan Index Pattern
    index_pattern = "logs-*, .ds-logs-suricata*, .ds-logs-sophos*, .ds-logs-panw.panos-default-*"
    
    # 2. Ambil filter range dari fungsi Anda
    # Fungsi Anda mengembalikan: {"range": {"@timestamp": {"gte": ..., "lte": ...}}}
    # time_filter = get_time_range_filter(timeframe)
    if timeframe == "today":
        gte_time = "now/d"
        lte_time = "now"
    elif timeframe == "yesterday":
        # Dari kemarin jam 00:00 sampai sekarang
        gte_time = "now-1d/d" 
        lte_time = "now"
    elif timeframe == "last7days":
        gte_time = "now-7d/d"
        lte_time = "now"
    elif timeframe == "last30days":
        gte_time = "now-30d/d"
        lte_time = "now"
    else:
        # Default fallback
        gte_time = "now/d"
        lte_time = "now"

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte_time,
                                "lte": lte_time,
                                "time_zone": "+07:00"
                            }
                        }
                    },
                    { "terms": { "event.module": ["suricata", "sophos", "panw"] } },
                    { "exists": { "field": "source.ip" } }
                ]
            }
        },
        "aggs": {
            "by_internal_ip": {
                "terms": {
                    "script": {
                        "source": """
                            def s = doc.containsKey('source.ip') && doc['source.ip'].size() > 0 ? doc['source.ip'].value : '';
                            def d = doc.containsKey('destination.ip') && doc['destination.ip'].size() > 0 ? doc['destination.ip'].value : '';
                            if (s.startsWith('192.168.')) return s;
                            if (d.startsWith('192.168.')) return d;
                            return null;
                        """
                    },
                    "size": 5,
                    "order": { "final_score_sum": "desc" }
                },
                "aggs": {
                    "modul_count": { "cardinality": { "field": "event.module" } },
                    "sub_type_count": { "cardinality": { "field": "event.dataset" } },
                    "last_seen": { "max": { "field": "@timestamp" } },
                    "final_score_sum": {
                        "sum": {
                            "script": {
                                "source": """
                                    double score = 1.0;
                                    double w_mod = 1.0;
                                    def m = doc['event.module'].value;
                                    if (m == 'panw') w_mod = 1.2; 
                                    else if (m == 'sophos') w_mod = 1.3;

                                    double w_sev = 0.5;
                                    if (doc.containsKey('event.severity_label') && doc['event.severity_label'].size() > 0) {
                                        def sev = doc['event.severity_label'].value.toLowerCase();
                                        if (sev.contains('critical') || sev.contains('severe')) w_sev = 5.0;
                                        else if (sev.contains('high')) w_sev = 3.5;
                                        else if (sev.contains('medium')) w_sev = 2.0;
                                        else if (sev.contains('low')) w_sev = 1.0;
                                    }
                                    return w_mod * w_sev;
                                """
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        res = es.search(index=index_pattern, body=query)
        buckets = res['aggregations']['by_internal_ip']['buckets']
        final_output = []
        
        for b in buckets:
            raw_score = b['final_score_sum']['value']
            m_cnt = b['modul_count']['value']
            s_cnt = b['sub_type_count']['value']
            
            # 4. Final Normalization (Sesuai Logic SQL Anda)
            # score_raw * (1 + 0.2 * (modul_count - 1)) * (1 + 0.1 * (sub_type - 1))
            score_raw = raw_score * (1 + 0.2 * (m_cnt - 1)) * (1 + 0.1 * min(s_cnt - 1, 3))
            score_normalized = round(min(100, score_raw * 2), 2)
            
            final_output.append({
                "ip": b['key'],
                "event_count": b['doc_count'],
                "modul_count": m_cnt,
                "sub_type_count": s_cnt,
                "score": score_normalized,
                "severity": "Critical" if score_normalized >= 80 else "High" if score_normalized >= 60 else "Medium" if score_normalized >= 30 else "Low",
                "last_active": b['last_seen'].get('value_as_string', "N/A")
            })
        return final_output
    except Exception as e:
        print(f"❌ Error Detail: {str(e)}")
        return []


def calculate_global_stats(timeframe):
    index_pattern = "logs-*, .ds-logs-suricata*, .ds-logs-sophos*, .ds-logs-panw.panos-default-*"
    
    # time_filter = get_time_range_filter(timeframe)
    if timeframe == "today":
        gte_time = "now/d"
        lte_time = "now"
    elif timeframe == "yesterday":
        # Dari kemarin jam 00:00 sampai sekarang
        gte_time = "now-1d/d" 
        lte_time = "now"
    elif timeframe == "last7days":
        gte_time = "now-7d/d"
        lte_time = "now"
    elif timeframe == "last30days":
        gte_time = "now-30d/d"
        lte_time = "now"
    else:
        # Default fallback
        gte_time = "now/d"
        lte_time = "now"
    
    # Siapkan filter 5 menit lalu
    jakarta_tz = ZoneInfo("Asia/Jakarta")
    now = datetime.now(tz=jakarta_tz)
    five_min_ago = (now - timedelta(seconds=5)).isoformat()

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte_time,
                                "lte": lte_time,
                                "time_zone": "+07:00"
                            }
                        }
                    },
                    { "terms": { "event.module": ["suricata", "sophos", "panw"] } }
                ]
            }
        },
        "aggs": {
            "by_module": {
                "filters": {
                    "filters": {
                        "suricata": { "term": { "event.module": "suricata" } },
                        "sophos": { "term": { "event.module": "sophos" } },
                        "panw": { "term": { "event.module": "panw" } }
                    }
                }
            },
            "last_5_minutes": {
                "filter": {
                    "range": { "@timestamp": { "gte": five_min_ago } }
                }
            }
        }
    }

    try:
        res = es.search(index=index_pattern, body=query)
        aggs = res.get('aggregations', {})
        module_buckets = aggs.get('by_module', {}).get('buckets', {})
        
        # Logika 5 menit ago (Hanya muncul jika timeframe == "today")
        total_5m = 0
        if timeframe == "today":
            total_5m = aggs.get('last_5_minutes', {}).get('doc_count', 0)

        # Hitung Total All secara manual dari total hits
        total_all = res.get('hits', {}).get('total', {}).get('value', 0)

        # Susun return sesuai permintaan Anda
        return {
            "total_all": total_all,
            "total_5_min_ago": total_5m,
            "list": [
                {
                    "event_type": "suricata",
                    "total": module_buckets.get('suricata', {}).get('doc_count', 0)
                },
                {
                    "event_type": "sophos",
                    "total": module_buckets.get('sophos', {}).get('doc_count', 0)
                },
                {
                    "event_type": "panw",
                    "total": module_buckets.get('panw', {}).get('doc_count', 0)
                }
            ]
        }

    except Exception as e:
        print(f"❌ Error Global Stats: {e}")
        return {
            "total_all": 0,
            "total_5_min_ago": 0,
            "list": [
                {"event_type": "suricata", "total": 0},
                {"event_type": "sophos", "total": 0},
                {"event_type": "panw", "total": 0}
            ]
        }

# Pastikan semua event timestamp diubah ke objek datetime agar bisa dihitung.
# Asumsi: Timestamp di event adalah string ISO-like (e.g., "2025-11-11T01:00:00Z")
def safe_parse_timestamp(ts):
    if not ts:
        return None
    try:
        # ISO format (2025-01-13T10:30:00Z)
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        try:
            # Format DB umum
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    # 🔴 PAKSA TIMEZONE JIKA NAIVE
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("Asia/Jakarta"))

    return dt

# def build_timeline(events: list, timeframe: str) -> list:
#     # Mengambil waktu saat ini (UTC disarankan untuk konsistensi)
#     jakarta_tz = ZoneInfo("Asia/Jakarta")
#     now = datetime.now(tz=jakarta_tz)
    
#     # 1. Tentukan Granularitas, Format Output, dan Jangkauan Waktu
    
#     # Granularitas (Interval) dan Format Output
#     if timeframe == "today":
#         # 24 jam terakhir, interval 3 menit
#         interval = timedelta(minutes=3)
#         time_format = "%Y-%m-%d %H:%M"
#         # Start dari 24 jam yang lalu (agar genap)
#         # start_time = now - timedelta(hours=24)
#         # ✅ Start dari hari ini jam 00:00
#         start_time = now.replace(
#             hour=0,
#             minute=0,
#             second=0,
#             microsecond=0
#         )
        
#         # Penyesuaian agar start_time adalah pada kelipatan 3 menit terdekat
#         total_seconds_start = (start_time - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
#         remainder = total_seconds_start % (3 * 60)
#         if remainder != 0:
#             start_time -= timedelta(seconds=remainder)
    
#     elif timeframe == "last1hours":
#         # 24 jam terakhir, interval 3 menit
#         interval = timedelta(minutes=5)
#         time_format = "%Y-%m-%d %H:%M"
#         # Start dari 24 jam yang lalu (agar genap)
#         start_time = now - timedelta(hours=1)
        
#         # Penyesuaian agar start_time adalah pada kelipatan 3 menit terdekat
#         total_seconds_start = (start_time - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
#         remainder = total_seconds_start % (3 * 60)
#         if remainder != 0:
#             start_time -= timedelta(seconds=remainder)
            
#     elif timeframe == "last24hours":
#         # 24 jam terakhir, interval 1 jam
#         interval = timedelta(hours=1)
#         time_format = "%Y-%m-%d %H:00"
#         # Start dari 24 jam yang lalu (agar genap)
#         start_time = now - timedelta(hours=24)
        
#         # Penyesuaian agar start_time adalah pada jam genap
#         start_time = start_time.replace(minute=0, second=0, microsecond=0)
        
#     elif timeframe in ["last7days", "last30days"]:
#         # Interval harian
#         interval = timedelta(days=1)
#         time_format = "%Y-%m-%d %H:00"
        
#         days_ago = 7 if timeframe == "last7days" else 30
#         start_time = now - timedelta(days=days_ago)
        
#         # Penyesuaian agar start_time adalah pada awal hari
#         start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        
#     else:
#         # Fallback atau penanganan timeframe yang tidak dikenal
#         return []

#     # 2. Agregasi Event ke Interval Waktu
    
#     # Inisialisasi dictionary untuk menyimpan hitungan: {timestamp_key: count}
#     timeline_counts = defaultdict(int) 
    
#     for event in events:
#         ts_obj = safe_parse_timestamp(event.get("timestamp"))
        
#         if not ts_obj:
#             continue
        
#         if ts_obj and ts_obj >= start_time:
#             # Hitung 'bin' waktu untuk event ini
            
#             # Cari selisih waktu dari start_time
#             delta = ts_obj - start_time
            
#             # Hitung jumlah interval yang dilewati
#             num_intervals = math.floor(delta.total_seconds() / interval.total_seconds())
            
#             # Tentukan timestamp awal dari bin waktu tersebut
#             bin_start_time = start_time + (num_intervals * interval)
            
#             # Format kunci (key) untuk agregasi
#             key = bin_start_time.strftime(time_format)
            
#             timeline_counts[key] += 1
            
            
#     # 3. Buat Garis Waktu Penuh (Full Timeline) dan Isi Nilai 0

#     full_timeline = []
#     current_time = start_time
    
#     # Loop dari waktu awal (start_time) hingga waktu saat ini (now)
#     while current_time <= now:
        
#         # Format kunci waktu untuk dicocokkan dengan hasil agregasi
#         key = current_time.strftime(time_format)
        
#         full_timeline.append({
#             "timeline": key,
#             "count": timeline_counts.get(key, 0) # Ambil count, default 0 jika tidak ada event
#         })
        
#         # Pindah ke interval waktu berikutnya
#         current_time += interval
        
#     # Hapus entry terakhir jika melebihi waktu saat ini (now), 
#     # meskipun loop while sudah membatasi dengan <= now
#     if full_timeline and current_time > now:
#          # Hanya memastikan bahwa timeline tidak memiliki slot waktu masa depan 
#          # yang mungkin tercipta jika intervalnya besar.
#          pass
         
#     return full_timeline
def build_timeline(events: list, timeframe: str) -> list:
    # Mengambil waktu saat ini (UTC disarankan untuk konsistensi)
    jakarta_tz = ZoneInfo("Asia/Jakarta")
    now = datetime.now(tz=jakarta_tz)
    
    # 1. Tentukan Granularitas, Format Output, dan Jangkauan Waktu
    
    # Granularitas (Interval) dan Format Output
    if timeframe == "today":
        # 24 jam terakhir, interval 3 menit
        interval = timedelta(minutes=3)
        time_format = "%Y-%m-%d %H:%M"
        # Start dari 24 jam yang lalu (agar genap)
        # start_time = now - timedelta(hours=24)
        # ✅ Start dari hari ini jam 00:00
        start_time = now.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
        
        # Penyesuaian agar start_time adalah pada kelipatan 3 menit terdekat
        total_seconds_start = (start_time - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
        remainder = total_seconds_start % (3 * 60)
        if remainder != 0:
            start_time -= timedelta(seconds=remainder)
    
    elif timeframe == "last1hours":
        # 24 jam terakhir, interval 3 menit
        interval = timedelta(minutes=5)
        time_format = "%Y-%m-%d %H:%M"
        # Start dari 24 jam yang lalu (agar genap)
        start_time = now - timedelta(hours=1)
        
        # Penyesuaian agar start_time adalah pada kelipatan 3 menit terdekat
        total_seconds_start = (start_time - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
        remainder = total_seconds_start % (3 * 60)
        if remainder != 0:
            start_time -= timedelta(seconds=remainder)
            
    elif timeframe == "last24hours":
        # 24 jam terakhir, interval 1 jam
        interval = timedelta(hours=1)
        time_format = "%Y-%m-%d %H:00"
        # Start dari 24 jam yang lalu (agar genap)
        start_time = now - timedelta(hours=24)
        
        # Penyesuaian agar start_time adalah pada jam genap
        start_time = start_time.replace(minute=0, second=0, microsecond=0)
        
    elif timeframe in ["last7days", "last30days"]:
        # Interval harian
        interval = timedelta(days=1)
        time_format = "%Y-%m-%d %H:00"
        
        days_ago = 7 if timeframe == "last7days" else 30
        start_time = now - timedelta(days=days_ago)
        
        # Penyesuaian agar start_time adalah pada awal hari
        start_time = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
        
    else:
        # Fallback atau penanganan timeframe yang tidak dikenal
        return []

    # 2. Agregasi Event ke Interval Waktu
    
    # Inisialisasi dictionary untuk menyimpan hitungan: {timestamp_key: count}
    timeline_counts = defaultdict(int) 
    
    for event in events:
        ts_obj = safe_parse_timestamp(event.get("timestamp"))
        
        if not ts_obj:
            continue
        
        if ts_obj and ts_obj >= start_time:
            # Hitung 'bin' waktu untuk event ini
            
            # Cari selisih waktu dari start_time
            delta = ts_obj - start_time
            
            # Hitung jumlah interval yang dilewati
            num_intervals = math.floor(delta.total_seconds() / interval.total_seconds())
            
            # Tentukan timestamp awal dari bin waktu tersebut
            bin_start_time = start_time + (num_intervals * interval)
            
            # Format kunci (key) untuk agregasi
            key = bin_start_time.strftime(time_format)
            
            timeline_counts[key] += 1
            
            
    # 3. Buat Garis Waktu Penuh (Full Timeline) dan Isi Nilai 0

    full_timeline = []
    current_time = start_time
    
    # Loop dari waktu awal (start_time) hingga waktu saat ini (now)
    while current_time <= now:
        
        # Format kunci waktu untuk dicocokkan dengan hasil agregasi
        key = current_time.strftime(time_format)
        
        full_timeline.append({
            "timeline": key,
            "count": timeline_counts.get(key, 0) # Ambil count, default 0 jika tidak ada event
        })
        
        # Pindah ke interval waktu berikutnya
        current_time += interval
        
    # Hapus entry terakhir jika melebihi waktu saat ini (now), 
    # meskipun loop while sudah membatasi dengan <= now
    if full_timeline and current_time > now:
         # Hanya memastikan bahwa timeline tidak memiliki slot waktu masa depan 
         # yang mungkin tercipta jika intervalnya besar.
         pass
         
    return full_timeline

# -------------------------------------------------------------------------
# FUNGSI UTAMA ANDA (TETAP SAMA, HANYA MENGGUNAKAN FUNGSI BUILD_TIMELINE BARU)
# -------------------------------------------------------------------------

def build_event_type_stats(timeframe):
    index_pattern = "logs-*, .ds-logs-suricata*, .ds-logs-sophos*, .ds-logs-panw.panos-default-*"
    
    # 1. Logika Penentuan Waktu dan Interval
    interval_type = "fixed_interval"
    
    if timeframe == "today":
        gte_time = "now/d"
        lte_time = "now"
        interval_val = "3m"
    elif timeframe == "yesterday":
        # Dari kemarin jam 00:00 sampai sekarang
        gte_time = "now-1d/d" 
        lte_time = "now"
        interval_val = "1h"
    elif timeframe == "last7days":
        gte_time = "now-7d/d"
        lte_time = "now"
        interval_val = "1d"
        interval_type = "calendar_interval" # Lebih akurat untuk harian
    elif timeframe == "last30days":
        gte_time = "now-30d/d"
        lte_time = "now"
        interval_val = "1d"
        interval_type = "calendar_interval"
    else:
        # Default fallback
        gte_time = "now/d"
        lte_time = "now"
        interval_val = "1h"

    # 2. Build Query
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte_time,
                                "lte": lte_time,
                                "time_zone": "+07:00"
                            }
                        }
                    },
                    { 
                        "terms": { 
                            "event.module": ["suricata", "sophos", "panw"] 
                        } 
                    }
                ]
            }
        },
        "aggs": {
            "by_module": {
                "terms": {
                    "field": "event.module",
                    "size": 3
                },
                "aggs": {
                    "timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            interval_type: interval_val,
                            "time_zone": "+07:00",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": gte_time,
                                "max": lte_time
                            },
                            "format": "yyyy-MM-dd HH:mm"
                        }
                    }
                }
            }
        }
    }

    try:
        res = es.search(index=index_pattern, body=query)
        buckets = res.get("aggregations", {}).get("by_module", {}).get("buckets", [])
        
        found_modules = { b['key']: b for b in buckets }
        
        results = []
        for mod in ["suricata", "sophos", "panw"]:
            data = found_modules.get(mod, {})
            t_buckets = data.get("timeline", {}).get("buckets", [])
            
            results.append({
                "event_type": mod,
                "total": data.get("doc_count", 0),
                "timeline": [
                    {
                        "timeline": tb.get("key_as_string"),
                        "count": tb.get("doc_count", 0)
                    } for tb in t_buckets
                ]
            })
            
        return results

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return []

# def build_event_type_ingest(suricata, sophos, panw, timeframe):
#     return [
#         {
#             "event_type": "suricata",
#             "total": len(suricata)
#         },
#         {
#             "event_type": "sophos",
#             "total": len(sophos)
#         },
#         {
#             "event_type": "panw",
#             "total": len(panw)
#         }
#     ]

def calculate_global_attack(timeframe):

    GEO_MAP = {
        "AFG": {"lat": 33.9391, "lon": 67.7100}, "ALB": {"lat": 41.1533, "lon": 20.1683},
        "DZA": {"lat": 28.0339, "lon": 1.6596}, "ARG": {"lat": -38.4161, "lon": -63.6167},
        "AUS": {"lat": -25.2744, "lon": 133.7751}, "AUT": {"lat": 47.5162, "lon": 14.5501},
        "BGD": {"lat": 23.6850, "lon": 90.3563}, "BEL": {"lat": 50.5039, "lon": 4.4699},
        "BRA": {"lat": -14.2350, "lon": -51.9253}, "CAN": {"lat": 56.1304, "lon": -106.3468},
        "CHL": {"lat": -35.6751, "lon": -71.5430}, "CHN": {"lat": 35.8617, "lon": 104.1954},
        "COL": {"lat": 4.5709, "lon": -74.2973}, "DNK": {"lat": 56.2639, "lon": 9.5018},
        "EGY": {"lat": 26.8206, "lon": 30.8025}, "FRA": {"lat": 46.2276, "lon": 2.2137},
        "DEU": {"lat": 51.1657, "lon": 10.4515}, "GRC": {"lat": 39.0742, "lon": 21.8243},
        "HKG": {"lat": 22.3964, "lon": 114.1095}, "IND": {"lat": 20.5937, "lon": 78.9629},
        "IDN": {"lat": -6.2088, "lon": 106.8456}, "IRN": {"lat": 32.4279, "lon": 53.6880},
        "IRQ": {"lat": 33.2232, "lon": 43.6793}, "IRL": {"lat": 53.4129, "lon": -8.2439},
        "ISR": {"lat": 31.0461, "lon": 34.8516}, "ITA": {"lat": 41.8719, "lon": 12.5674},
        "JPN": {"lat": 36.2048, "lon": 138.2529}, "KOR": {"lat": 35.9078, "lon": 127.7669},
        "MYS": {"lat": 4.2105, "lon": 101.9758}, "MEX": {"lat": 23.6345, "lon": -102.5528},
        "NLD": {"lat": 52.1326, "lon": 5.2913}, "NZL": {"lat": -40.9006, "lon": 174.8860},
        "NGA": {"lat": 9.0820, "lon": 8.6753}, "NOR": {"lat": 60.4720, "lon": 8.4689},
        "PAK": {"lat": 30.3753, "lon": 69.3451}, "PHL": {"lat": 12.8797, "lon": 121.7740},
        "POL": {"lat": 51.9194, "lon": 19.1451}, "PRT": {"lat": 39.3999, "lon": -8.2245},
        "RUS": {"lat": 61.5240, "lon": 105.3188}, "SAU": {"lat": 23.8859, "lon": 45.0792},
        "SGP": {"lat": 1.3521, "lon": 103.8198}, "ZAF": {"lat": -30.5595, "lon": 22.9375},
        "ESP": {"lat": 40.4637, "lon": -3.7492}, "SWE": {"lat": 60.1282, "lon": 18.6435},
        "CHE": {"lat": 46.8182, "lon": 8.2275}, "TWN": {"lat": 23.6978, "lon": 120.9605},
        "THA": {"lat": 15.8700, "lon": 100.9925}, "TUR": {"lat": 38.9637, "lon": 35.2433},
        "UKR": {"lat": 48.3794, "lon": 31.1656}, "ARE": {"lat": 23.4241, "lon": 53.8478},
        "GBR": {"lat": 55.3781, "lon": -3.4360}, "USA": {"lat": 37.0902, "lon": -95.7129},
        "VNM": {"lat": 14.0583, "lon": 108.2772}, "MCO": {"lat": 43.7384, "lon": 7.4246}
    }
    # 1. Definisi Index dan Filter Waktu
    index_pattern = "logs-*, .ds-logs-suricata*, .ds-logs-sophos*, .ds-logs-panw.panos-default-*"
    # time_filter = get_time_range_filter(timeframe)
    if timeframe == "today":
        gte_time = "now/d"
        lte_time = "now"
    elif timeframe == "yesterday":
        # Dari kemarin jam 00:00 sampai sekarang
        gte_time = "now-1d/d" 
        lte_time = "now"
    elif timeframe == "last7days":
        gte_time = "now-7d/d"
        lte_time = "now"
    elif timeframe == "last30days":
        gte_time = "now-30d/d"
        lte_time = "now"
    else:
        # Default fallback
        gte_time = "now/d"
        lte_time = "now"

    sophos_severity = "Information"
    # 2. Query Elasticsearch
    query = {
        "size": 5000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": gte_time, "lte": lte_time, "time_zone": "+07:00"}}},
                    {
                        "bool": {
                            "should": [
                                {
                                    "bool": {
                                        "must": [
                                            {"terms": {"event.module": ["suricata", "panw"]}},
                                            {"terms": {"event.severity_label": ["high", "critical", "High", "Critical"]}}
                                        ]
                                    }
                                },
                                {
                                    "bool": {
                                        "must": [
                                            {"wildcard": {"_index": "*sophos*"}},
                                            {"query_string": {"query": f"message: *{sophos_severity}*", "analyze_wildcard": True}}
                                        ]
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        res = es.search(index=index_pattern, body=query)
        hits = res.get("hits", {}).get("hits", [])
        
        summary = {}
        # Nilai yang akan dibuang
        invalid_values = [None, "Unknown", "unknown", "R1", "r1", ""]

        for h in hits:
            src_data = h["_source"]
            msg = src_data.get("message", "")
            
            # Helper untuk mengambil data dari teks message (Sophos)
            def extract_sophos(key):
                m = re.search(rf'{key}=[\"]?([^\s\",]+)[\"]?', msg)
                return m.group(1) if m else None

            is_sophos = "sophos" in h["_index"]
            event_mod = src_data.get("event", {}).get("module") or src_data.get("event", {}).get("dataset", "")

            # Ekstraksi Negara
            country = src_data.get("source", {}).get("geo", {}).get("country_name") or extract_sophos("src_country")
            dest_country = src_data.get("destination", {}).get("geo", {}).get("country_name") or extract_sophos("dst_country")
            
            # --- LOGIKA FILTER DESTINATION IDN (KHUSUS SOPHOS) ---
            if is_sophos:
                if dest_country != "IDN":
                    continue
            
            # --- FILTER UMUM (Hapus R1 / Unknown) ---
            if country in invalid_values or dest_country in invalid_values:
                continue
            
            group_key = f"{country}|{dest_country}"
            
            if group_key not in summary:
                # Ambil Koordinat (Prioritas: Elasticsearch > GEO_MAP)
                s_lon = src_data.get("source", {}).get("geo", {}).get("location", {}).get("lon") or GEO_MAP.get(country, {}).get("lon")
                s_lat = src_data.get("source", {}).get("geo", {}).get("location", {}).get("lat") or GEO_MAP.get(country, {}).get("lat")
                d_lon = src_data.get("destination", {}).get("geo", {}).get("location", {}).get("lon") or GEO_MAP.get(dest_country, {}).get("lon")
                d_lat = src_data.get("destination", {}).get("geo", {}).get("location", {}).get("lat") or GEO_MAP.get(dest_country, {}).get("lat")

                summary[group_key] = {
                    "country": country,
                    "destination_country": dest_country,
                    "event_type": "sophos" if is_sophos else event_mod,
                    "severity": src_data.get("event", {}).get("severity_label") or extract_sophos("severity") or "High",
                    "count": 0,
                    "source_longitude": s_lon,
                    "source_latitude": s_lat,
                    "destination_longitude": d_lon,
                    "destination_latitude": d_lat,
                }
            
            summary[group_key]["count"] += 1

        # Sorting berdasarkan count terbanyak
        final_results = list(summary.values())
        final_results.sort(key=lambda x: x['count'], reverse=True)

        return final_results[:5]

    except Exception as e:
        print(f"❌ Error Global Attack: {e}")
        return []


# ----------------------------
# 🔥 NEW FUNCTION – MITRE STATS
# ----------------------------
def calculate_mitre_stats(timeframe):
    index_pattern = "logs-*, .ds-logs-suricata*, .ds-logs-sophos*, .ds-logs-panw.panos-default-*"
    # time_filter = get_time_range_filter(timeframe)
    if timeframe == "today":
        gte_time = "now/d"
        lte_time = "now"
    elif timeframe == "yesterday":
        # Dari kemarin jam 00:00 sampai sekarang
        gte_time = "now-1d/d" 
        lte_time = "now"
    elif timeframe == "last7days":
        gte_time = "now-7d/d"
        lte_time = "now"
    elif timeframe == "last30days":
        gte_time = "now-30d/d"
        lte_time = "now"
    else:
        # Default fallback
        gte_time = "now/d"
        lte_time = "now"

    # 1. Mapping Detail (Sesuai permintaan Anda)
    STAGE_DETAILS = {
        "Initial Attempts": {"severity": "low", "description": "Reconnaissance, Initial Access"},
        "Persistent Foothold": {"severity": "medium", "description": "Execution, Persistence, Privilege Escalation"},
        "Exploration": {"severity": "medium", "description": "Defense Evasion, Credential Access, Discovery"},
        "Propagation": {"severity": "high", "description": "Lateral Movement"},
        "Exfiltration": {"severity": "critical", "description": "Collection, Exfiltration, Impact"}
    }

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte_time,
                                "lte": lte_time,
                                "time_zone": "+07:00"
                            }
                        }
                    },
                    {"terms": {"event.module": ["suricata", "sophos", "panw"]}}
                ]
            }
        },
        "aggs": {
            "mitre_stages_buckets": {
                "terms": {
                    "script": {
                        "source": """
                            def stages = [];
                            // Cek Suricata (rule.metadata.mitre_tactic_name)
                            if (doc.containsKey('rule.metadata.mitre_tactic_name') && doc['rule.metadata.mitre_tactic_name'].size() > 0) {
                                stages = doc['rule.metadata.mitre_tactic_name'];
                            } 
                            // Cek Sophos & PANW (mitre.stages)
                            else if (doc.containsKey('mitre.stages') && doc['mitre.stages'].size() > 0) {
                                stages = doc['mitre.stages'];
                            }

                            if (stages.size() == 0) return "Unmapped";

                            def raw = stages[0].toLowerCase();
                            if (raw.startsWith('initial') || raw.startsWith('reconnaissance')) return "Initial Attempts";
                            if (raw.startsWith('execution') || raw.startsWith('persistence') || raw.startsWith('privilege')) return "Persistent Foothold";
                            if (raw.startsWith('defense') || raw.startsWith('credential') || raw.startsWith('discovery') || raw.startsWith('command')) return "Exploration";
                            if (raw.startsWith('lateral')) return "Propagation";
                            if (raw.startsWith('collection') || raw.startsWith('exfiltration') || raw.startsWith('impact')) return "Exfiltration";
                            
                            return "Unmapped";
                        """
                    },
                    "size": 10
                }
            }
        }
    }

    try:
        res = es.search(index=index_pattern, body=query)
        buckets = res.get('aggregations', {}).get('mitre_stages_buckets', {}).get('buckets', [])
        
        # Mapping hasil aggregasi ke dictionary sementara
        counts = {b['key']: b['doc_count'] for b in buckets}
        
        # Hitung Total MITRE (Hanya dari 5 stage utama, abaikan Unmapped)
        total_mitre = sum(counts.get(stage, 0) for stage in STAGE_DETAILS.keys())

        result = []
        for stage, detail in STAGE_DETAILS.items():
            count = counts.get(stage, 0)
            persen = (count / total_mitre * 100) if total_mitre > 0 else 0
            
            result.append({
                "stages": stage,
                "total_all": total_mitre,
                "total_data": count,
                "persen": f"{persen:.2f}",
                "severity": detail["severity"],
                "description": detail["description"]
            })
        
        return result

    except Exception as e:
        print(f"❌ Error MITRE Stats: {e}")
        return []


def build_dynamic_filters(filters: List[FilterItem]):
    es_filters = []

    for f in filters:

        # Operator exact match
        if f.operator == "is":
            es_filters.append({"term": {f.field: f.value}})

        # Operator wildcard (contains)
        elif f.operator == "contains":
            es_filters.append({"wildcard": {f.field: f"*{f.value}*"}})

        # Prefix match
        elif f.operator == "starts_with":
            es_filters.append({"prefix": {f.field: f.value}})

        # Range gte
        elif f.operator == "gte":
            es_filters.append({"range": {f.field: {"gte": f.value}}})

        # Range lte
        elif f.operator == "lte":
            es_filters.append({"range": {f.field: {"lte": f.value}}})

        # IP CIDR match
        elif f.operator == "cidr":
            es_filters.append({"term": {f.field: f.value}})

    return es_filters