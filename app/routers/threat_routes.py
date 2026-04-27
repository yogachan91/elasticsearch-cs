from fastapi import APIRouter
from fastapi import WebSocket, WebSocketDisconnect
from fastapi import Depends
from fastapi import Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Any
from app.elastic_client import es, get_elastic_status
from ..services import (
    get_suricata_events,
    get_sophos_events,
    get_panw_events,
    build_dynamic_filters,
    calculate_risk_summary,
    calculate_global_stats,
    build_event_type_stats,
    calculate_mitre_stats,
    calculate_global_attack,
    get_combined_events
)
import requests
import os
import traceback
import asyncio
import json
import jwt
import httpx

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"
INDEX_SEARCH = "logs-*"

router = APIRouter(prefix="/api/threats", tags=["Threat Analytics"])

# URL backend utama untuk verifikasi token
# BACKEND_AUTH_VERIFY = os.getenv("AUTH_VERIFY_URL", "http://103.150.227.205:8080/api/auth/verify-token")

# ======================================================
# MODEL INPUT REQUEST
# ======================================================
class FilterItem(BaseModel):
    field: str
    operator: str
    value: str
class EventRequest(BaseModel):
    timeframe: str
    operator_logic: Optional[str] = "AND" 
    filters: Optional[List[FilterItem]] = []
    search_query: Optional[str] = None

def verify_internal_access(x_internal_service_key: str = Header(None, alias="X-Internal-Service-Key")):
    # Tambahkan print untuk debugging sementara
    print(f"DEBUG: Key yang diterima = {x_internal_service_key}") 
    
    expected_key = "RAHASIA_SANGAT_KUAT"
    
    if x_internal_service_key != expected_key:
        raise HTTPException(
            status_code=403, 
            detail=f"Forbidden: Key mismatch. Received: {x_internal_service_key}"
        )

# def evaluate_condition(event: dict, f: FilterItem) -> bool:
#     """Helper untuk mengecek apakah satu event memenuhi satu kriteria filter"""
#     field = f.field
#     val_filter = str(f.value).lower()
#     val_event = str(event.get(field, "")).lower()

#     if f.operator == "is":
#         return val_event == val_filter
    
#     elif f.operator == "is_not":
#         return val_event != val_filter
    
#     elif f.operator == "contains":
#         return val_filter in val_event
    
#     elif f.operator == "exists":
#         return event.get(field) is not None
    
#     elif f.operator == ">":
#         try: return float(event.get(field)) > float(f.value)
#         except: return False
        
#     elif f.operator == "<":
#         try: return float(event.get(field)) < float(f.value)
#         except: return False
        
#     return False   


#@router.post("/events/filter", dependencies=[Depends(verify_internal_access)])
@router.post("/events/filter")
def get_filtered_events(body: EventRequest):
    # Langsung panggil fungsi gabungan
    # Elasticsearch melakukan semua filter & search di sisi server
    events = get_combined_events(
        es=es, 
        timeframe=body.timeframe, 
        filters=body.filters, 
        search_query=body.search_query,
        logic=body.operator_logic
    )

    return {
        "timeframe": body.timeframe,
        "count": len(events),
        "events": events
    }
# def get_filtered_events(body: EventRequest):
#     timeframe = body.timeframe
#     search_query = body.search_query.lower() if body.search_query else None
#     logic = body.operator_logic.upper() if body.operator_logic else "AND"

#     # 1. Ambil data dari semua source
#     suricata = get_suricata_events(es, INDEX, timeframe)
#     sophos = get_sophos_events(es, INDEX, timeframe)
#     panw = get_panw_events(es, INDEX_PANW, timeframe)

#     combined = suricata + sophos + panw

#     # 2. Logika Filter Dinamis (AND / OR)
#     if body.filters:
#         filtered_list = []
        
#         for event in combined:
#             if logic == "AND":
#                 # LOGIKA AND: Harus lolos SEMUA filter
#                 is_match = True
#                 for f in body.filters:
#                     if not evaluate_condition(event, f):
#                         is_match = False
#                         break # Satu gagal, langsung coret event ini
#             else:
#                 # LOGIKA OR: Cukup lolos SATU filter saja
#                 is_match = False
#                 for f in body.filters:
#                     if evaluate_condition(event, f):
#                         is_match = True
#                         break # Satu cocok, langsung ambil event ini
            
#             if is_match:
#                 filtered_list.append(event)
        
#         combined = filtered_list

#     # 3. Logika Search Bar (Universal Search)
#     # Search bar bersifat mempersempit hasil (AND terhadap hasil filter)
#     if search_query:
#         searchable_fields = ["source_ip", "destination_ip", "country", "event_type", "severity"]
#         combined = [
#             event for event in combined 
#             if any(search_query in str(event.get(f, "")).lower() for f in searchable_fields)
#         ]

#     # 4. Sorting & Response
#     combined_sorted = sorted(combined, key=lambda x: x.get("timestamp", ""), reverse=True)

#     return {
#         "timeframe": timeframe,
#         "operator_logic_used": logic,
#         "filters_applied": body.filters,
#         "count": len(combined_sorted),
#         "events": combined_sorted
#     }


@router.post("/events/summary", dependencies=[Depends(verify_internal_access)])
#@router.post("/events/summary")
def get_risk_summary(body: EventRequest):
    try:
        timeframe = body.timeframe
        elastic_status = get_elastic_status()

        # suricata = get_suricata_events(es, INDEX, timeframe) or []
        # sophos = get_sophos_events(es, INDEX, timeframe) or []
        # panw = get_panw_events(es, INDEX_PANW, timeframe) or []

        # combined = suricata + sophos + panw

        summary = calculate_risk_summary(timeframe)
        global_stats = calculate_global_stats(timeframe)
        event_type_stats = build_event_type_stats(timeframe)
        # event_type_ingest = build_event_type_ingest(suricata, sophos, panw, timeframe)

        # 🔥 HITUNG MITRE
        mitre_stats = calculate_mitre_stats(timeframe)
        global_attack = calculate_global_attack(timeframe)

        return {
            "timeframe": timeframe,
            "status_connect": elastic_status,
            "count": len(summary),
            "summary": summary,
            "mitre": mitre_stats,
            "global_attack": global_attack,
            "events": [
                {
                    "total": global_stats["total_all"],
                    "seconds": global_stats["total_5_min_ago"],
                    "list": event_type_stats
                }
            ],
            "events_ingest": [
                {
                    "total": global_stats["total_all"],
                    "seconds": global_stats["total_5_min_ago"],
                    "list": global_stats["list"]
                }
            ]
        }

    except Exception as e:
        print("🔥 ERROR:", e)
        print(traceback.format_exc())
        




