import json
from app.services.queue import QUEUE_SCAN
def test_queue_payload_serializable():
    payload={"scan_id":"123"}; encoded=json.dumps(payload); assert json.loads(encoded)==payload and QUEUE_SCAN.startswith("csai:")
