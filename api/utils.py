from datetime import datetime, timezone
from uuid import uuid4

def randomUUID():
    return str(uuid4())




def get_latest_timestamp():
    # get current datetime in UTC
    dt = datetime.now(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")