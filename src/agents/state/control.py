from pydantic import BaseModel

class ControlState(BaseModel):
    cache_hit: bool = False
    should_retry: bool = False
    should_stop: bool = False
    should_skip_dynamic: bool = False
