import base64
import os
from typing import Optional

def encode_screenshot(screenshot_path: Optional[str]) -> Optional[str]:
    """Prepares the captured screenshot for consumption by the AI Vision Model.
    
    If screenshot_path is missing, invalid, doesn't exist, or is None, returns None.
    Otherwise, reads the binary file and returns a Base64 encoded string.
    """
    if not screenshot_path:
        return None

    if not os.path.exists(screenshot_path):
        return None

    try:
        with open(screenshot_path, "rb") as image_file:
            encoded_bytes = base64.b64encode(image_file.read())
            return encoded_bytes.decode("utf-8")
    except Exception:
        # Return None safely if any I/O error occurs
        return None
