import base64
import os
from io import BytesIO
from typing import Optional
from PIL import Image

def encode_screenshot(screenshot_path: Optional[str]) -> Optional[str]:
    """Prepares the captured screenshot for consumption by the AI Vision Model.
    
    If screenshot_path is missing, invalid, doesn't exist, or is None, returns None.
    Otherwise, reads the binary file, resizes it if it exceeds standard dimensions,
    compresses it as a JPEG, and returns a Base64 encoded string.
    """
    if not screenshot_path:
        return None

    if not os.path.exists(screenshot_path):
        return None

    try:
        # Open using PIL to allow resizing and compression
        with Image.open(screenshot_path) as img:
            # Scale down if width exceeds 1024px (maintaining aspect ratio)
            max_width = 1024
            if img.width > max_width:
                aspect_ratio = img.height / img.width
                new_width = max_width
                new_height = int(max_width * aspect_ratio)
                img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
            
            # Save compressed JPEG into BytesIO buffer
            # Convert to RGB if the image is in RGBA mode
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")
            
            buffer = BytesIO()
            img.save(buffer, format="JPEG", quality=70)
            encoded_bytes = base64.b64encode(buffer.getvalue())
            return encoded_bytes.decode("utf-8")
    except Exception:
        # Fallback to direct read if PIL fails
        try:
            with open(screenshot_path, "rb") as image_file:
                encoded_bytes = base64.b64encode(image_file.read())
                return encoded_bytes.decode("utf-8")
        except Exception:
            return None

