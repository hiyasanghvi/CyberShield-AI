
import cv2
import numpy as np

from urllib.parse import urlsplit


class QRDecoder:
    """
    Decode QR codes from image bytes and identify payload types.
    Supports single and multiple QR codes.
    """

    def __init__(self):
        pass

    @staticmethod
    def identify_payload_type(payload: str) -> tuple[str, str | None]:
        payload = payload.strip()

        if not payload:
            return "UNKNOWN", None

        # HTTP / HTTPS URL
        if payload.lower().startswith(("http://", "https://")):
            parsed = urlsplit(payload)

            if parsed.hostname:
                return "URL", payload

        # URL without scheme
        if payload.lower().startswith("www."):
            candidate = "https://" + payload
            parsed = urlsplit(candidate)

            if parsed.hostname:
                return "URL", candidate

        # Wi-Fi configuration
        if payload.upper().startswith("WIFI:"):
            return "WIFI", None

        # Email
        if payload.lower().startswith("mailto:"):
            return "EMAIL", None

        # Phone / SMS
        if payload.lower().startswith(("tel:", "sms:", "smsto:")):
            return "PHONE", None

        return "TEXT", None

    
    @staticmethod
    def prepare_images(image):
        """
        Generate image variants for robust QR decoding.
        Nearest-neighbour interpolation preserves QR module edges.
        """

        images = [image]

        # Grayscale image
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        images.append(gray)

        # Add a small white quiet zone
        padded = cv2.copyMakeBorder(
            gray,
            4, 4, 4, 4,
            cv2.BORDER_CONSTANT,
            value=255,
        )

        images.append(padded)

        height, width = padded.shape[:2]
        max_dimension = max(height, width)

        # Nearest-neighbour resizing preserves QR patterns.
        # Particularly useful for small QR images.
        if max_dimension < 500:
            scale = min(10, max(2, 1000 // max_dimension))

            nearest = cv2.resize(
                padded,
                None,
                fx=scale,
                fy=scale,
                interpolation=cv2.INTER_NEAREST,
            )

            images.append(nearest)

        # Cubic interpolation as an additional fallback
        if max_dimension < 500:
            cubic = cv2.resize(
                padded,
                None,
                fx=4,
                fy=4,
                interpolation=cv2.INTER_CUBIC,
            )

            images.append(cubic)

        # Adaptive threshold preprocessing
        threshold = cv2.adaptiveThreshold(
            gray,
            255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31,
            5,
        )

        threshold = cv2.copyMakeBorder(
            threshold,
            4, 4, 4, 4,
            cv2.BORDER_CONSTANT,
            value=255,
        )

        images.append(threshold)

        return images


    def decode(self, image_bytes: bytes) -> dict:
        """
        Decode QR codes from uploaded image bytes.
        """

        if not image_bytes:
            raise ValueError("Image data is empty.")

        image_array = np.frombuffer(
            image_bytes,
            dtype=np.uint8,
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR,
        )

        if image is None:
            raise ValueError(
                "Invalid or unsupported image file."
            )

        # Prevent excessively large images from consuming resources.
        height, width = image.shape[:2]

        if height * width > 20_000_000:
            raise ValueError(
                "Image resolution is too large."
            )

        candidate_images = self.prepare_images(image)

        decoded_values = []

        detector = cv2.QRCodeDetector()

        # Attempt multiple QR decoding on each image version.
        for candidate in candidate_images:

            try:
                result = detector.detectAndDecodeMulti(candidate)

                if result and result[0]:

                    decoded_values.extend(
                        value.strip()
                        for value in result[1]
                        if value and value.strip()
                    )

            except cv2.error:
                pass

            if decoded_values:
                break

        # Fallback to single QR decoding.
        if not decoded_values:

            for candidate in candidate_images:

                try:
                    decoded_text, points, _ = (
                        detector.detectAndDecode(candidate)
                    )

                    if decoded_text and decoded_text.strip():
                        decoded_values.append(
                            decoded_text.strip()
                        )
                        break

                except cv2.error:
                    continue

        if not decoded_values:
            raise ValueError(
                "No readable QR code found in the uploaded image."
            )

        # Remove duplicates while preserving order.
        unique_values = list(dict.fromkeys(decoded_values))

        payloads = []

        for payload in unique_values:

            payload_type, decoded_url = (
                self.identify_payload_type(payload)
            )

            payloads.append({
                "payload": payload,
                "payload_type": payload_type,
                "decoded_url": decoded_url,
            })

        return {
            "decoded": True,
            "count": len(payloads),
            "payloads": payloads,
        }


def decode_qr_image(image_bytes: bytes) -> dict:
    """
    Public function used by the QR analysis service.
    """

    decoder = QRDecoder()

    return decoder.decode(image_bytes)
