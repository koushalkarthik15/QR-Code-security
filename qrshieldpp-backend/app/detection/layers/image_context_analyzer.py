"""QR + image-context analysis using OpenCV for QRShield++.

Capabilities:
- Detect QR bounding boxes
- Identify edge irregularities
- Detect sticker/overlay artifacts
- Detect multiple QR codes in one image
- Produce image risk classification (Low / Medium / High)
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from typing import Any

import cv2
import numpy as np


@dataclass
class QRRegionAnalysis:
    """Per-QR analysis output."""

    qr_index: int
    bounding_box: dict[str, int]
    corner_points: list[list[float]]
    edge_irregularity_score: float
    overlay_artifact_score: float
    local_risk_score: float


@dataclass
class ImageContextAnalysisResult:
    """Image-level QR context analysis result."""

    image_path: str
    image_width: int
    image_height: int
    qr_count: int
    multiple_qr_detected: bool
    qr_regions: list[QRRegionAnalysis]
    risk_score: float
    risk_classification: str
    risk_factors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a JSON-serializable payload."""
        payload = asdict(self)
        payload["qr_regions"] = [asdict(region) for region in self.qr_regions]
        return payload


class QRImageContextAnalyzer:
    """OpenCV-based analyzer for QR geometry and tampering cues."""

    def __init__(self, warp_size: int = 280, max_qr_to_analyze: int = 12) -> None:
        self.warp_size = int(max(120, warp_size))
        self.max_qr_to_analyze = int(max(1, max_qr_to_analyze))
        self.detector = cv2.QRCodeDetector()

    def analyze_image(self, image_path: str) -> ImageContextAnalysisResult:
        """Analyze one image and return risk-scored context findings."""
        errors: list[str] = []
        risk_factors: list[str] = []

        image = cv2.imread(image_path, cv2.IMREAD_COLOR)
        if image is None:
            return ImageContextAnalysisResult(
                image_path=image_path,
                image_width=0,
                image_height=0,
                qr_count=0,
                multiple_qr_detected=False,
                qr_regions=[],
                risk_score=1.0,
                risk_classification="High",
                risk_factors=["Image could not be loaded"],
                errors=[f"Unable to read image file: {image_path}"],
            )

        image_height, image_width = image.shape[:2]
        qr_polygons, detect_errors = self._detect_qr_polygons(image)
        errors.extend(detect_errors)

        qr_regions: list[QRRegionAnalysis] = []
        for idx, polygon in enumerate(qr_polygons[: self.max_qr_to_analyze]):
            region_analysis, region_errors = self._analyze_qr_region(image, polygon, idx)
            qr_regions.append(region_analysis)
            errors.extend(region_errors)

        qr_count = len(qr_regions)
        multiple_qr_detected = qr_count > 1

        if qr_count == 0:
            risk_factors.append("No QR code detected in image")
        if multiple_qr_detected:
            risk_factors.append(f"Multiple QR codes detected: {qr_count}")

        if any(region.edge_irregularity_score >= 0.55 for region in qr_regions):
            risk_factors.append("Edge irregularities detected around at least one QR")
        if any(region.overlay_artifact_score >= 0.55 for region in qr_regions):
            risk_factors.append("Sticker/overlay artifact pattern detected")

        risk_score = self._compute_risk_score(
            qr_regions=qr_regions,
            has_multiple_qr=multiple_qr_detected,
            has_errors=bool(errors),
        )
        risk_classification = self._risk_classification(risk_score)

        return ImageContextAnalysisResult(
            image_path=image_path,
            image_width=image_width,
            image_height=image_height,
            qr_count=qr_count,
            multiple_qr_detected=multiple_qr_detected,
            qr_regions=qr_regions,
            risk_score=risk_score,
            risk_classification=risk_classification,
            risk_factors=risk_factors,
            errors=errors,
        )

    def _detect_qr_polygons(self, image: np.ndarray) -> tuple[list[np.ndarray], list[str]]:
        """Detect QR polygons using multi-QR and single-QR OpenCV methods."""
        errors: list[str] = []
        polygons: list[np.ndarray] = []

        # 1) Preferred method for multiple QR codes.
        try:
            multi_out = self.detector.detectAndDecodeMulti(image)
            if isinstance(multi_out, tuple) and len(multi_out) >= 3:
                multi_ok = bool(multi_out[0])
                points = multi_out[2]
                if multi_ok and points is not None:
                    polygons.extend(self._normalize_qr_points(points))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"detectAndDecodeMulti failed: {exc}")

        # 2) Fallback to detectMulti if no polygon found.
        if not polygons:
            try:
                multi_detect_out = self.detector.detectMulti(image)
                if isinstance(multi_detect_out, tuple) and len(multi_detect_out) >= 2:
                    multi_ok = bool(multi_detect_out[0])
                    points = multi_detect_out[1]
                    if multi_ok and points is not None:
                        polygons.extend(self._normalize_qr_points(points))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"detectMulti failed: {exc}")

        # 3) Fallback to single QR decode path.
        if not polygons:
            try:
                single_out = self.detector.detectAndDecode(image)
                if isinstance(single_out, tuple) and len(single_out) >= 2:
                    points = single_out[1]
                    if points is not None:
                        polygons.extend(self._normalize_qr_points(points))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"detectAndDecode failed: {exc}")

        polygons = self._deduplicate_polygons(polygons)
        return polygons, errors

    @staticmethod
    def _normalize_qr_points(points: Any) -> list[np.ndarray]:
        """Normalize OpenCV QR points into a list of (4, 2) float arrays."""
        arr = np.asarray(points, dtype=np.float32)
        if arr.size < 8:
            return []

        # Common shapes: (4,2), (1,4,2), (N,4,2), (4,1,2)
        if arr.ndim == 2 and arr.shape == (4, 2):
            return [arr]

        if arr.ndim == 3:
            if arr.shape[1:] == (4, 2):
                return [arr[idx] for idx in range(arr.shape[0])]
            if arr.shape[0:2] == (4, 1):
                return [arr.reshape(4, 2)]

        if arr.size % 8 == 0:
            reshaped = arr.reshape(-1, 4, 2)
            return [reshaped[idx] for idx in range(reshaped.shape[0])]

        return []

    @staticmethod
    def _deduplicate_polygons(polygons: list[np.ndarray]) -> list[np.ndarray]:
        """Remove duplicate polygons that come from multi-method fallback."""
        unique: list[np.ndarray] = []
        seen_boxes: set[tuple[int, int, int, int]] = set()

        for poly in polygons:
            poly_i = np.round(poly).astype(np.int32)
            x, y, w, h = cv2.boundingRect(poly_i)
            key = (x, y, w, h)
            if key in seen_boxes:
                continue
            seen_boxes.add(key)
            unique.append(poly.astype(np.float32))

        return unique

    def _analyze_qr_region(
        self,
        image: np.ndarray,
        polygon: np.ndarray,
        qr_index: int,
    ) -> tuple[QRRegionAnalysis, list[str]]:
        """Analyze one QR region for irregular edges and overlay/sticker artifacts."""
        errors: list[str] = []

        ordered_polygon = self._order_points_clockwise(polygon)
        polygon_i = np.round(ordered_polygon).astype(np.int32)
        x, y, w, h = cv2.boundingRect(polygon_i)

        patch, patch_error = self._warp_qr_patch(image, ordered_polygon, self.warp_size)
        if patch_error:
            errors.append(patch_error)
            patch = self._safe_crop(image, x, y, w, h)

        edge_score = self._edge_irregularity_score(patch)
        overlay_score = self._overlay_artifact_score(patch)
        local_risk = round(min(1.0, 0.55 * edge_score + 0.45 * overlay_score), 4)

        region = QRRegionAnalysis(
            qr_index=qr_index,
            bounding_box={"x": int(x), "y": int(y), "w": int(w), "h": int(h)},
            corner_points=ordered_polygon.tolist(),
            edge_irregularity_score=edge_score,
            overlay_artifact_score=overlay_score,
            local_risk_score=local_risk,
        )
        return region, errors

    @staticmethod
    def _order_points_clockwise(points: np.ndarray) -> np.ndarray:
        """Return points ordered as top-left, top-right, bottom-right, bottom-left."""
        pts = np.asarray(points, dtype=np.float32).reshape(4, 2)
        ordered = np.zeros((4, 2), dtype=np.float32)

        sum_axis = pts.sum(axis=1)
        diff_axis = np.diff(pts, axis=1).reshape(-1)

        ordered[0] = pts[np.argmin(sum_axis)]  # top-left
        ordered[2] = pts[np.argmax(sum_axis)]  # bottom-right
        ordered[1] = pts[np.argmin(diff_axis)]  # top-right
        ordered[3] = pts[np.argmax(diff_axis)]  # bottom-left
        return ordered

    @staticmethod
    def _safe_crop(image: np.ndarray, x: int, y: int, w: int, h: int) -> np.ndarray:
        """Fallback crop when perspective warp is not available."""
        h_img, w_img = image.shape[:2]
        x0 = max(0, x)
        y0 = max(0, y)
        x1 = min(w_img, x + max(1, w))
        y1 = min(h_img, y + max(1, h))
        if x1 <= x0 or y1 <= y0:
            return image.copy()
        return image[y0:y1, x0:x1]

    @staticmethod
    def _warp_qr_patch(
        image: np.ndarray,
        polygon: np.ndarray,
        size: int,
    ) -> tuple[np.ndarray, str | None]:
        """Perspective-warp QR polygon into a normalized square patch."""
        destination = np.array(
            [[0, 0], [size - 1, 0], [size - 1, size - 1], [0, size - 1]],
            dtype=np.float32,
        )
        try:
            matrix = cv2.getPerspectiveTransform(polygon.astype(np.float32), destination)
            patch = cv2.warpPerspective(image, matrix, (size, size))
            return patch, None
        except Exception as exc:  # noqa: BLE001
            return image.copy(), f"Perspective warp failed: {exc}"

    def _edge_irregularity_score(self, patch: np.ndarray) -> float:
        """Score edge irregularity around the QR perimeter (0 to 1)."""
        gray = cv2.cvtColor(patch, cv2.COLOR_BGR2GRAY) if patch.ndim == 3 else patch.copy()
        gray = cv2.GaussianBlur(gray, (3, 3), 0)
        edges = cv2.Canny(gray, 70, 180)

        h, w = gray.shape[:2]
        border = max(4, int(min(h, w) * 0.08))
        border_mask = np.zeros((h, w), dtype=np.uint8)
        border_mask[:border, :] = 1
        border_mask[-border:, :] = 1
        border_mask[:, :border] = 1
        border_mask[:, -border:] = 1

        border_pixels = float(np.count_nonzero(border_mask))
        border_edge_density = float(np.count_nonzero(edges & border_mask)) / max(border_pixels, 1.0)
        density_score = self._normalize(border_edge_density, low=0.03, high=0.30)

        # Quiet zone should remain bright. Dark border strips can indicate tampering.
        strips = [
            gray[:border, :],
            gray[-border:, :],
            gray[:, :border],
            gray[:, -border:],
        ]
        min_strip_brightness = min(float(np.mean(strip)) for strip in strips) / 255.0
        quiet_zone_penalty = self._normalize(0.75 - min_strip_brightness, low=0.03, high=0.50)

        score = 0.7 * density_score + 0.3 * quiet_zone_penalty
        return round(self._clip01(score), 4)

    def _overlay_artifact_score(self, patch: np.ndarray) -> float:
        """Score likely sticker/overlay artifacts inside the QR region (0 to 1)."""
        gray = cv2.cvtColor(patch, cv2.COLOR_BGR2GRAY) if patch.ndim == 3 else patch.copy()
        gray = cv2.GaussianBlur(gray, (3, 3), 0)

        h, w = gray.shape[:2]
        margin = max(8, int(min(h, w) * 0.12))
        if h <= margin * 2 or w <= margin * 2:
            return 0.0

        inner = gray[margin : h - margin, margin : w - margin]
        inner_area = float(inner.shape[0] * inner.shape[1])

        # A large rectangular edge pattern in the data zone is suspicious.
        edges = cv2.Canny(inner, 60, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        best_rect_ratio = 0.0

        for contour in contours:
            area = float(cv2.contourArea(contour))
            area_ratio = area / max(inner_area, 1.0)
            if area_ratio < 0.03 or area_ratio > 0.65:
                continue

            perimeter = float(cv2.arcLength(contour, True))
            if perimeter <= 1.0:
                continue
            approx = cv2.approxPolyDP(contour, 0.04 * perimeter, True)
            if len(approx) < 4 or len(approx) > 8:
                continue

            hull_area = float(cv2.contourArea(cv2.convexHull(contour)))
            if hull_area <= 1.0:
                continue
            solidity = area / hull_area
            if solidity < 0.75:
                continue

            best_rect_ratio = max(best_rect_ratio, area_ratio)

        rectangular_overlay_score = self._normalize(best_rect_ratio, low=0.05, high=0.35)

        # Large low-detail contiguous blob in the QR data area is suspicious.
        lap = cv2.Laplacian(inner, cv2.CV_32F, ksize=3)
        local_detail = cv2.blur(np.abs(lap), (5, 5))
        smooth_mask = (local_detail < 4.5).astype(np.uint8)

        n_labels, _, stats, _ = cv2.connectedComponentsWithStats(smooth_mask, connectivity=8)
        largest_blob = 0
        for idx in range(1, n_labels):
            largest_blob = max(largest_blob, int(stats[idx, cv2.CC_STAT_AREA]))
        largest_blob_ratio = float(largest_blob) / max(inner_area, 1.0)
        smooth_blob_score = self._normalize(largest_blob_ratio, low=0.12, high=0.50)

        score = max(rectangular_overlay_score, smooth_blob_score)
        return round(self._clip01(score), 4)

    def _compute_risk_score(
        self,
        qr_regions: list[QRRegionAnalysis],
        has_multiple_qr: bool,
        has_errors: bool,
    ) -> float:
        """Aggregate per-region findings into a 0-1 image risk score."""
        if not qr_regions:
            base = 0.85
            if has_errors:
                base += 0.10
            return round(self._clip01(base), 4)

        edge_mean = float(np.mean([region.edge_irregularity_score for region in qr_regions]))
        overlay_mean = float(np.mean([region.overlay_artifact_score for region in qr_regions]))
        local_max = float(np.max([region.local_risk_score for region in qr_regions]))

        multiple_qr_score = 0.0
        if has_multiple_qr:
            multiple_qr_score = min(1.0, (len(qr_regions) - 1) / 3.0)

        score = (
            0.35 * edge_mean
            + 0.35 * overlay_mean
            + 0.20 * local_max
            + 0.10 * multiple_qr_score
        )

        if has_multiple_qr:
            score += 0.08
        if has_errors:
            score += 0.05

        return round(self._clip01(score), 4)

    @staticmethod
    def _risk_classification(risk_score: float) -> str:
        if risk_score < 0.33:
            return "Low"
        if risk_score < 0.66:
            return "Medium"
        return "High"

    @staticmethod
    def _normalize(value: float, low: float, high: float) -> float:
        if high <= low:
            return 0.0
        return (value - low) / (high - low)

    @staticmethod
    def _clip01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze QR image context using OpenCV.")
    parser.add_argument("--image", required=True, help="Path to the image file.")
    parser.add_argument("--warp-size", type=int, default=280, help="Normalized QR patch size.")
    parser.add_argument(
        "--max-qr-to-analyze",
        type=int,
        default=12,
        help="Maximum QR detections to process from one image.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    analyzer = QRImageContextAnalyzer(
        warp_size=args.warp_size,
        max_qr_to_analyze=args.max_qr_to_analyze,
    )
    result = analyzer.analyze_image(args.image)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()

