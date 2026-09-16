"""
Image Forensics Analyzer — Error Level Analysis (ELA) + DCT Frequency-Domain Analysis.

Classical forensic techniques for detecting image manipulation without requiring
GPU or deep learning models. Produces visually compelling heatmap outputs.
"""

import base64
import io
import math
from typing import Any, Dict, List, Tuple

import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ImageFilter

from ...models.schemas import ThreatIndicator


class ImageForensicsAnalyzer:
    """Performs ELA and DCT frequency analysis on uploaded images."""

    # ELA configuration
    ELA_QUALITY = 90          # JPEG re-save quality level
    ELA_SCALE_FACTOR = 15     # Brightness amplification for heatmap visibility
    ELA_BLOCK_SIZE = 16       # Block size for regional analysis

    # DCT configuration
    DCT_BLOCK_SIZE = 8        # Standard JPEG DCT block size

    # Thresholds
    ELA_SUSPICIOUS_THRESHOLD = 0.35
    ELA_MANIPULATED_THRESHOLD = 0.55
    DCT_SUSPICIOUS_THRESHOLD = 0.30
    DCT_MANIPULATED_THRESHOLD = 0.50

    def analyze(self, image_bytes: bytes) -> Dict[str, Any]:
        """
        Runs full image forensics pipeline on raw image bytes.

        Returns dict with:
            - ela_score (float 0-1)
            - ela_heatmap_base64 (str)
            - ela_details (dict)
            - dct_score (float 0-1)
            - dct_spectrum_base64 (str)
            - dct_details (dict)
            - combined_score (float 0-1)
            - indicators (List[ThreatIndicator])
        """
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # Run ELA analysis
        ela_result = self._perform_ela(img)

        # Run DCT frequency analysis
        dct_result = self._perform_dct_analysis(img)

        # Combine scores with weighted average
        combined = (ela_result["ela_score"] * 0.55) + (dct_result["dct_score"] * 0.45)

        # Build indicators
        indicators = self._build_indicators(ela_result, dct_result, combined)

        return {
            "ela_score": ela_result["ela_score"],
            "ela_heatmap_base64": ela_result["heatmap_base64"],
            "ela_details": ela_result["details"],
            "dct_score": dct_result["dct_score"],
            "dct_spectrum_base64": dct_result["spectrum_base64"],
            "dct_details": dct_result["details"],
            "combined_score": round(combined, 4),
            "indicators": indicators,
            "image_dimensions": {"width": img.width, "height": img.height},
            "image_format_info": self._get_format_info(image_bytes),
        }

    # ── ELA Implementation ───────────────────────────────────────────────

    def _perform_ela(self, original: Image.Image) -> Dict[str, Any]:
        """
        Error Level Analysis: Re-saves image at known JPEG quality and computes
        the absolute pixel difference. Manipulated regions show abnormal error
        levels compared to surrounding authentic content.
        """
        # Re-save at controlled quality
        buffer = io.BytesIO()
        original.save(buffer, format="JPEG", quality=self.ELA_QUALITY)
        buffer.seek(0)
        resaved = Image.open(buffer).convert("RGB")

        # Compute absolute pixel difference
        diff = ImageChops.difference(original, resaved)

        # Amplify differences for visibility
        extrema = diff.getextrema()
        max_diff = max(max(ch) for ch in extrema) or 1
        scale = 255.0 / max_diff
        enhanced_diff = diff.point(lambda x: min(255, int(x * scale * self.ELA_SCALE_FACTOR / 10)))

        # Convert to numpy for statistical analysis
        diff_array = np.array(diff, dtype=np.float32)
        enhanced_array = np.array(enhanced_diff, dtype=np.float32)

        # Compute per-channel statistics
        channel_means = diff_array.mean(axis=(0, 1))
        channel_stds = diff_array.std(axis=(0, 1))
        global_mean = diff_array.mean()
        global_std = diff_array.std()

        # Regional analysis — divide into blocks and find hotspots
        hotspot_regions = self._find_ela_hotspots(diff_array)

        # Compute ELA score based on variance distribution
        # High variance in error levels = likely manipulation
        # Uniform error levels = likely authentic (single compression)
        coefficient_of_variation = global_std / (global_mean + 1e-6)

        # Normalize to 0-1 score
        # Authentic images typically have CV < 1.5, manipulated > 2.5
        ela_score = min(1.0, max(0.0, (coefficient_of_variation - 0.8) / 3.5))

        # Boost score if hotspot regions have significantly different error levels
        if hotspot_regions:
            hotspot_boost = min(0.3, len(hotspot_regions) * 0.05)
            ela_score = min(1.0, ela_score + hotspot_boost)

        # Generate heatmap visualization
        heatmap = self._generate_ela_heatmap(enhanced_diff)
        heatmap_base64 = self._image_to_base64(heatmap)

        return {
            "ela_score": round(ela_score, 4),
            "heatmap_base64": heatmap_base64,
            "details": {
                "global_mean_error": round(float(global_mean), 3),
                "global_std_error": round(float(global_std), 3),
                "coefficient_of_variation": round(float(coefficient_of_variation), 3),
                "channel_means": {
                    "red": round(float(channel_means[0]), 3),
                    "green": round(float(channel_means[1]), 3),
                    "blue": round(float(channel_means[2]), 3),
                },
                "channel_stds": {
                    "red": round(float(channel_stds[0]), 3),
                    "green": round(float(channel_stds[1]), 3),
                    "blue": round(float(channel_stds[2]), 3),
                },
                "hotspot_count": len(hotspot_regions),
                "hotspot_regions": hotspot_regions[:5],  # Top 5 regions
                "resave_quality": self.ELA_QUALITY,
            },
        }

    def _find_ela_hotspots(self, diff_array: np.ndarray) -> List[Dict[str, Any]]:
        """Identifies regions with abnormally high error levels relative to global mean."""
        h, w, _ = diff_array.shape
        block_h = self.ELA_BLOCK_SIZE
        block_w = self.ELA_BLOCK_SIZE
        global_mean = diff_array.mean()
        global_std = diff_array.std()
        threshold = global_mean + 2.0 * global_std

        hotspots = []
        for y in range(0, h - block_h + 1, block_h):
            for x in range(0, w - block_w + 1, block_w):
                block = diff_array[y:y + block_h, x:x + block_w]
                block_mean = block.mean()
                if block_mean > threshold and block_mean > 5.0:
                    hotspots.append({
                        "x": int(x),
                        "y": int(y),
                        "width": block_w,
                        "height": block_h,
                        "intensity": round(float(block_mean), 2),
                        "deviation": round(float((block_mean - global_mean) / (global_std + 1e-6)), 2),
                    })

        # Sort by intensity descending
        hotspots.sort(key=lambda h: h["intensity"], reverse=True)
        return hotspots

    def _generate_ela_heatmap(self, enhanced_diff: Image.Image) -> Image.Image:
        """Converts ELA difference image into a color-coded heatmap."""
        gray = enhanced_diff.convert("L")
        gray_array = np.array(gray, dtype=np.float32)

        # Normalize to 0-255
        max_val = gray_array.max() or 1
        normalized = (gray_array / max_val * 255).astype(np.uint8)

        # Apply colormap: blue (low) → green (mid) → red (high)
        h, w = normalized.shape
        heatmap_rgb = np.zeros((h, w, 3), dtype=np.uint8)

        for i in range(h):
            for j in range(w):
                val = normalized[i, j]
                if val < 85:
                    # Blue to Cyan
                    t = val / 85.0
                    heatmap_rgb[i, j] = [0, int(255 * t), int(255 * (1 - t * 0.5))]
                elif val < 170:
                    # Cyan to Yellow
                    t = (val - 85) / 85.0
                    heatmap_rgb[i, j] = [int(255 * t), 255, int(128 * (1 - t))]
                else:
                    # Yellow to Red
                    t = (val - 170) / 85.0
                    heatmap_rgb[i, j] = [255, int(255 * (1 - t)), 0]

        return Image.fromarray(heatmap_rgb)

    # ── DCT Frequency Analysis ───────────────────────────────────────────

    def _perform_dct_analysis(self, img: Image.Image) -> Dict[str, Any]:
        """
        DCT Frequency-Domain Analysis: Detects double-JPEG compression artifacts,
        spectral anomalies, and inconsistent frequency patterns that indicate
        post-capture manipulation.
        """
        # Convert to grayscale for frequency analysis
        gray = np.array(img.convert("L"), dtype=np.float64)
        h, w = gray.shape

        # Ensure dimensions are multiples of block size
        h_blocks = h // self.DCT_BLOCK_SIZE
        w_blocks = w // self.DCT_BLOCK_SIZE
        cropped = gray[:h_blocks * self.DCT_BLOCK_SIZE, :w_blocks * self.DCT_BLOCK_SIZE]

        # Compute block-wise DCT using manual implementation (no OpenCV dependency)
        block_energies = []
        high_freq_ratios = []

        for by in range(h_blocks):
            for bx in range(w_blocks):
                y_start = by * self.DCT_BLOCK_SIZE
                x_start = bx * self.DCT_BLOCK_SIZE
                block = cropped[y_start:y_start + self.DCT_BLOCK_SIZE,
                                x_start:x_start + self.DCT_BLOCK_SIZE]

                # Apply DCT via matrix multiplication
                dct_block = self._dct2d(block)

                # Analyze energy distribution
                total_energy = np.sum(np.abs(dct_block))
                # High frequency = bottom-right quadrant of DCT block
                high_freq = np.sum(np.abs(dct_block[4:, 4:]))
                low_freq = np.sum(np.abs(dct_block[:4, :4]))

                block_energies.append(total_energy)
                if total_energy > 0:
                    high_freq_ratios.append(high_freq / total_energy)

        block_energies = np.array(block_energies)
        high_freq_ratios = np.array(high_freq_ratios) if high_freq_ratios else np.array([0.0])

        # Detect double-compression artifacts via energy histogram analysis
        energy_hist, _ = np.histogram(block_energies, bins=50)
        energy_hist_norm = energy_hist / (energy_hist.sum() + 1e-6)

        # Double-compressed images show periodic peaks in block energy histogram
        periodicity_score = self._detect_periodicity(energy_hist_norm)

        # High-frequency ratio variance — manipulated regions differ from authentic
        hf_variance = float(np.var(high_freq_ratios))
        hf_mean = float(np.mean(high_freq_ratios))

        # Compute composite DCT score
        # Higher periodicity + higher HF variance = more likely manipulated
        dct_score = min(1.0, max(0.0,
            (periodicity_score * 0.5) +
            (min(1.0, hf_variance * 10) * 0.3) +
            (min(1.0, hf_mean * 2) * 0.2)
        ))

        # Generate frequency spectrum visualization
        spectrum_img = self._generate_spectrum_visualization(gray)
        spectrum_base64 = self._image_to_base64(spectrum_img)

        return {
            "dct_score": round(dct_score, 4),
            "spectrum_base64": spectrum_base64,
            "details": {
                "blocks_analyzed": h_blocks * w_blocks,
                "periodicity_score": round(periodicity_score, 4),
                "high_freq_mean": round(hf_mean, 4),
                "high_freq_variance": round(hf_variance, 6),
                "mean_block_energy": round(float(block_energies.mean()), 2),
                "std_block_energy": round(float(block_energies.std()), 2),
                "double_compression_indicators": periodicity_score > self.DCT_SUSPICIOUS_THRESHOLD,
                "spectral_anomaly_detected": hf_variance > 0.02,
            },
        }

    def _dct2d(self, block: np.ndarray) -> np.ndarray:
        """Computes 2D DCT of an 8x8 block using separable 1D transforms."""
        N = block.shape[0]
        result = np.zeros_like(block, dtype=np.float64)

        # Create DCT basis matrix
        basis = np.zeros((N, N))
        for k in range(N):
            for n in range(N):
                if k == 0:
                    basis[k, n] = 1.0 / math.sqrt(N)
                else:
                    basis[k, n] = math.sqrt(2.0 / N) * math.cos(math.pi * k * (2 * n + 1) / (2 * N))

        # 2D DCT = basis @ block @ basis.T
        result = basis @ block @ basis.T
        return result

    def _detect_periodicity(self, histogram: np.ndarray) -> float:
        """Detects periodic peaks in energy histogram — signature of double JPEG compression."""
        if len(histogram) < 10:
            return 0.0

        # Compute autocorrelation of histogram
        mean = histogram.mean()
        centered = histogram - mean
        norm = np.sum(centered ** 2)
        if norm < 1e-10:
            return 0.0

        autocorr = np.correlate(centered, centered, mode='full')
        autocorr = autocorr[len(autocorr) // 2:]  # Keep positive lags
        autocorr = autocorr / (norm + 1e-10)

        # Look for secondary peaks (skip lag 0)
        if len(autocorr) < 5:
            return 0.0

        secondary_peaks = []
        for i in range(2, len(autocorr) - 1):
            if autocorr[i] > autocorr[i - 1] and autocorr[i] > autocorr[i + 1]:
                secondary_peaks.append(autocorr[i])

        if not secondary_peaks:
            return 0.0

        # Strong secondary peaks indicate periodicity
        max_secondary = max(secondary_peaks)
        return min(1.0, max(0.0, max_secondary * 2.0))

    def _generate_spectrum_visualization(self, gray: np.ndarray) -> Image.Image:
        """Generates a frequency spectrum visualization using FFT magnitude spectrum."""
        # Compute 2D FFT
        f_transform = np.fft.fft2(gray)
        f_shift = np.fft.fftshift(f_transform)
        magnitude = np.log1p(np.abs(f_shift))

        # Normalize to 0-255
        mag_min = magnitude.min()
        mag_max = magnitude.max()
        if mag_max - mag_min > 0:
            normalized = ((magnitude - mag_min) / (mag_max - mag_min) * 255).astype(np.uint8)
        else:
            normalized = np.zeros_like(magnitude, dtype=np.uint8)

        # Apply colormap
        h, w = normalized.shape
        spectrum_rgb = np.zeros((h, w, 3), dtype=np.uint8)
        for i in range(h):
            for j in range(w):
                val = normalized[i, j]
                if val < 64:
                    t = val / 64.0
                    spectrum_rgb[i, j] = [0, 0, int(128 + 127 * t)]
                elif val < 128:
                    t = (val - 64) / 64.0
                    spectrum_rgb[i, j] = [0, int(255 * t), 255]
                elif val < 192:
                    t = (val - 128) / 64.0
                    spectrum_rgb[i, j] = [int(255 * t), 255, int(255 * (1 - t))]
                else:
                    t = (val - 192) / 63.0
                    spectrum_rgb[i, j] = [255, int(255 * (1 - t * 0.5)), int(128 * (1 - t))]

        # Resize to reasonable display size
        result = Image.fromarray(spectrum_rgb)
        max_dim = 400
        if result.width > max_dim or result.height > max_dim:
            ratio = max_dim / max(result.width, result.height)
            new_size = (int(result.width * ratio), int(result.height * ratio))
            result = result.resize(new_size, Image.Resampling.LANCZOS)

        return result

    # ── Indicator Builder ────────────────────────────────────────────────

    def _build_indicators(
        self, ela_result: Dict[str, Any], dct_result: Dict[str, Any], combined: float
    ) -> List[ThreatIndicator]:
        """Builds ThreatIndicator list from ELA and DCT analysis results."""
        indicators: List[ThreatIndicator] = []

        ela_score = ela_result["ela_score"]
        ela_details = ela_result["details"]
        dct_score = dct_result["dct_score"]
        dct_details = dct_result["details"]

        # ELA indicators
        if ela_score > self.ELA_SUSPICIOUS_THRESHOLD:
            hotspots = ela_details.get("hotspot_count", 0)
            severity = "significant" if ela_score > self.ELA_MANIPULATED_THRESHOLD else "moderate"
            indicators.append(ThreatIndicator(
                name="ELA Compression Inconsistency",
                category="Image Forensics / Error Level Analysis",
                weight=round(ela_score, 2),
                value=f"ELA Score: {ela_score:.1%}, {hotspots} hotspot(s)",
                description=(
                    f"Error Level Analysis detected {severity} compression inconsistencies "
                    f"across {hotspots} image region(s). Coefficient of variation: "
                    f"{ela_details.get('coefficient_of_variation', 0):.3f}. "
                    f"Regions with abnormal error levels suggest post-capture editing."
                ),
            ))

        # DCT indicators
        if dct_score > self.DCT_SUSPICIOUS_THRESHOLD:
            if dct_details.get("double_compression_indicators"):
                indicators.append(ThreatIndicator(
                    name="Double JPEG Compression Detected",
                    category="Image Forensics / Frequency Analysis",
                    weight=round(dct_score, 2),
                    value=f"Periodicity: {dct_details.get('periodicity_score', 0):.4f}",
                    description=(
                        "DCT frequency analysis reveals periodic peaks in block energy histogram — "
                        "a strong signature of double-JPEG compression indicating the image was "
                        "decoded, modified, and re-encoded."
                    ),
                ))
            if dct_details.get("spectral_anomaly_detected"):
                indicators.append(ThreatIndicator(
                    name="Spectral Frequency Anomaly",
                    category="Image Forensics / Frequency Analysis",
                    weight=round(min(dct_score, 0.7), 2),
                    value=f"HF variance: {dct_details.get('high_freq_variance', 0):.6f}",
                    description=(
                        "High-frequency energy distribution shows abnormal variance across image blocks, "
                        "indicating non-uniform processing — possibly from localized edits or inpainting."
                    ),
                ))

        # EXIF-related indicator (absence of EXIF in a photo context is suspicious)
        # This will be populated by the caller with format info

        return indicators

    # ── Utility Methods ──────────────────────────────────────────────────

    def _image_to_base64(self, img: Image.Image) -> str:
        """Encodes a PIL Image as base64 PNG string."""
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        return base64.b64encode(buffer.read()).decode("utf-8")

    def _get_format_info(self, image_bytes: bytes) -> Dict[str, Any]:
        """Extracts basic format metadata from raw image bytes."""
        img = Image.open(io.BytesIO(image_bytes))
        info: Dict[str, Any] = {
            "format": img.format or "Unknown",
            "mode": img.mode,
            "size_bytes": len(image_bytes),
        }
        # Check for EXIF data presence
        exif = img.getexif()
        if exif:
            info["has_exif"] = True
            info["exif_tag_count"] = len(exif)
        else:
            info["has_exif"] = False
            info["exif_tag_count"] = 0
        return info
