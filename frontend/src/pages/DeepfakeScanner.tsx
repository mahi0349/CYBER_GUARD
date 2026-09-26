import React, { useState, useEffect } from 'react';
import {
  UserCheck,
  Upload,
  Bot,
  Shield,
  CheckCircle2,
  AlertTriangle,
  FileImage,
  Loader2,
  Eye,
  Camera,
  Activity,
  Cpu,
  Layers,
  Sparkles,
  Maximize2
} from 'lucide-react';
import { analyzeImage } from '../services/api';
import { AnalysisResponse } from '../types';
import { RiskScoreMeter } from '../components/dashboard/RiskScoreMeter';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { EvidenceList } from '../components/dashboard/EvidenceList';
import { MitreBadge } from '../components/dashboard/MitreBadge';

export const DeepfakeScanner: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [fileName, setFileName] = useState('Select or drop an image...');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [simulatedAction, setSimulatedAction] = useState<string | null>(null);

  useEffect(() => {
    if (file) {
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);
      return () => URL.revokeObjectURL(url);
    } else {
      setPreviewUrl(null);
    }
  }, [file]);

  const handleScan = async (sampleFile?: File, sampleName?: string) => {
    setLoading(true);
    setSimulatedAction(null);
    try {
      const targetFile = sampleFile || file;
      if (!targetFile) {
        // Fallback demo file if nothing selected
        const fallback = new File(['demo_content'], sampleName || 'synthetic_sample.png', { type: 'image/png' });
        const res = await analyzeImage(fallback);
        setResult(res);
      } else {
        const res = await analyzeImage(targetFile);
        setResult(res);
      }
    } catch (err) {
      console.error('Deepfake scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const f = e.target.files[0];
      setFile(f);
      setFileName(f.name);
      setResult(null);
    }
  };

  const authenticityScore = result?.features?.authenticity_score ?? (result ? Math.max(0, 100 - result.risk_score) : 0);
  const manipulationScore = result?.features?.manipulation_probability ?? (result ? Math.round(result.confidence * 100) : 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <UserCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>DEEPFAKE & SYNTHETIC MEDIA FORENSICS</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                SCENARIO 2
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              2D Fast Fourier Transform Spectrum + Micro-Texture Noise Residual & Sensor Provenance
            </p>
          </div>
        </div>
      </div>

      {/* Upload Zone & Interactive Media Card */}
      <div className="cyber-panel rounded-xl p-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* File Selector Dropzone */}
          <div className="md:col-span-2 border-2 border-dashed border-slate-700 hover:border-purple-500/50 rounded-xl p-6 text-center transition-all bg-slate-900/40 flex flex-col justify-center items-center">
            <div className="w-12 h-12 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center justify-center mb-3">
              <Upload className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-mono font-bold text-white mb-1">
              Upload Image Asset for Real-Time Forensic Pixel Inspection
            </h3>
            <p className="text-xs text-slate-400 mb-4 font-mono">
              Accepts PNG, JPG, WEBP, BMP (Processed locally via FFT & Pixel Residuals)
            </p>

            <div className="flex items-center gap-3">
              <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs font-mono text-white cursor-pointer transition-colors shadow-sm">
                <FileImage className="w-4 h-4 text-purple-400" />
                <span>{file ? file.name : 'Choose Image File'}</span>
                <input type="file" accept="image/*" onChange={handleFileUpload} className="hidden" />
              </label>

              {file && (
                <button
                  onClick={() => {
                    setFile(null);
                    setFileName('Select or drop an image...');
                    setResult(null);
                  }}
                  className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-rose-950 text-slate-400 hover:text-rose-300 border border-slate-700 text-xs font-mono transition-colors"
                >
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Real-Time Preview Thumbnail */}
          <div className="border border-slate-800 rounded-xl p-4 bg-slate-950/60 flex flex-col items-center justify-center relative min-h-[160px]">
            {previewUrl ? (
              <div className="relative w-full h-full flex flex-col items-center justify-center">
                <img
                  src={previewUrl}
                  alt="Uploaded target preview"
                  className="max-h-40 max-w-full rounded-lg object-contain border border-purple-500/30 shadow-md"
                />
                <span className="text-[10px] font-mono text-slate-400 mt-2 truncate max-w-full">
                  {file?.name} ({(file?.size ? file.size / 1024 : 0).toFixed(1)} KB)
                </span>
              </div>
            ) : (
              <div className="text-center p-4 text-slate-500 font-mono text-xs">
                <Camera className="w-8 h-8 mx-auto mb-2 text-slate-600 opacity-60" />
                <span>No Image Loaded</span>
                <p className="text-[10px] text-slate-600 mt-1">Preview will appear here</p>
              </div>
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-800">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-slate-400">Quick Test Profiles:</span>
            <button
              onClick={() => {
                const sampleName = 'synthetic_gan_diffusion_face.png';
                setFileName(sampleName);
                const mockFake = new File(['mock_fake_diffusion_data'], sampleName, { type: 'image/png' });
                setFile(mockFake);
                handleScan(mockFake, sampleName);
              }}
              className="px-3 py-1 rounded bg-slate-900 hover:bg-purple-950 hover:border-purple-500/40 border border-slate-700 text-xs font-mono text-purple-300 transition-all"
            >
              🔴 Synthetic AI Face-Swap
            </button>
            <button
              onClick={() => {
                const sampleName = 'authentic_camera_portrait.jpg';
                setFileName(sampleName);
                const mockReal = new File(['mock_real_camera_sensor'], sampleName, { type: 'image/jpeg' });
                setFile(mockReal);
                handleScan(mockReal, sampleName);
              }}
              className="px-3 py-1 rounded bg-slate-900 hover:bg-emerald-950 hover:border-emerald-500/40 border border-slate-700 text-xs font-mono text-emerald-300 transition-all"
            >
              🟢 Genuine Sensor Portrait
            </button>
          </div>

          <button
            onClick={() => handleScan()}
            disabled={loading}
            className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 text-white font-mono font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-purple-500/20 transition-all"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>COMPUTING 2D FFT & SENSOR NOISE...</span>
              </>
            ) : (
              <>
                <Eye className="w-4 h-4" />
                <span>EXECUTE FORENSIC SCAN</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="cyber-panel rounded-xl p-6 border-purple-500/30 space-y-6">
          {/* Top Bar with Verdict & Risk */}
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
            <div className="space-y-2">
              <div className="flex items-center gap-3 flex-wrap">
                <SeverityBadge severity={result.severity} size="lg" />
                <MitreBadge technique={result.mitre_technique || 'T1586'} name={result.mitre_name || 'Impersonation'} />
                <span className="text-xs font-mono text-slate-400">
                  Target: <strong className="text-white">{fileName}</strong>
                </span>
              </div>
              <h3 className="text-lg font-mono font-bold text-white flex items-center gap-2">
                <span>Forensic Authenticity Assessment</span>
                {authenticityScore >= 70 ? (
                  <span className="text-xs px-2 py-0.5 rounded font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    AUTHENTIC OPTICAL MEDIA
                  </span>
                ) : (
                  <span className="text-xs px-2 py-0.5 rounded font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    SYNTHETIC / MANIPULATED ARTIFACTS
                  </span>
                )}
              </h3>
            </div>

            <div className="shrink-0 self-center lg:self-auto">
              <RiskScoreMeter score={result.risk_score} severity={result.severity} size="lg" />
            </div>
          </div>

          {/* Genuine vs Manipulated Dual Score Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Authenticity / Genuineness Card */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-emerald-500/30 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Media Genuineness Score</span>
                </div>
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {authenticityScore}%
                </span>
              </div>
              {/* Progress Bar */}
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div
                  className="bg-emerald-500 h-2.5 rounded-full transition-all duration-700 shadow-sm shadow-emerald-500/50"
                  style={{ width: `${authenticityScore}%` }}
                />
              </div>
              <p className="text-[11px] font-mono text-slate-400">
                Confidence of authentic optical capture based on ISO Bayer sensor noise consistency and natural frequency decay.
              </p>
            </div>

            {/* Manipulation Probability Card */}
            <div className="p-4 rounded-xl bg-slate-900/80 border border-purple-500/30 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-purple-400 font-mono text-xs font-bold uppercase tracking-wider">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Manipulation Probability</span>
                </div>
                <span className="text-2xl font-bold font-mono text-purple-400">
                  {manipulationScore}%
                </span>
              </div>
              {/* Progress Bar */}
              <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
                <div
                  className="bg-purple-500 h-2.5 rounded-full transition-all duration-700 shadow-sm shadow-purple-500/50"
                  style={{ width: `${manipulationScore}%` }}
                />
              </div>
              <p className="text-[11px] font-mono text-slate-400">
                Likelihood of GAN/Diffusion synthesis or face-swapping seam artifacts detected in pixel matrices.
              </p>
            </div>
          </div>

          {/* Technical Forensic Telemetry Grid (Real Measured Details) */}
          <div>
            <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-purple-400" />
              <span>Extracted Forensic Pixel Telemetry</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* 1. Camera EXIF Provenance */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-slate-400 text-[11px] font-mono">
                  <Camera className="w-3.5 h-3.5 text-purple-400" />
                  <span>Hardware Sensor EXIF</span>
                </div>
                <div className="text-sm font-bold font-mono text-white truncate">
                  {result.features?.camera_model || 'None'}
                </div>
                <div className="text-[10px] font-mono text-slate-400">
                  {result.features?.exif_verdict || (result.features?.hardware_exif_present ? 'Verified Sensor' : 'Web/Privacy Export')}
                </div>
              </div>

              {/* 2. 2D FFT Spectral Peak Ratio */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-slate-400 text-[11px] font-mono">
                  <Activity className="w-3.5 h-3.5 text-indigo-400" />
                  <span>2D Fourier Peak Ratio</span>
                </div>
                <div className="text-sm font-bold font-mono text-white">
                  {result.features?.fft_spectral_peak_ratio !== undefined ? `${result.features.fft_spectral_peak_ratio}x` : 'N/A'}
                </div>
                <div className="text-[10px] font-mono text-slate-400 truncate">
                  {result.features?.frequency_verdict || (Number(result.features?.fft_spectral_peak_ratio) > 16 ? 'Anomalous Lattice' : 'Normal Spectrum')}
                </div>
              </div>

              {/* 3. Micro-Texture Noise Residual */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-slate-400 text-[11px] font-mono">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Micro-Texture Noise (σ)</span>
                </div>
                <div className="text-sm font-bold font-mono text-white">
                  {result.features?.noise_residual_std !== undefined ? `${result.features.noise_residual_std}` : 'N/A'}
                </div>
                <div className="text-[10px] font-mono text-slate-400 truncate">
                  {result.features?.sensor_verdict || 'Standard Sensor Grain'}
                </div>
              </div>

              {/* 4. Matrix Resolution & Payload */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="flex items-center gap-1.5 text-slate-400 text-[11px] font-mono">
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Resolution & Payload</span>
                </div>
                <div className="text-sm font-bold font-mono text-white truncate">
                  {result.features?.dimensions || '512x512'} ({result.features?.format || 'RAW'})
                </div>
                <div className="text-[10px] font-mono text-slate-400">
                  {result.features?.file_size_kb ? `${result.features.file_size_kb} KB` : 'Payload analyzed'}
                </div>
              </div>
            </div>
          </div>

          {/* Explainable AI Narrative */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-purple-500/30">
            <div className="flex items-center gap-2 text-purple-400 text-xs font-mono font-semibold mb-2">
              <Bot className="w-4 h-4" />
              <span>FORENSIC EXPLAINABILITY (GEMINI MULTIMODAL REASONING)</span>
            </div>
            <p className="text-xs font-mono text-slate-200 leading-relaxed">
              {result.explanation}
            </p>
          </div>

          {/* Indicators list */}
          <EvidenceList evidence={result.evidence} title="Detected Visual & Frequency Domain Manipulation Indicators" />

          {/* Containment Buttons */}
          <div className="pt-6 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-xs font-mono font-semibold text-slate-300 block">
                SOC Identity Safeguards:
              </span>
              <span className="text-[11px] text-slate-400">
                Prevent unauthorized credential delegation & biometric impersonation
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              {result.recommended_actions.map((act) => (
                <button
                  key={act}
                  onClick={() => setSimulatedAction(act)}
                  className="px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/40 text-purple-300 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
                >
                  <Shield className="w-3.5 h-3.5" />
                  <span>{act.replace(/_/g, ' ').toUpperCase()}</span>
                </button>
              ))}
            </div>
          </div>

          {simulatedAction && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                <strong>IDENTITY MITIGATION APPLIED:</strong> Action <strong>{simulatedAction.replace(/_/g, ' ').toUpperCase()}</strong> executed. Privileged access suspended pending physical verification.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
