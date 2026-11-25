/**
 * components/ThreatGlobe.jsx — Performance-Optimized Live 3D Threat Activity Globe
 *
 * Performance Optimizations:
 *   1. Zero per-frame React re-renders during auto-rotation (pure 60 FPS WebGL loop)
 *   2. Clamped WebGL devicePixelRatio (max 1.5) to prevent high-DPI GPU fillrate bottlenecks
 *   3. Downscaled 2048x1024 compressed night earth texture (158KB vs 715KB 4K)
 *   4. Debounced camera & zoom-tier recalculations (triggers only on tier crossing or gesture end)
 *   5. Capped concurrent animated arcs (16 max) and pulsing rings (4 max)
 *   6. Strict viewport culling and capped label counts per zoom tier
 *   7. Wrapped in React.memo to prevent parent re-render leakage
 */

import React, { useMemo, useRef, useEffect, useState, useCallback } from 'react';
import Globe from 'react-globe.gl';
import { getProgressiveLabels, getNearestCity } from '../data/geoData';

const HQ_LAT = 19.0760;
const HQ_LNG = 72.8777;

const TYPE_COLOR = {
  website: '#FF3B5C',
  url:     '#FF3B5C',
  email:   '#FFB020',
  apk:     '#FF5252',
};

function getColor(scanType) {
  return TYPE_COLOR[scanType] || '#FF3B5C';
}

function riskColor(level) {
  if (level === 'High') return '#FF3B5C';
  if (level === 'Medium') return '#FFB020';
  return '#3DDC84';
}

function getTierFromAltitude(alt) {
  if (alt > 1.7) return 'FAR';
  if (alt > 0.9) return 'MEDIUM';
  return 'CLOSE';
}

function ThreatGlobeComponent({ events = [], focusedEvent = null, onSelectThreat = null }) {
  const containerRef = useRef(null);
  const globeEl = useRef(null);
  const debounceTimerRef = useRef(null);
  const lastTierRef = useRef('FAR');

  const [dimensions, setDimensions] = useState({ width: 600, height: 480 });

  // Camera tracking state (only updated on gesture end or tier shift)
  const [cameraState, setCameraState] = useState({ altitude: 2.1, lat: 22, lng: 75 });
  const [activeThreat, setActiveThreat] = useState(null);

  // Auto-resize globe canvas to parent container
  useEffect(() => {
    if (!containerRef.current) return;
    const updateSize = () => {
      if (containerRef.current) {
        const { clientWidth, clientHeight } = containerRef.current;
        setDimensions({
          width: clientWidth || 600,
          height: clientHeight || 480,
        });
      }
    };
    updateSize();
    const ro = new ResizeObserver(updateSize);
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Debounced camera state synchronization to prevent React re-renders during active gestures
  const syncCameraToReact = useCallback(() => {
    if (!globeEl.current) return;
    const pov = globeEl.current.pointOfView();
    if (!pov) return;
    const newTier = getTierFromAltitude(pov.altitude);
    lastTierRef.current = newTier;
    setCameraState({
      altitude: pov.altitude,
      lat: pov.lat,
      lng: pov.lng,
    });
  }, []);

  // Configure OrbitControls & clamp WebGL Pixel Ratio
  useEffect(() => {
    if (!globeEl.current) return;

    // Clamp devicePixelRatio to max 1.5 to prevent high-DPI GPU fillrate stalls
    try {
      const renderer = globeEl.current.renderer?.();
      if (renderer) {
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
      }
    } catch (_) {}

    const controls = globeEl.current.controls?.();
    if (!controls) return;

    controls.enableZoom = true;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.35;
    controls.enablePan = false;
    controls.minDistance = 150; // Altitude ~0.50 — keeps entire region well-framed and visible
    controls.maxDistance = 420; // Altitude ~3.2
    controls.zoomSpeed = 0.8;

    // Sync camera state ONLY when user gestures end (wheel debounce or drag end)
    // Completely decoupled from idle auto-rotation loop!
    const handleWheel = () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = setTimeout(() => {
        syncCameraToReact();
      }, 150);
    };

    const handleDragEnd = () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = setTimeout(() => {
        syncCameraToReact();
      }, 100);
    };

    const container = containerRef.current;
    if (container) {
      container.addEventListener('wheel', handleWheel, { passive: true });
    }
    controls.addEventListener('end', handleDragEnd);

    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
      if (container) container.removeEventListener('wheel', handleWheel);
      controls.removeEventListener('end', handleDragEnd);
    };
  }, [syncCameraToReact]);

  // Initial camera view focus
  useEffect(() => {
    if (!globeEl.current) return;
    globeEl.current.pointOfView({ lat: 22, lng: 75, altitude: 2.1 }, 1000);
  }, []);

  // Handle external selection (e.g. clicked in Recent Events sidebar)
  useEffect(() => {
    if (!focusedEvent || !globeEl.current) return;
    handleFlyToThreat(focusedEvent);
  }, [focusedEvent]);

  // Fly camera to a selected threat
  const handleFlyToThreat = useCallback((ev) => {
    if (!ev || !globeEl.current) return;
    const controls = globeEl.current.controls?.();
    if (controls) controls.autoRotate = false;

    lastTierRef.current = 'CLOSE';
    setCameraState({ altitude: 0.65, lat: ev.lat, lng: ev.lng });
    setActiveThreat(ev);
    onSelectThreat?.(ev);

    globeEl.current.pointOfView(
      { lat: ev.lat, lng: ev.lng, altitude: 0.65 },
      1000
    );
  }, [onSelectThreat]);

  // Zoom buttons
  const handleZoomIn = () => {
    if (!globeEl.current) return;
    const pov = globeEl.current.pointOfView();
    const newAlt = Math.max(0.50, (pov.altitude || 2.1) * 0.75);
    lastTierRef.current = getTierFromAltitude(newAlt);
    setCameraState(prev => ({ ...prev, altitude: newAlt }));
    globeEl.current.pointOfView({ altitude: newAlt }, 300);
  };

  const handleZoomOut = () => {
    if (!globeEl.current) return;
    const pov = globeEl.current.pointOfView();
    const newAlt = Math.min(2.8, (pov.altitude || 2.1) * 1.35);
    lastTierRef.current = getTierFromAltitude(newAlt);
    setCameraState(prev => ({ ...prev, altitude: newAlt }));
    globeEl.current.pointOfView({ altitude: newAlt }, 300);
  };

  const handleResetView = () => {
    if (!globeEl.current) return;
    const controls = globeEl.current.controls?.();
    if (controls) controls.autoRotate = true;
    setActiveThreat(null);
    lastTierRef.current = 'FAR';
    setCameraState({ lat: 22, lng: 75, altitude: 2.1 });
    globeEl.current.pointOfView({ lat: 22, lng: 75, altitude: 2.1 }, 800);
  };

  // Compute lightweight points, arcs (max 16), and rings (max 4)
  const { points, arcs, rings } = useMemo(() => {
    const validEvents = events.filter((e) => !(e.lat === 0 && e.lng === 0));

    // Cap points to 35 max for high rendering efficiency
    const pts = validEvents.slice(0, 35).map((e) => ({
      lat:   e.lat,
      lng:   e.lng,
      size:  0.35,
      color: getColor(e.scan_type),
      event: e,
      label: `<div style="background:rgba(13,17,23,0.95); border:1px solid rgba(255,255,255,0.15); padding:6px 10px; border-radius:6px; font-family:'Inter',sans-serif; font-size:11px; color:#E6EDF3; box-shadow:0 4px 12px rgba(0,0,0,0.6);">
        <div style="font-weight:700; color:${getColor(e.scan_type)}; font-family:'Space Grotesk',sans-serif;">${e.risk_level?.toUpperCase() || 'HIGH'} RISK · CLICK TO INSPECT</div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:10px; margin-top:2px;">${e.entity}</div>
        <div style="color:#8B949E; font-size:10px; margin-top:1px;">${e.country || 'Global'} · ${e.scan_type?.toUpperCase()}</div>
      </div>`,
    }));

    // QFireNet Defense HQ
    pts.push({
      lat: HQ_LAT,
      lng: HQ_LNG,
      size: 0.6,
      color: '#00D9FF',
      isHq: true,
      label: `<div style="background:rgba(13,17,23,0.95); border:1px solid #00D9FF; padding:6px 10px; border-radius:6px; font-family:'Inter',sans-serif; font-size:11px; color:#00D9FF; box-shadow:0 0 12px rgba(0,217,255,0.4);">
        <div style="font-weight:700; font-family:'Space Grotesk',sans-serif;">⚡ QFIRENET CORE HQ</div>
        <div style="color:#8B949E; font-size:10px;">Primary Sensor Array · Active</div>
      </div>`,
    });

    // Capped at 16 active animated arcs
    const arcList = validEvents.slice(0, 16).map((e) => ({
      startLat: e.lat,
      startLng: e.lng,
      endLat:   HQ_LAT,
      endLng:   HQ_LNG,
      color:    [getColor(e.scan_type), 'rgba(0, 217, 255, 0.75)'],
      stroke:   0.65,
    }));

    // Capped at 4 active rings (HQ + 3 threats)
    const ringList = [
      {
        lat: HQ_LAT,
        lng: HQ_LNG,
        color: (t) => `rgba(0, 217, 255, ${Math.max(0, 1 - t)})`,
        maxR: 4.5,
        propagationSpeed: 1.8,
        repeatPeriod: 1200,
      },
    ];

    validEvents.slice(0, 3).forEach((e) => {
      const c = getColor(e.scan_type);
      ringList.push({
        lat: e.lat,
        lng: e.lng,
        color: (t) => c === '#FF3B5C'
          ? `rgba(255, 59, 92, ${Math.max(0, 0.8 - t)})`
          : `rgba(255, 176, 32, ${Math.max(0, 0.8 - t)})`,
        maxR: 3.2,
        propagationSpeed: 1.5,
        repeatPeriod: 1800,
      });
    });

    return { points: pts, arcs: arcList, rings: ringList };
  }, [events]);

  // Compute progressive labels (strictly capped & culled)
  const labels = useMemo(() => {
    return getProgressiveLabels({
      altitude: cameraState.altitude,
      camLat: cameraState.lat,
      camLng: cameraState.lng,
      events,
    });
  }, [cameraState, events]);

  const zoomTierName =
    cameraState.altitude > 1.7
      ? 'GLOBAL VIEW'
      : cameraState.altitude > 0.9
      ? 'REGIONAL CITIES'
      : 'PINPOINT THREAT FOCUS';

  const activeDetails = useMemo(() => {
    if (!activeThreat) return null;
    const nearest = getNearestCity(activeThreat.lat, activeThreat.lng, activeThreat.country);
    return {
      cityName: nearest ? nearest.name : (activeThreat.country || 'Target Location'),
      countryName: nearest ? nearest.country : (activeThreat.country || 'Global'),
      latStr: `${Math.abs(activeThreat.lat).toFixed(2)}°${activeThreat.lat >= 0 ? 'N' : 'S'}`,
      lngStr: `${Math.abs(activeThreat.lng).toFixed(2)}°${activeThreat.lng >= 0 ? 'E' : 'W'}`,
    };
  }, [activeThreat]);

  return (
    <div ref={containerRef} className="w-full h-full flex items-center justify-center relative select-none">
      <Globe
        ref={globeEl}
        width={dimensions.width}
        height={dimensions.height}
        // Visuals (2048x1024 optimized night texture)
        globeImageUrl="/textures/earth-night.jpg"
        backgroundColor="rgba(0,0,0,0)"
        showAtmosphere={true}
        atmosphereColor="#00D9FF"
        atmosphereAltitude={0.06}
        // Points (capped to 35 max)
        pointsData={points}
        pointAltitude={0.015}
        pointColor="color"
        pointRadius="size"
        pointLabel="label"
        onPointClick={(pt) => {
          if (pt.event) handleFlyToThreat(pt.event);
        }}
        // Progressive Labels Layer (cached label pool, instant 0ms swap, 1 curve segment)
        labelsData={labels}
        labelLat={(d) => d.lat}
        labelLng={(d) => d.lng}
        labelText={(d) => d.text}
        labelSize={(d) => d.size}
        labelColor={(d) => d.color}
        labelDotRadius={0}
        labelAltitude={(d) => d.altitude || 0.015}
        labelResolution={1}
        labelsTransitionDuration={0}
        onLabelClick={(lb) => {
          if (lb.event) handleFlyToThreat(lb.event);
        }}
        // Arcs (capped to 16 active, streamlined elevation)
        arcsData={arcs}
        arcColor="color"
        arcDashLength={0.45}
        arcDashGap={0.15}
        arcDashAnimateTime={2000}
        arcStroke="stroke"
        arcAltitude={0.10}
        // Rings (capped to 4 active)
        ringsData={rings}
        ringColor="color"
        ringMaxRadius="maxR"
        ringPropagationSpeed="propagationSpeed"
        ringRepeatPeriod="repeatPeriod"
      />

      {/* ── HUD Controls: Zoom & View Reset ────────────────────────────── */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-2 pointer-events-auto">
        <div
          className="px-2.5 py-1 rounded-md text-[10px] font-mono font-semibold flex items-center gap-1.5"
          style={{
            background: 'rgba(13, 17, 23, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.12)',
            color: cameraState.altitude <= 0.9 ? '#FF3B5C' : cameraState.altitude <= 1.7 ? '#FFB020' : 'var(--accent)',
            backdropFilter: 'blur(8px)',
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full animate-pulse"
            style={{ background: cameraState.altitude <= 0.9 ? '#FF3B5C' : cameraState.altitude <= 1.7 ? '#FFB020' : 'var(--accent)' }}
          />
          {zoomTierName}
        </div>
      </div>

      <div className="absolute top-4 right-4 z-10 flex flex-col gap-1.5 pointer-events-auto">
        <button
          type="button"
          onClick={handleZoomIn}
          title="Zoom In"
          className="w-8 h-8 rounded-md flex items-center justify-center text-sm font-bold text-white/80 hover:text-white hover:border-[var(--accent)] transition-colors"
          style={{
            background: 'rgba(13, 17, 23, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            backdropFilter: 'blur(8px)',
          }}
        >
          +
        </button>
        <button
          type="button"
          onClick={handleZoomOut}
          title="Zoom Out"
          className="w-8 h-8 rounded-md flex items-center justify-center text-sm font-bold text-white/80 hover:text-white hover:border-[var(--accent)] transition-colors"
          style={{
            background: 'rgba(13, 17, 23, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            backdropFilter: 'blur(8px)',
          }}
        >
          −
        </button>
        <button
          type="button"
          onClick={handleResetView}
          title="Reset Global View"
          className="w-8 h-8 rounded-md flex items-center justify-center text-xs font-bold text-white/80 hover:text-[var(--accent)] hover:border-[var(--accent)] transition-colors"
          style={{
            background: 'rgba(13, 17, 23, 0.85)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            backdropFilter: 'blur(8px)',
          }}
        >
          ⟲
        </button>
      </div>

      {/* ── Anchored Floating Threat Detail Card ────────────────────────── */}
      {activeThreat && activeDetails && (
        <div
          className="absolute bottom-4 left-4 right-4 sm:right-auto sm:max-w-sm z-20 p-4 rounded-lg shadow-2xl animate-fade-in pointer-events-auto"
          style={{
            background: 'rgba(13, 17, 23, 0.95)',
            border: `1px solid ${riskColor(activeThreat.risk_level)}`,
            boxShadow: `0 8px 32px rgba(0,0,0,0.7), 0 0 16px ${riskColor(activeThreat.risk_level)}25`,
            backdropFilter: 'blur(12px)',
          }}
        >
          <div className="flex items-start justify-between gap-3 mb-2">
            <div className="flex items-center gap-2">
              <span
                className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider"
                style={{
                  background: `${riskColor(activeThreat.risk_level)}18`,
                  color: riskColor(activeThreat.risk_level),
                  border: `1px solid ${riskColor(activeThreat.risk_level)}40`,
                }}
              >
                {activeThreat.risk_level} RISK
              </span>
              <span className="text-[10px] font-mono text-[#8B949E] uppercase">
                {activeThreat.scan_type}
              </span>
            </div>
            <button
              type="button"
              onClick={() => setActiveThreat(null)}
              className="text-[#8B949E] hover:text-white text-sm font-mono leading-none px-1 py-0.5 rounded hover:bg-white/10 transition-colors"
            >
              ✕
            </button>
          </div>

          <h3 className="font-mono text-sm font-bold text-[#E6EDF3] truncate mb-1" title={activeThreat.entity}>
            {activeThreat.entity}
          </h3>

          <div className="space-y-1 mb-3 text-xs text-[#8B949E]">
            <p className="flex items-center gap-1.5 text-[#E6EDF3] font-medium">
              <span style={{ color: 'var(--accent)' }}>📍</span>
              {activeDetails.cityName}, {activeDetails.countryName}
            </p>
            <p className="font-mono text-[10px]">
              Coordinates: {activeDetails.latStr}, {activeDetails.lngStr}
            </p>
            <p className="text-[11px] text-[#8B949E]">
              Trigger: {activeThreat.reason || 'Anomalous network signatures detected'}
            </p>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-white/10 text-[10px] font-mono">
            <span className="text-[#8B949E]">
              {new Date(activeThreat.timestamp).toLocaleTimeString()}
            </span>
            <button
              type="button"
              onClick={handleResetView}
              className="text-[var(--accent)] hover:underline font-semibold"
            >
              Back to Overview →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default React.memo(ThreatGlobeComponent);
