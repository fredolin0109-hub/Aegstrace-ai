import React from 'react';

interface ThreatScoreGaugeProps {
  score: number; // 0.0 to 1.0, or 0 to 100
  classification?: string;
  confidence?: number;
  size?: number;
  showLabel?: boolean;
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({
  score,
  classification,
  confidence,
  size = 180,
  showLabel = true,
}) => {
  // Normalize score to 0 - 100
  const normalizedScore = Math.min(100, Math.max(0, score <= 1.0 && score > 0 ? Math.round(score * 100) : Math.round(score)));

  // Determine threat level color
  let color = '#10b981'; // Safe
  let glowColor = 'rgba(16, 185, 129, 0.4)';
  let verdict = classification || 'SAFE';

  if (normalizedScore >= 70 || verdict === 'HIGH_RISK') {
    color = '#f43f5e'; // High Risk
    glowColor = 'rgba(244, 63, 94, 0.4)';
    verdict = 'HIGH RISK';
  } else if (normalizedScore >= 35 || verdict === 'SUSPICIOUS') {
    color = '#f59e0b'; // Suspicious
    glowColor = 'rgba(245, 158, 11, 0.4)';
    verdict = 'SUSPICIOUS';
  } else {
    verdict = 'SAFE';
  }

  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="rotate-[-90deg] transition-all duration-700 ease-out"
        >
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active progress arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 8px ${glowColor})`,
              transition: 'stroke-dashoffset 1s ease-in-out, stroke 0.5s ease',
            }}
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl font-extrabold font-mono tracking-tight text-white drop-shadow-md">
            {normalizedScore}
          </span>
          <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase">
            RISK SCORE
          </span>
          {confidence !== undefined && (
            <span className="text-[10px] text-slate-400 font-mono mt-0.5">
              conf: {(confidence > 1 ? confidence : confidence * 100).toFixed(0)}%
            </span>
          )}
        </div>
      </div>

      {showLabel && (
        <div className="mt-3 text-center">
          <span
            className="inline-block px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border"
            style={{
              borderColor: color,
              color: color,
              backgroundColor: `${color}15`,
            }}
          >
            {verdict}
          </span>
        </div>
      )}
    </div>
  );
};

export default ThreatScoreGauge;
