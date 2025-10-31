import React from 'react';
import { GiScythe } from 'react-icons/gi';

interface LoadingSpinnerProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ 
  size = 24, 
  className = '', 
  style = {} 
}) => {
  return (
    <GiScythe 
      className={`scythe-icon spinning-scythe ${className}`}
      style={{ 
        width: `${size}px`, 
        height: `${size}px`,
        color: 'var(--accent-red)',
        filter: 'drop-shadow(0 0 8px rgba(255, 0, 0, 0.3))',
        animation: 'spin 1s linear infinite',
        ...style
      }} 
    />
  );
};

export default LoadingSpinner;
